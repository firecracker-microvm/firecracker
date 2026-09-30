// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Barrier};

use serde::{Deserialize, Serialize};
use vm_superio::Trigger;
use vmm_sys_util::eventfd::EventFd;

use crate::devices::legacy::EventFdTrigger;
use crate::logger::{IncMetric, SharedIncMetric, warn};
use crate::utils::u64_to_usize;
use crate::vstate::bus::BusDevice;

/// Size of the PL061 MMIO register window.
const PL061_REGISTER_SPACE_SIZE: u64 = 0x1000;
/// End of the data register aperture. The data registers occupy `0x000..0x3ff`; the
/// access address doubles as a per-line mask (address bits [9:2]).
const PL061_DATA_REG_END: u64 = 0x400;

/// PL061 register offsets (see the ARM PrimeCell PL061 TRM).
const PL061_DIR: u64 = 0x400; // GPIODIR: direction, 0 = input, 1 = output
const PL061_IS: u64 = 0x404; // GPIOIS: interrupt sense, 0 = edge, 1 = level
const PL061_IBE: u64 = 0x408; // GPIOIBE: interrupt both edges
const PL061_IEV: u64 = 0x40c; // GPIOIEV: interrupt event (edge/level polarity)
const PL061_IE: u64 = 0x410; // GPIOIE: interrupt mask (enable)
const PL061_RIS: u64 = 0x414; // GPIORIS: raw interrupt status
const PL061_MIS: u64 = 0x418; // GPIOMIS: masked interrupt status
const PL061_IC: u64 = 0x41c; // GPIOIC: interrupt clear (write 1 to clear)
const PL061_AFSEL: u64 = 0x420; // GPIOAFSEL: alternate function select

/// PrimeCell identification registers (`PeriphID0..3` then `PrimeCellID0..3`).
const PL061_ID_REG_START: u64 = 0xfd0;
const PL061_ID_REG_END: u64 = 0x1000;

/// Number of GPIO lines modelled by a single PL061.
const GPIO_PIN_COUNT: u8 = 8;
/// Mask covering all GPIO lines.
const GPIO_PIN_MASK: u8 = 0xff;
/// GPIO line the virtual power button is wired to (must match the FDT `gpio-keys` node).
const POWER_BUTTON_PIN: u8 = 0;
/// Identification register contents: PeriphID = 0x00041061 (PL061), PrimeCellID = 0xb105f00d.
/// These let the Linux AMBA bus match and probe the `pl061` driver.
const PL061_ID: [u8; 12] = [
    0x00, 0x00, 0x00, 0x00, 0x61, 0x10, 0x04, 0x00, 0x0d, 0xf0, 0x05, 0xb1,
];

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum PL061Error {
    /// Could not create EventFd: {0}
    CreateEventFd(std::io::Error),
    /// Could not trigger interrupt: {0}
    TriggerInterrupt(std::io::Error),
    /// The guest has reconfigured the power button line as an output
    PowerButtonNotAnInput,
}

/// Metrics specific to the PL061 device.
#[derive(Debug, Serialize, Default)]
pub struct PL061DeviceMetrics {
    /// Errors triggered while using the PL061 device.
    pub error_count: SharedIncMetric,
    /// Number of superfluous read intents on this device.
    pub missed_read_count: SharedIncMetric,
    /// Number of superfluous write intents on this device.
    pub missed_write_count: SharedIncMetric,
    /// Number of interrupts injected into the guest.
    pub interrupt_count: SharedIncMetric,
}

impl PL061DeviceMetrics {
    pub const fn new() -> Self {
        Self {
            error_count: SharedIncMetric::new(),
            missed_read_count: SharedIncMetric::new(),
            missed_write_count: SharedIncMetric::new(),
            interrupt_count: SharedIncMetric::new(),
        }
    }

    fn invalid_read(&self, offset: u64, len: usize) {
        self.missed_read_count.inc();
        self.error_count.inc();
        warn!(
            "Guest read at invalid PL061 offset/length: offset={:#x}, len={}",
            offset, len
        );
    }

    fn invalid_write(&self, offset: u64, len: usize) {
        self.missed_write_count.inc();
        self.error_count.inc();
        warn!(
            "Guest write at invalid PL061 offset/length: offset={:#x}, len={}",
            offset, len
        );
    }
}

/// Stores aggregated metrics. There is only ever one PL061 device, so it accesses this directly.
pub static METRICS: PL061DeviceMetrics = PL061DeviceMetrics::new();

/// Minimal PL061 GPIO controller skeleton for aarch64 guests.
///
/// This models the core MMIO register bank, an interrupt line, and host-side
/// input injection so higher layers can later wire a GPIO-backed power button.
#[derive(Debug)]
pub struct PL061Device {
    /// Interrupt line exposed to the guest.
    pub interrupt_evt: EventFdTrigger,
    /// Register state (also what is captured/restored for snapshots).
    state: PL061State,
}

/// Serializable register state of a [`PL061Device`], used for snapshot save/restore.
///
/// The interrupt eventfd is intentionally not part of the state: it is recreated and
/// re-registered with KVM during restore.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PL061State {
    /// Pin levels (GPIODATA).
    data: u8,
    /// Pin directions (GPIODIR): 0 = input, 1 = output.
    direction: u8,
    /// Interrupt sense (GPIOIS): 0 = edge, 1 = level.
    interrupt_sense: u8,
    /// Interrupt both-edges select (GPIOIBE).
    interrupt_both_edges: u8,
    /// Interrupt event/polarity (GPIOIEV).
    interrupt_event: u8,
    /// Interrupt mask/enable (GPIOIE).
    interrupt_mask: u8,
    /// Raw (pre-mask) interrupt status (GPIORIS).
    raw_interrupt_status: u8,
    /// Alternate function select (GPIOAFSEL).
    alternate_function_select: u8,
    /// Input lines the host is holding asserted until the guest has read them back through
    /// the data aperture. See [`PL061Device::trigger_power_button`].
    auto_release: u8,
}

impl PL061Device {
    pub fn new() -> Result<Self, PL061Error> {
        Ok(Self {
            interrupt_evt: EventFdTrigger::new(
                EventFd::new(libc::EFD_NONBLOCK).map_err(PL061Error::CreateEventFd)?,
            ),
            state: PL061State::default(),
        })
    }

    /// Captures the current register state for snapshotting.
    pub fn state(&self) -> PL061State {
        self.state.clone()
    }

    /// Rebuilds a device from a previously saved register state, with a fresh interrupt eventfd.
    ///
    /// The saved state may carry an interrupt the guest had not acknowledged yet. The new
    /// eventfd starts empty, so re-assert the line here: otherwise the restored guest would
    /// wait forever for an interrupt that was consumed by the pre-snapshot eventfd.
    pub fn from_state(state: &PL061State) -> Result<Self, PL061Error> {
        let mut device = Self {
            state: state.clone(),
            ..Self::new()?
        };
        device.refresh_masked_interrupt(0)?;
        Ok(device)
    }

    /// Presses the virtual power button.
    ///
    /// The line is held asserted until the guest reads it back through the data aperture,
    /// at which point it is released automatically and the falling edge is latched. Holding
    /// it rather than releasing after a fixed delay is what makes the press survive a paused
    /// vCPU: a guest that is not running cannot observe a press that has already been undone,
    /// so a timed release would silently drop the request. This mirrors the x86_64 i8042
    /// path, where the keystroke stays queued until the guest consumes it.
    pub fn trigger_power_button(&mut self) -> Result<(), PL061Error> {
        let mask = line_mask(POWER_BUTTON_PIN);
        // The power button is wired as an input. A guest that reconfigures the line as an
        // output drives the level itself, so the press could never reach it: report that
        // instead of acknowledging a request that would be silently dropped.
        if self.state.direction & mask != 0 {
            METRICS.error_count.inc();
            return Err(PL061Error::PowerButtonNotAnInput);
        }
        // An unacknowledged press is still pending: re-assert the line so a repeated request
        // is not silently swallowed, but do not queue a second press.
        self.state.auto_release |= mask;
        self.set_input_level(mask, true)
    }

    /// Drives the input lines in `mask` from the host side, raising an interrupt for whichever
    /// transitions the guest has armed. Lines the guest has configured as outputs are driven by
    /// the guest rather than the host, so they are dropped from the mask.
    fn set_input_level(&mut self, mask: u8, high: bool) -> Result<(), PL061Error> {
        let mask = mask & !self.state.direction;

        let old_data = self.state.data;
        if high {
            self.state.data |= mask;
        } else {
            self.state.data &= !mask;
        }

        self.update_interrupts(old_data)
    }

    /// Reads a register, returning `None` for offsets that are not backed by a register.
    fn read_reg(&mut self, offset: u64) -> Option<u8> {
        Some(match offset {
            // Reads in the data aperture only return the lines selected by the address mask.
            0..PL061_DATA_REG_END => self.state.data & data_mask(offset),
            PL061_DIR => self.state.direction,
            PL061_IS => self.state.interrupt_sense,
            PL061_IBE => self.state.interrupt_both_edges,
            PL061_IEV => self.state.interrupt_event,
            PL061_IE => self.state.interrupt_mask,
            PL061_RIS => self.state.raw_interrupt_status,
            PL061_MIS => self.masked_interrupt_status(),
            PL061_AFSEL => self.state.alternate_function_select,
            PL061_ID_REG_START..PL061_ID_REG_END => {
                let index = u64_to_usize((offset - PL061_ID_REG_START) >> 2);
                PL061_ID.get(index).copied()?
            }
            _ => return None,
        })
    }

    /// Writes a register. Returns `Ok(true)` if the offset was handled, `Ok(false)` for an
    /// unknown/read-only offset, and `Err` only if raising the interrupt line failed.
    fn write_reg(&mut self, offset: u64, value: u8) -> Result<bool, PL061Error> {
        match offset {
            0..PL061_DATA_REG_END => {
                // Only the lines selected by the address mask, and only those configured as
                // outputs, are affected by a guest write.
                let mask = data_mask(offset) & self.state.direction;
                self.state.data = (self.state.data & !mask) | (value & mask);
            }
            PL061_DIR => self.state.direction = value,
            // Changing the sense/polarity configuration can make a line that is already at the
            // matching level interrupt-worthy, so re-evaluate instead of waiting for the next
            // level change.
            PL061_IS | PL061_IBE | PL061_IEV => {
                let old_mis = self.masked_interrupt_status();
                match offset {
                    PL061_IS => self.state.interrupt_sense = value,
                    PL061_IBE => self.state.interrupt_both_edges = value,
                    PL061_IEV => self.state.interrupt_event = value,
                    _ => unreachable!(),
                }
                self.recompute_level_interrupts();
                self.refresh_masked_interrupt(old_mis)?;
                return Ok(true);
            }
            PL061_IE => {
                let old_mis = self.masked_interrupt_status();
                self.state.interrupt_mask = value;
                self.refresh_masked_interrupt(old_mis)?;
                return Ok(true);
            }
            PL061_IC => {
                let old_mis = self.masked_interrupt_status();
                self.state.raw_interrupt_status &= !value;
                // Clearing has no lasting effect on a level-sensitive line whose level is
                // still active: the bit comes straight back.
                self.recompute_level_interrupts();
                self.refresh_masked_interrupt(old_mis)?;
                return Ok(true);
            }
            PL061_AFSEL => self.state.alternate_function_select = value,
            _ => return Ok(false),
        }

        Ok(true)
    }

    /// Handles a guest MMIO read. Only 1-byte and (4-aligned) 4-byte accesses are accepted, as
    /// used by the Linux `gpio-pl061` driver; anything else is counted as a missed read.
    pub fn bus_read(&mut self, offset: u64, data: &mut [u8]) {
        if !(data.len() == 1 || data.len() == 4)
            || offset >= PL061_REGISTER_SPACE_SIZE
            || (data.len() == 4 && !offset.is_multiple_of(4))
        {
            METRICS.invalid_read(offset, data.len());
            return;
        }

        if let Some(value) = self.read_reg(offset) {
            // Every PL061 register is 8 bits, so a 4-byte access just zero-extends it.
            data.fill(0);
            data[0] = value;

            // The guest has now seen the input lines selected by this access, so release any
            // the host was holding, latching the falling edge. Reading an output line returns
            // the guest's own value, so it releases nothing and a pending press is kept.
            if offset < PL061_DATA_REG_END {
                let released = self.state.auto_release & data_mask(offset) & !self.state.direction;
                self.state.auto_release &= !released;
                if released != 0
                    && let Err(err) = self.set_input_level(released, false)
                {
                    METRICS.error_count.inc();
                    warn!("Failed to release PL061 power button: {err}");
                }
            }
        } else {
            METRICS.invalid_read(offset, data.len());
        }
    }

    /// Handles a guest MMIO write, with the same access-width rules as [`Self::bus_read`].
    pub fn bus_write(&mut self, offset: u64, data: &[u8]) {
        if !(data.len() == 1 || data.len() == 4)
            || offset >= PL061_REGISTER_SPACE_SIZE
            || (data.len() == 4 && !offset.is_multiple_of(4))
        {
            METRICS.invalid_write(offset, data.len());
            return;
        }

        // The PL061 registers are all 8-bit, so only the low byte of the access is meaningful.
        match self.write_reg(offset, data[0]) {
            Ok(true) => {}
            Ok(false) => METRICS.invalid_write(offset, data.len()),
            Err(err) => {
                METRICS.error_count.inc();
                warn!("Failed to update PL061 state: {err}");
            }
        }
    }

    /// Interrupt status visible to the guest after masking (GPIOMIS).
    fn masked_interrupt_status(&self) -> u8 {
        self.state.raw_interrupt_status & self.state.interrupt_mask
    }

    /// Recomputes the raw interrupt status after the input lines changed from `old_data`, then
    /// refreshes the masked line. Only input lines can raise interrupts.
    fn update_interrupts(&mut self, old_data: u8) -> Result<(), PL061Error> {
        let changed = (old_data ^ self.state.data) & !self.state.direction;
        if changed == 0 {
            return Ok(());
        }

        let old_mis = self.masked_interrupt_status();

        // Edge-sensitive lines latch on the transition the guest selected.
        for line in 0..GPIO_PIN_COUNT {
            let mask = line_mask(line);
            // Skip lines that did not change or are configured level-sensitive (handled below).
            if changed & mask == 0 || self.state.interrupt_sense & mask != 0 {
                continue;
            }

            if self.state.interrupt_both_edges & mask != 0 {
                self.state.raw_interrupt_status |= mask;
            } else {
                // Single-edge: latch only when the new level matches the configured edge.
                let line_is_high = self.state.data & mask != 0;
                let wants_high = self.state.interrupt_event & mask != 0;
                if line_is_high == wants_high {
                    self.state.raw_interrupt_status |= mask;
                }
            }
        }

        self.recompute_level_interrupts();

        self.refresh_masked_interrupt(old_mis)
    }

    /// Re-evaluates the level-sensitive part of GPIORIS.
    ///
    /// Unlike the edge-sensitive bits, a level-sensitive bit is not latched: it tracks whether
    /// the line currently matches the polarity in GPIOIEV, so it must be cleared again once the
    /// level goes inactive, and it re-asserts itself after a GPIOIC write while the level is
    /// still active. The edge-sensitive bits are left untouched.
    fn recompute_level_interrupts(&mut self) {
        let level_active =
            !(self.state.data ^ self.state.interrupt_event) & self.state.interrupt_sense;
        self.state.raw_interrupt_status =
            (self.state.raw_interrupt_status & !self.state.interrupt_sense) | level_active;
    }

    /// Pulses the interrupt line when a masked interrupt becomes newly pending, given the
    /// GPIOMIS value from before the change. The line is modelled as edge-triggered (one
    /// eventfd signal whenever at least one bit becomes newly pending) to match the plain KVM
    /// irqfd used to deliver it; see the FDT node, which declares it edge-rising. Comparing
    /// against the previous GPIOMIS rather than "was anything pending" keeps a new edge on one
    /// line from being swallowed while another line already has an interrupt outstanding.
    fn refresh_masked_interrupt(&mut self, old_mis: u8) -> Result<(), PL061Error> {
        if (!old_mis & self.masked_interrupt_status()) != 0 {
            METRICS.interrupt_count.inc();
            self.interrupt_evt
                .trigger()
                .map_err(PL061Error::TriggerInterrupt)?;
        }
        Ok(())
    }
}

/// Single-bit mask for a GPIO `line`.
fn line_mask(line: u8) -> u8 {
    1u8 << line
}

/// Per-line mask carried by a data-aperture access address (PL061 uses address bits [9:2] as
/// the line mask, so the masked register at `0x000..0x3ff` only touches the selected lines).
#[allow(clippy::cast_possible_truncation)]
fn data_mask(offset: u64) -> u8 {
    ((offset >> 2) & u64::from(GPIO_PIN_MASK)) as u8
}

impl BusDevice for PL061Device {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        self.bus_read(offset, data);
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        self.bus_write(offset, data);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logger::IncMetric;

    /// Address of a masked access to the lines in `line_mask`, within the data register aperture
    /// (`0x000..0x3ff`). The PL061 carries the per-line mask in address bits [9:2], so the access
    /// to a given set of lines is made at `line_mask << 2`.
    fn data_aperture(line_mask: u8) -> u64 {
        u64::from(line_mask) << 2
    }

    fn read_u32(device: &mut PL061Device, offset: u64) -> u32 {
        let mut data = [0u8; 4];
        device.bus_read(offset, &mut data);
        u32::from_le_bytes(data)
    }

    fn write_u32(device: &mut PL061Device, offset: u64, value: u32) {
        device.bus_write(offset, &value.to_le_bytes());
    }

    fn read_u8(device: &mut PL061Device, offset: u64) -> u8 {
        let mut data = [0u8; 1];
        device.bus_read(offset, &mut data);
        data[0]
    }

    fn write_u8(device: &mut PL061Device, offset: u64, value: u8) {
        device.bus_write(offset, &[value]);
    }

    #[test]
    fn test_pl061_data_and_direction_registers() {
        let mut device = PL061Device::new().unwrap();

        // Lines 0 and 1 are outputs; the rest are inputs.
        write_u32(&mut device, PL061_DIR, 0b0000_0011);
        // A masked write to line 0 only affects line 0 (and only because it is an output).
        write_u32(&mut device, data_aperture(0b0000_0001), 0b1111_1111);

        assert_eq!(read_u32(&mut device, PL061_DIR), 0b0000_0011);
        assert_eq!(
            read_u32(&mut device, data_aperture(0b0000_0001)),
            0b0000_0001
        );

        // Drive input line 2 high from the host and read it back through its line mask.
        device.set_input_level(line_mask(2), true).unwrap();
        assert_eq!(
            read_u32(&mut device, data_aperture(0b0000_0100)),
            0b0000_0100
        );
    }

    #[test]
    fn test_pl061_edge_interrupts() {
        let mut device = PL061Device::new().unwrap();

        write_u32(&mut device, PL061_IEV, 0b0000_0001);
        write_u32(&mut device, PL061_IE, 0b0000_0001);

        device.trigger_power_button().unwrap();

        assert_eq!(read_u32(&mut device, PL061_RIS), 0b0000_0001);
        assert_eq!(read_u32(&mut device, PL061_MIS), 0b0000_0001);
        assert_eq!(device.interrupt_evt.read().unwrap(), 1);

        write_u32(&mut device, PL061_IC, 0b0000_0001);
        assert_eq!(read_u32(&mut device, PL061_RIS), 0);
        assert_eq!(read_u32(&mut device, PL061_MIS), 0);
    }

    #[test]
    fn test_pl061_both_edges_interrupt() {
        // This mirrors how the Linux gpio-keys driver wires the power button: it requests the
        // line's IRQ for both edges, so press (rising) and release (falling) must each interrupt.
        let mut device = PL061Device::new().unwrap();

        write_u32(&mut device, PL061_IBE, 0b0000_0001); // both-edge detection on line 0
        write_u32(&mut device, PL061_IE, 0b0000_0001); // unmask line 0

        // Rising edge (button press).
        device.trigger_power_button().unwrap();
        assert_eq!(read_u32(&mut device, PL061_RIS), 0b0000_0001);
        assert_eq!(read_u32(&mut device, PL061_MIS), 0b0000_0001);
        assert_eq!(device.interrupt_evt.read().unwrap(), 1);
        write_u32(&mut device, PL061_IC, 0b0000_0001); // ack
        assert_eq!(read_u32(&mut device, PL061_RIS), 0);

        // The driver's handler reads the line back, which releases the button; the falling
        // edge must interrupt as well.
        assert_eq!(
            read_u32(&mut device, data_aperture(0b0000_0001)),
            0b0000_0001
        );
        assert_eq!(read_u32(&mut device, PL061_RIS), 0b0000_0001);
        assert_eq!(read_u32(&mut device, PL061_MIS), 0b0000_0001);
        assert_eq!(device.interrupt_evt.read().unwrap(), 1);
    }

    #[test]
    fn test_pl061_power_button_is_held_until_the_guest_reads_it() {
        let mut device = PL061Device::new().unwrap();

        write_u32(&mut device, PL061_IBE, 0b0000_0001);
        write_u32(&mut device, PL061_IE, 0b0000_0001);

        device.trigger_power_button().unwrap();
        assert_eq!(device.interrupt_evt.read().unwrap(), 1);
        write_u32(&mut device, PL061_IC, 0b0000_0001); // ack the press

        // Reading the interrupt registers is not the guest observing the line, so the button
        // stays pressed. This is what makes a press issued against a paused vCPU survive.
        assert_eq!(read_u32(&mut device, PL061_RIS), 0);
        assert_eq!(read_u32(&mut device, PL061_MIS), 0);
        assert_eq!(
            read_u32(&mut device, data_aperture(0b0000_0001)),
            0b0000_0001
        );

        // Neither does a data access that does not select the power-button line.
        let mut device = PL061Device::new().unwrap();
        write_u32(&mut device, PL061_IBE, 0b0000_0001);
        write_u32(&mut device, PL061_IE, 0b0000_0001);
        device.trigger_power_button().unwrap();
        assert_eq!(device.interrupt_evt.read().unwrap(), 1);
        write_u32(&mut device, PL061_IC, 0b0000_0001);
        assert_eq!(read_u32(&mut device, data_aperture(0b0000_0010)), 0);
        assert_eq!(read_u32(&mut device, PL061_RIS), 0);

        // Reading the line does release it, latching the falling edge, and the button then
        // reads as released.
        assert_eq!(
            read_u32(&mut device, data_aperture(0b0000_0001)),
            0b0000_0001
        );
        assert_eq!(read_u32(&mut device, PL061_RIS), 0b0000_0001);
        assert_eq!(device.interrupt_evt.read().unwrap(), 1);
        assert_eq!(read_u32(&mut device, data_aperture(0b0000_0001)), 0);
    }

    #[test]
    fn test_pl061_pending_press_survives_a_read_of_an_output_line() {
        let mut device = PL061Device::new().unwrap();
        let power_button = line_mask(POWER_BUTTON_PIN);

        write_u32(&mut device, PL061_IEV, u32::from(power_button));
        write_u32(&mut device, PL061_IE, u32::from(power_button));
        device.trigger_power_button().unwrap();

        // The guest takes the line over as an output and reads it back. Such a read returns
        // the guest's own output value rather than observing the held input level, so it must
        // not release the press.
        write_u32(&mut device, PL061_DIR, u32::from(power_button));
        read_u32(&mut device, data_aperture(power_button));

        // Handing the line back makes the next read observe and release it, as usual.
        write_u32(&mut device, PL061_DIR, 0);
        assert_eq!(
            read_u32(&mut device, data_aperture(power_button)),
            u32::from(power_button)
        );
        assert_eq!(read_u32(&mut device, data_aperture(power_button)), 0);
    }

    #[test]
    fn test_pl061_power_button_press_rejected_when_line_is_an_output() {
        let mut device = PL061Device::new().unwrap();
        let power_button = u32::from(line_mask(POWER_BUTTON_PIN));

        // Arm a rising-edge interrupt on the power button line, as a guest driver would.
        write_u32(&mut device, PL061_IEV, power_button);
        write_u32(&mut device, PL061_IE, power_button);

        // The guest then takes the line over as an output, so it drives the level itself and
        // a host-side press can no longer reach it.
        write_u32(&mut device, PL061_DIR, power_button);

        let errors_before = METRICS.error_count.count();
        assert!(matches!(
            device.trigger_power_button(),
            Err(PL061Error::PowerButtonNotAnInput)
        ));
        assert_eq!(METRICS.error_count.count() - errors_before, 1);
        // Nothing was injected and nothing is left pending for a later read to release.
        assert_eq!(read_u32(&mut device, PL061_RIS), 0);
        device.interrupt_evt.read().unwrap_err();

        // Handing the line back to the host makes the button work again.
        write_u32(&mut device, PL061_DIR, 0);
        device.trigger_power_button().unwrap();
        assert_eq!(read_u32(&mut device, PL061_RIS), power_button);
    }

    #[test]
    fn test_pl061_pending_power_button_survives_snapshot_restore() {
        let mut device = PL061Device::new().unwrap();

        write_u32(&mut device, PL061_IBE, 0b0000_0001);
        write_u32(&mut device, PL061_IE, 0b0000_0001);

        // Press the button but never let the guest observe it, as happens when the microVM is
        // paused and then snapshotted.
        device.trigger_power_button().unwrap();
        assert_eq!(device.interrupt_evt.read().unwrap(), 1);

        let mut restored = PL061Device::from_state(&device.state()).unwrap();

        // The restored device gets a brand new eventfd, so the still-unacknowledged interrupt
        // has to be re-raised on it, and the button must still read as pressed.
        assert_eq!(restored.interrupt_evt.read().unwrap(), 1);
        assert_eq!(read_u32(&mut restored, PL061_MIS), 0b0000_0001);
        assert_eq!(
            read_u32(&mut restored, data_aperture(0b0000_0001)),
            0b0000_0001
        );
        // ... and releasing it afterwards still works on the restored device.
        assert_eq!(read_u32(&mut restored, data_aperture(0b0000_0001)), 0);
    }

    #[test]
    fn test_pl061_new_interrupt_signals_while_another_is_pending() {
        // A line going active must reach the guest even when a different line already has an
        // interrupt outstanding: the guest's handler may not have acknowledged the first one
        // yet, and an edge that is never signalled is lost for good.
        let mut device = PL061Device::new().unwrap();
        let line_0 = line_mask(0);
        let line_2 = line_mask(2);
        let lines = line_0 | line_2;

        write_u32(&mut device, PL061_IEV, u32::from(lines));
        write_u32(&mut device, PL061_IE, u32::from(lines));

        device.set_input_level(line_0, true).unwrap();
        device.set_input_level(line_2, true).unwrap();

        assert_eq!(read_u32(&mut device, PL061_MIS), u32::from(lines));
        assert_eq!(device.interrupt_evt.read().unwrap(), 2);
    }

    #[test]
    fn test_pl061_level_sensitive_interrupt_follows_the_level() {
        let mut device = PL061Device::new().unwrap();

        write_u32(&mut device, PL061_IS, 0b0000_0100); // line 2 level-sensitive
        write_u32(&mut device, PL061_IEV, 0b0000_0100); // active high
        write_u32(&mut device, PL061_IE, 0b0000_0100);

        device.set_input_level(line_mask(2), true).unwrap();
        assert_eq!(read_u32(&mut device, PL061_RIS), 0b0000_0100);
        assert_eq!(device.interrupt_evt.read().unwrap(), 1);

        // GPIOIC cannot clear a level-sensitive bit while the level is still active.
        write_u32(&mut device, PL061_IC, 0b0000_0100);
        assert_eq!(read_u32(&mut device, PL061_RIS), 0b0000_0100);

        // The bit clears itself once the level goes inactive.
        device.set_input_level(line_mask(2), false).unwrap();
        assert_eq!(read_u32(&mut device, PL061_RIS), 0);
        assert_eq!(read_u32(&mut device, PL061_MIS), 0);
    }

    #[test]
    fn test_pl061_level_sensitive_interrupt_asserts_on_configuration_change() {
        let mut device = PL061Device::new().unwrap();

        // The line is already high before the guest arms it, so arming must assert straight
        // away rather than wait for a level change that has already happened.
        device.set_input_level(line_mask(2), true).unwrap();
        assert_eq!(read_u32(&mut device, PL061_RIS), 0);

        write_u32(&mut device, PL061_IEV, 0b0000_0100);
        write_u32(&mut device, PL061_IE, 0b0000_0100);
        write_u32(&mut device, PL061_IS, 0b0000_0100);

        assert_eq!(read_u32(&mut device, PL061_RIS), 0b0000_0100);
        assert_eq!(read_u32(&mut device, PL061_MIS), 0b0000_0100);
        assert_eq!(device.interrupt_evt.read().unwrap(), 1);
    }

    #[test]
    fn test_pl061_byte_accesses_match_linux_driver_usage() {
        let mut device = PL061Device::new().unwrap();

        write_u8(&mut device, PL061_IEV, 0b0000_0001);
        write_u8(&mut device, PL061_IE, 0b0000_0001);

        device.trigger_power_button().unwrap();

        assert_eq!(
            read_u8(&mut device, data_aperture(0b0000_0001)),
            0b0000_0001
        );
        assert_eq!(read_u8(&mut device, PL061_RIS), 0b0000_0001);
        assert_eq!(read_u8(&mut device, PL061_MIS), 0b0000_0001);
        assert_eq!(device.interrupt_evt.read().unwrap(), 1);
    }

    #[test]
    fn test_pl061_id_registers() {
        let mut device = PL061Device::new().unwrap();

        for (index, expected) in PL061_ID.iter().enumerate() {
            let offset = PL061_ID_REG_START + (index as u64) * 4;
            assert_eq!(read_u32(&mut device, offset), u32::from(*expected));
        }
    }

    #[test]
    fn test_pl061_state_serialization_round_trip() {
        let mut device = PL061Device::new().unwrap();

        // Configure a representative register set, including a pending interrupt.
        write_u32(&mut device, PL061_DIR, 0b0000_0010);
        write_u32(&mut device, PL061_IEV, 0b0000_0001);
        write_u32(&mut device, PL061_IE, 0b0000_0001);
        device.set_input_level(line_mask(0), true).unwrap();
        let state = device.state();

        // Round-trip through the same serializer Firecracker uses for snapshots.
        let bytes = bitcode::serialize(&state).unwrap();
        let decoded: PL061State = bitcode::deserialize(&bytes).unwrap();
        assert_eq!(decoded, state);

        // A device rebuilt from the restored state must expose identical registers.
        let mut restored = PL061Device::from_state(&decoded).unwrap();
        assert_eq!(restored.state(), state);
        assert_eq!(read_u32(&mut restored, PL061_DIR), 0b0000_0010);
        assert_eq!(read_u32(&mut restored, PL061_IE), 0b0000_0001);
        assert_eq!(read_u32(&mut restored, PL061_RIS), 0b0000_0001);
    }

    #[test]
    fn test_pl061_invalid_access_metrics() {
        let mut device = PL061Device::new().unwrap();

        let errors_before = METRICS.error_count.count();
        let missed_reads_before = METRICS.missed_read_count.count();
        let missed_writes_before = METRICS.missed_write_count.count();

        device.bus_read(PL061_DIR, &mut [0u8; 2]);
        device.bus_write(PL061_REGISTER_SPACE_SIZE, &[0u8; 4]);

        assert_eq!(METRICS.error_count.count() - errors_before, 2);
        assert_eq!(METRICS.missed_read_count.count() - missed_reads_before, 1);
        assert_eq!(METRICS.missed_write_count.count() - missed_writes_before, 1);
    }
}
