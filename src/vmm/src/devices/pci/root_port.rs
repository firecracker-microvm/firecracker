// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Emulation of a PCI Express root port with native hot-plug support.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Barrier, Mutex};

use vm_allocator::RangeInclusive;
use vmm_sys_util::eventfd::EventFd;

use zerocopy::IntoBytes;

use crate::logger::error;
use crate::pci::bus::MAX_PCI_BUSES;
use crate::pci::configuration::{BAR0_REG_IDX, BarPrefetchable, Bars, PciConfiguration};
use crate::pci::msix::{MsixCap, MsixConfig};
use crate::pci::pcie_cap::{
    PCI_EXP_LNKSTA, PCI_EXP_LNKSTA_CLS_2_5GB, PCI_EXP_LNKSTA_DLLLA, PCI_EXP_LNKSTA_NLW_X1,
    PCI_EXP_SLTCTL, PCI_EXP_SLTCTL_ABPE, PCI_EXP_SLTCTL_DLLSCE, PCI_EXP_SLTCTL_HPIE,
    PCI_EXP_SLTCTL_PDCE, PCI_EXP_SLTCTL_PIC, PCI_EXP_SLTCTL_PWR_IND_OFF, PCI_EXP_SLTSTA_ABP,
    PCI_EXP_SLTSTA_DLLSC, PCI_EXP_SLTSTA_PDC, PCI_EXP_SLTSTA_PDS, PCI_EXP_SLTSTA_RW1C,
    PciExpressCap,
};
use crate::pci::{PciBridgeSubclass, PciClassCode, PciDevice, PciSBDF};
use crate::vstate::bus::BusDevice;
use crate::vstate::interrupts::MsixVectorGroup;

const VENDOR_ID_AMAZON: u16 = 0x1d0f;
const DEVICE_ID_AMAZON_RP: u16 = 0x0200;

const ROOT_PORT_MSIX_BAR: u8 = 0;
/// Size of the MSI-X BAR
pub const ROOT_PORT_MSIX_BAR_SIZE: u64 = 0x1000;
const ROOT_PORT_MSIX_TABLE_OFFSET: u32 = 0x0;
const ROOT_PORT_MSIX_PBA_OFFSET: u32 = 0x800;
const ROOT_PORT_MSIX_VECTORS: u16 = 1;

// A Type 1 header exposes two BAR registers; our 64-bit MSI-X BAR occupies
// both of them (BAR0 and BAR1).
const ROOT_PORT_NUM_BARS: u16 = 2;
const MSIX_TABLE_ENTRY_SIZE: u64 = 16;

const LINK_STATUS_UP: u16 = PCI_EXP_LNKSTA_DLLLA | PCI_EXP_LNKSTA_CLS_2_5GB | PCI_EXP_LNKSTA_NLW_X1;

/// Shared channel by which root ports report that a guest has acknowledged a
/// graceful hot-unplug and the device can be removed. The acknowledgement
/// arrives at a vCPU thread, but the device removal must be done in the main
/// thread. The eventfd is used to notify the main thread.
#[derive(Debug)]
pub struct HotplugCompletion {
    /// Signalled when the guest acks a removal.
    pub evt: EventFd,
    /// Secondary buses whose endpoints are ready to be torn down, bit `n`
    /// standing for bus `n`.
    pub acked_buses: AtomicU32,
}

const _: () = assert!(MAX_PCI_BUSES as u32 <= u32::BITS);

impl HotplugCompletion {
    /// Create a new completion channel.
    pub fn new() -> std::io::Result<Self> {
        Ok(HotplugCompletion {
            evt: EventFd::new(libc::EFD_NONBLOCK)?,
            acked_buses: AtomicU32::new(0),
        })
    }
}

/// A PCI Express root port with a hot-plug capable slot.
#[derive(Debug)]
pub struct PciRootPort {
    configuration: PciConfiguration,
    bars: Bars,
    pcie_cap_offset: u16,
    msix_cap_offset: u16,
    msix_config: Arc<Mutex<MsixConfig>>,
    slot_control: u16,
    slot_status: u16,
    link_status: u16,
    secondary_bus: u8,
    removal_requested: bool,
    completion: Arc<HotplugCompletion>,
}

impl PciRootPort {
    /// Create a new root port.
    ///
    /// * `sbdf` - the root port's own SBDF
    /// * `secondary_bus` - the bus number the port starts, which it also
    ///   advertises to the guest as its physical slot number
    /// * `msix_vectors` - a single-vector MSI-X group
    /// * `msix_bar_addr` - guest-physical base address of the MSI-X BAR
    /// * `completion` - channel for reporting acknowledged graceful removals
    pub fn new(
        sbdf: PciSBDF,
        secondary_bus: u8,
        msix_vectors: Arc<MsixVectorGroup>,
        msix_bar_addr: u64,
        completion: Arc<HotplugCompletion>,
    ) -> Self {
        assert_eq!(msix_vectors.num_vectors(), ROOT_PORT_MSIX_VECTORS);

        let mut configuration = PciConfiguration::new_type1(
            VENDOR_ID_AMAZON,
            DEVICE_ID_AMAZON_RP,
            0x1,
            PciClassCode::Bridge,
            PciBridgeSubclass::PciToPciBridge as u8,
        );

        // Add the PCIe and MSI-X capabilities
        let pcie_cap = PciExpressCap::new_root_port(u16::from(secondary_bus));
        let pcie_cap_offset = u16::from(configuration.add_capability(&pcie_cap));

        let msix_cap = MsixCap::new(
            ROOT_PORT_MSIX_BAR,
            ROOT_PORT_MSIX_VECTORS,
            ROOT_PORT_MSIX_TABLE_OFFSET,
            ROOT_PORT_MSIX_BAR,
            ROOT_PORT_MSIX_PBA_OFFSET,
        );
        let msix_cap_offset = u16::from(configuration.add_capability(&msix_cap));

        let msix_config = Arc::new(Mutex::new(MsixConfig::new(msix_vectors, sbdf)));

        // Register 6 is:
        // Secondary Latency Timer | Subordinate Bus | Secondary Bus | Primary Bus
        // Set the primary bus to 0 and the secondary and subordinate equal to
        // the bus started by this root port
        let bus_reg = (u32::from(secondary_bus) << 16) | (u32::from(secondary_bus) << 8);
        configuration.write_reg(6, bus_reg);

        // Set up the single 64-bit BAR hosting the MSI-x table
        let mut bars = Bars::default();
        bars.set_bar_64(
            ROOT_PORT_MSIX_BAR,
            msix_bar_addr,
            ROOT_PORT_MSIX_BAR_SIZE,
            BarPrefetchable::No,
        );

        PciRootPort {
            configuration,
            bars,
            pcie_cap_offset,
            msix_cap_offset,
            msix_config,
            slot_control: 0,
            slot_status: 0,
            link_status: 0,
            secondary_bus,
            removal_requested: false,
            completion,
        }
    }

    pub fn secondary_bus(&self) -> u8 {
        self.secondary_bus
    }

    /// Return the non-prefetchable memory window the guest programmed for this
    /// port, or `None` if the window is disabled (base > limit).
    pub fn nonpref_memory_window(&self) -> Option<RangeInclusive> {
        const MEMORY_WINDOW_REG: u16 = 8;

        let reg = self.configuration.read_reg(MEMORY_WINDOW_REG);
        let base = u64::from(reg & 0xfff0) << 16;
        let limit = (u64::from((reg >> 16) & 0xfff0) << 16) | 0xf_ffff;
        RangeInclusive::new(base, limit).ok()
    }

    fn slot_reg_idx(&self) -> u16 {
        (self.pcie_cap_offset + PCI_EXP_SLTCTL) / 4
    }

    fn link_reg_idx(&self) -> u16 {
        (self.pcie_cap_offset + PCI_EXP_LNKSTA) / 4
    }

    /// Return true if a hot-plug event that set `changed` Slot Status bits
    /// should raise an interrupt.
    fn must_inject_irq(&self, changed: u16) -> bool {
        if self.slot_control & PCI_EXP_SLTCTL_HPIE == 0 {
            return false;
        }

        if changed & PCI_EXP_SLTSTA_PDC != 0 && self.slot_control & PCI_EXP_SLTCTL_PDCE != 0 {
            return true;
        }
        if changed & PCI_EXP_SLTSTA_ABP != 0 && self.slot_control & PCI_EXP_SLTCTL_ABPE != 0 {
            return true;
        }
        if changed & PCI_EXP_SLTSTA_DLLSC != 0 && self.slot_control & PCI_EXP_SLTCTL_DLLSCE != 0 {
            return true;
        }

        false
    }

    /// Deliver the hot-plug MSI-X interrupt (vector 0). If MSI-X is masked or
    /// the vector is masked, record it in the Pending Bit Array instead.
    fn inject_irq(&self) {
        let mut config = self.msix_config.lock().expect("Poisoned lock");
        let masked = config.masked || config.table_entries[0].masked();
        if masked {
            config.set_pba_bit(0, false);
            return;
        }
        if let Err(err) = config.vectors.trigger(0) {
            error!("Failed to inject root port hot-plug interrupt: {err:?}");
        }
    }

    /// Signal that a device is present in the slot. When `hotplug` is true the
    /// device was inserted at runtime, so latch the change bits and raise the
    /// hot-plug interrupt; a device present from boot (`hotplug` false) is
    /// discovered by enumeration and needs no notification.
    pub fn plug(&mut self, hotplug: bool) {
        self.link_status |= LINK_STATUS_UP;
        self.slot_status |= PCI_EXP_SLTSTA_PDS;
        if hotplug {
            self.slot_status |= PCI_EXP_SLTSTA_PDC | PCI_EXP_SLTSTA_DLLSC;
            if self.must_inject_irq(PCI_EXP_SLTSTA_PDC | PCI_EXP_SLTSTA_DLLSC) {
                self.inject_irq();
            }
        }
    }

    /// Signal to the guest that a device is about to be unplugged.
    /// The device remains present until eject() is called (either after the
    /// guest acknowledges the removal or due to a force detach).
    pub fn request_unplug(&mut self) {
        self.removal_requested = true;
        self.slot_status |= PCI_EXP_SLTSTA_ABP;
        if self.must_inject_irq(PCI_EXP_SLTSTA_ABP) {
            self.inject_irq();
        }
    }

    /// Signal to the guest that slot is now empty.
    pub fn eject(&mut self) {
        self.removal_requested = false;
        self.link_status &= !LINK_STATUS_UP;
        self.slot_status &= !PCI_EXP_SLTSTA_PDS;
        self.slot_status |= PCI_EXP_SLTSTA_PDC | PCI_EXP_SLTSTA_DLLSC;
        if self.must_inject_irq(PCI_EXP_SLTSTA_PDC | PCI_EXP_SLTSTA_DLLSC) {
            self.inject_irq();
        }
    }

    /// Apply a guest write to the Slot Control / Slot Status DWORD.
    ///
    /// Return true if the write turned the Power Indicator off, which is the
    /// guest's acknowledgement that a managed removal may complete.
    fn write_slot_dword(&mut self, offset: u8, data: &[u8]) -> bool {
        // Writable bits of the Slot Control register (bits 0-12).
        const SLOT_CONTROL_WRITABLE_MASK: u16 = 0x1fff;

        let old_control = self.slot_control;
        let mut control_bytes = old_control.to_le_bytes();
        // A bitmap with bits to clear
        let mut status_w1c: u16 = 0;

        for (i, &byte) in data.iter().enumerate() {
            match usize::from(offset) + i {
                0 => control_bytes[0] = byte,
                1 => control_bytes[1] = byte,
                2 => status_w1c |= u16::from(byte),
                3 => status_w1c |= u16::from(byte) << 8,
                _ => {}
            }
        }

        let new_control = u16::from_le_bytes(control_bytes) & SLOT_CONTROL_WRITABLE_MASK;
        self.slot_control = new_control;
        // Clear the bits stored in status_w1c
        self.slot_status &= !(status_w1c & PCI_EXP_SLTSTA_RW1C);

        (new_control & PCI_EXP_SLTCTL_PIC == PCI_EXP_SLTCTL_PWR_IND_OFF)
            && (old_control & PCI_EXP_SLTCTL_PIC != PCI_EXP_SLTCTL_PWR_IND_OFF)
    }
}

impl PciDevice for PciRootPort {
    fn write_config_register(
        &mut self,
        reg_idx: u16,
        offset: u8,
        data: &[u8],
    ) -> Option<Arc<Barrier>> {
        let in_bars = (BAR0_REG_IDX..BAR0_REG_IDX + ROOT_PORT_NUM_BARS).contains(&reg_idx);
        // Only capture writes in the first 4 bytes of the capability,
        // everything else is served from `self.configuration`.
        let in_msix_cap_header = reg_idx * 4 == self.msix_cap_offset;

        if in_bars {
            #[allow(clippy::cast_possible_truncation)]
            let bar_idx = (reg_idx - BAR0_REG_IDX) as u8;
            self.bars.write(bar_idx, offset, data);
        } else if in_msix_cap_header {
            self.msix_config
                .lock()
                .expect("Poisoned lock")
                .write_msg_ctl_register(offset, data);
            self.configuration
                .write_config_register(reg_idx, offset, data);
        } else if reg_idx == self.slot_reg_idx() {
            let removal_acked = self.write_slot_dword(offset, data);
            if self.removal_requested && removal_acked {
                self.removal_requested = false;
                self.completion
                    .acked_buses
                    .fetch_or(1 << self.secondary_bus, Ordering::Release);
                if let Err(err) = self.completion.evt.write(1) {
                    error!("root_port: Failed to signal hot-unplug completion: {err}");
                }
            }
        } else {
            self.configuration
                .write_config_register(reg_idx, offset, data);
        }
        None
    }

    fn read_config_register(&mut self, reg_idx: u16) -> u32 {
        let in_bars = (BAR0_REG_IDX..BAR0_REG_IDX + ROOT_PORT_NUM_BARS).contains(&reg_idx);
        if in_bars {
            #[allow(clippy::cast_possible_truncation)]
            let bar_idx = (reg_idx - BAR0_REG_IDX) as u8;
            let mut value: u32 = 0;
            self.bars.read(bar_idx, 0, value.as_mut_bytes());
            value
        } else if reg_idx == self.slot_reg_idx() {
            (u32::from(self.slot_status) << 16) | u32::from(self.slot_control)
        } else if reg_idx == self.link_reg_idx() {
            (u32::from(self.link_status) << 16)
                | (self.configuration.read_reg(reg_idx) & 0x0000_ffff)
        } else {
            self.configuration.read_reg(reg_idx)
        }
    }

    fn read_bar(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        let table_end = u64::from(ROOT_PORT_MSIX_TABLE_OFFSET)
            + u64::from(ROOT_PORT_MSIX_VECTORS) * MSIX_TABLE_ENTRY_SIZE;
        if (u64::from(ROOT_PORT_MSIX_TABLE_OFFSET)..table_end).contains(&offset) {
            self.msix_config
                .lock()
                .expect("Poisoned lock")
                .read_table(offset - u64::from(ROOT_PORT_MSIX_TABLE_OFFSET), data);
        } else if offset >= u64::from(ROOT_PORT_MSIX_PBA_OFFSET) {
            self.msix_config
                .lock()
                .expect("Poisoned lock")
                .read_pba(offset - u64::from(ROOT_PORT_MSIX_PBA_OFFSET), data);
        }
    }

    fn write_bar(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        let table_end = u64::from(ROOT_PORT_MSIX_TABLE_OFFSET)
            + u64::from(ROOT_PORT_MSIX_VECTORS) * MSIX_TABLE_ENTRY_SIZE;
        if (u64::from(ROOT_PORT_MSIX_TABLE_OFFSET)..table_end).contains(&offset) {
            self.msix_config
                .lock()
                .expect("Poisoned lock")
                .write_table(offset - u64::from(ROOT_PORT_MSIX_TABLE_OFFSET), data);
        } else if offset >= u64::from(ROOT_PORT_MSIX_PBA_OFFSET) {
            self.msix_config
                .lock()
                .expect("Poisoned lock")
                .write_pba(offset - u64::from(ROOT_PORT_MSIX_PBA_OFFSET), data);
        }
        None
    }
}

impl BusDevice for PciRootPort {
    fn read(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        self.read_bar(base, offset, data)
    }

    fn write(&mut self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        self.write_bar(base, offset, data)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::builder::tests::default_vmm;
    use crate::pci::pcie_cap::{
        PCI_EXP_FLAGS, PCI_EXP_FLAGS_SLOT, PCI_EXP_SLTCAP, PCI_EXP_SLTCAP_HPC,
    };
    use crate::vstate::vm::KvmVm;

    fn new_msix_vectors() -> Arc<MsixVectorGroup> {
        let vmm = default_vmm();
        Arc::new(
            KvmVm::create_msix_group(vmm.vm.as_kvm().unwrap().clone(), ROOT_PORT_MSIX_VECTORS)
                .unwrap(),
        )
    }

    fn new_root_port() -> PciRootPort {
        PciRootPort::new(
            PciSBDF::new(0, 0, 1, 0),
            1,
            new_msix_vectors(),
            0x1_0000_0000,
            Arc::new(HotplugCompletion::new().unwrap()),
        )
    }

    #[test]
    fn test_root_port_config_header() {
        let mut rp = new_root_port();
        // Vendor/device IDs.
        assert_eq!(
            rp.read_config_register(0) & 0xffff,
            u32::from(VENDOR_ID_AMAZON)
        );
        // Header type 1 (bridge).
        assert_eq!((rp.read_config_register(3) >> 16) & 0xff, 0x01);
        // Class code is Bridge / PCI-to-PCI.
        let reg2 = rp.read_config_register(2);
        assert_eq!((reg2 >> 24) & 0xff, PciClassCode::Bridge as u32);
        assert_eq!(
            (reg2 >> 16) & 0xff,
            PciBridgeSubclass::PciToPciBridge as u32
        );
        // Secondary and subordinate bus numbers both equal 1.
        let bus_reg = rp.read_config_register(6);
        assert_eq!((bus_reg >> 8) & 0xff, 1);
        assert_eq!((bus_reg >> 16) & 0xff, 1);
    }

    #[test]
    fn test_root_port_pcie_cap() {
        let mut rp = new_root_port();
        let cap_off = rp.pcie_cap_offset;

        // The PCI Express Capabilities register advertises Slot Implemented.
        let flags_reg = (cap_off + PCI_EXP_FLAGS - 2) / 4;
        let flags = (rp.read_config_register(flags_reg) >> 16) as u16;
        assert_ne!(flags & PCI_EXP_FLAGS_SLOT, 0);

        // Slot Capabilities advertise Hot-Plug Capable.
        let sltcap_reg = (cap_off + PCI_EXP_SLTCAP) / 4;
        let sltcap = rp.read_config_register(sltcap_reg);
        assert_ne!(sltcap & PCI_EXP_SLTCAP_HPC, 0);
    }

    #[test]
    fn test_hotplug_irq_gating() {
        let mut rp = new_root_port();

        // No enables set: not armed.
        assert!(!rp.must_inject_irq(PCI_EXP_SLTSTA_PDC));

        // HPIE alone is not enough without the per-event enable.
        rp.slot_control = PCI_EXP_SLTCTL_HPIE;
        assert!(!rp.must_inject_irq(PCI_EXP_SLTSTA_PDC));

        // HPIE + PDCE arms a presence-detect-change interrupt.
        rp.slot_control = PCI_EXP_SLTCTL_HPIE | PCI_EXP_SLTCTL_PDCE;
        assert!(rp.must_inject_irq(PCI_EXP_SLTSTA_PDC));

        // PDCE without HPIE is not armed.
        rp.slot_control = PCI_EXP_SLTCTL_PDCE;
        assert!(!rp.must_inject_irq(PCI_EXP_SLTSTA_PDC));
    }

    #[test]
    fn test_power_indicator_off_ack() {
        let mut rp = new_root_port();

        // The indicator blinking (value 0x0200) while the guest quiesces the
        // device is not an ack.
        assert!(!rp.write_slot_dword(0, &0x0200u16.to_le_bytes()));
        // Switching it off is the managed-removal acknowledgement.
        assert!(rp.write_slot_dword(0, &PCI_EXP_SLTCTL_PWR_IND_OFF.to_le_bytes()));
        // Staying off is not a new transition.
        assert!(!rp.write_slot_dword(0, &PCI_EXP_SLTCTL_PWR_IND_OFF.to_le_bytes()));
    }

    #[test]
    fn test_graceful_removal_reports_the_guest_ack() {
        let completion = Arc::new(HotplugCompletion::new().unwrap());
        let mut rp = PciRootPort::new(
            PciSBDF::new(0, 0, 1, 0),
            7,
            new_msix_vectors(),
            0x1_0000_0000,
            completion.clone(),
        );
        let reg = rp.slot_reg_idx();
        rp.plug(true);

        // A power-off with no removal pending is the guest's business, not an
        // acknowledgement of anything.
        rp.write_config_register(reg, 0, &PCI_EXP_SLTCTL_PWR_IND_OFF.to_le_bytes());
        assert_eq!(completion.acked_buses.load(Ordering::Relaxed), 0);

        // Once asked, the same write means the device can go, and names the
        // secondary bus so the VMM can find it.
        rp.request_unplug();
        rp.write_config_register(reg, 0, &0u16.to_le_bytes());
        rp.write_config_register(reg, 0, &PCI_EXP_SLTCTL_PWR_IND_OFF.to_le_bytes());
        assert_eq!(completion.acked_buses.load(Ordering::Relaxed), 1 << 7);
        assert_eq!(completion.evt.read().unwrap(), 1);

        // The request is one-shot: a later power-off does not report again.
        rp.write_config_register(reg, 0, &0u16.to_le_bytes());
        rp.write_config_register(reg, 0, &PCI_EXP_SLTCTL_PWR_IND_OFF.to_le_bytes());
        assert_eq!(completion.acked_buses.load(Ordering::Relaxed), 1 << 7);
    }

    #[test]
    fn test_forced_removal_expects_no_ack() {
        let completion = Arc::new(HotplugCompletion::new().unwrap());
        let mut rp = PciRootPort::new(
            PciSBDF::new(0, 0, 1, 0),
            7,
            new_msix_vectors(),
            0x1_0000_0000,
            completion.clone(),
        );
        let reg = rp.slot_reg_idx();
        rp.plug(true);
        rp.eject();

        // The device is already gone, so a late power-off from the guest must
        // not ask the VMM to tear it down a second time.
        rp.write_config_register(reg, 0, &PCI_EXP_SLTCTL_PWR_IND_OFF.to_le_bytes());
        assert_eq!(completion.acked_buses.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_boot_time_plug_is_silent() {
        let mut rp = new_root_port();
        let reg = rp.slot_reg_idx();

        // Arm every hot-plug notification the port supports.
        let ctl = PCI_EXP_SLTCTL_HPIE | PCI_EXP_SLTCTL_PDCE | PCI_EXP_SLTCTL_DLLSCE;
        rp.write_config_register(reg, 0, &ctl.to_le_bytes());

        // A device present from boot is found by ordinary enumeration, so the
        // slot reports it as present but latches no change bits.
        rp.plug(false);
        let status = (rp.read_config_register(reg) >> 16) as u16;
        assert_ne!(status & PCI_EXP_SLTSTA_PDS, 0);
        assert_eq!(status & PCI_EXP_SLTSTA_PDC, 0);
        assert_eq!(status & PCI_EXP_SLTSTA_DLLSC, 0);
    }

    #[test]
    fn test_link_status_reflects_presence() {
        let mut rp = new_root_port();
        let link_reg = rp.link_reg_idx();

        // Empty slot: link is down.
        assert_eq!(
            (rp.read_config_register(link_reg) >> 16) as u16 & PCI_EXP_LNKSTA_DLLLA,
            0
        );
        // After plug, Data Link Layer Link Active is set.
        rp.plug(true);
        assert_ne!(
            (rp.read_config_register(link_reg) >> 16) as u16 & PCI_EXP_LNKSTA_DLLLA,
            0
        );
        // After eject, link goes down again.
        rp.eject();
        assert_eq!(
            (rp.read_config_register(link_reg) >> 16) as u16 & PCI_EXP_LNKSTA_DLLLA,
            0
        );
    }
}
