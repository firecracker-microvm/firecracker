// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::sync::{Arc, Mutex};

use byteorder::{ByteOrder, LittleEndian};
use serde::{Deserialize, Serialize};

use super::BarReprogrammingParams;
use super::msix::MsixConfig;
use crate::logger::{info, warn};
use crate::pci::{PciCapabilityId, PciClassCode};

/// Errors from restoring PCI configuration state.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum PciConfigurationError {
    /// Invalid registers length: {0}
    InvalidRegistersLength(usize),
    /// Invalid writable_bits length: {0}
    InvalidWritableBitsLength(usize),
    /// Invalid bars length: {0}
    InvalidBarsLength(usize),
    /// Invalid cap_pci_cfg length: {0}
    InvalidCapPciCfgLength(usize),
}

// The number of 32bit registers in the config space, 4096 bytes.
const NUM_CONFIGURATION_REGISTERS: usize = 1024;

const STATUS_REG: usize = 1;
const STATUS_REG_CAPABILITIES_USED_MASK: u32 = 0x0010_0000;
const BAR0_REG: u16 = 4;
const ROM_BAR_REG: u16 = 12;
const BAR_MEM_ADDR_MASK: u32 = 0xffff_fff0;
const ROM_BAR_ADDR_MASK: u32 = 0xffff_f800;
const MSI_CAPABILITY_REGISTER_MASK: u32 = 0x0071_0000;
const MSIX_CAPABILITY_REGISTER_MASK: u32 = 0xc000_0000;
const NUM_BAR_REGS: usize = 6;
const CAPABILITY_LIST_HEAD_OFFSET: u8 = 0x34;
const FIRST_CAPABILITY_OFFSET: u8 = 0x40;
const CAPABILITY_MAX_OFFSET: u16 = 192;

/// A PCI capability list. Devices can optionally specify capabilities in their configuration space.
pub trait PciCapability {
    /// Bytes of the PCI capability
    fn bytes(&self) -> &[u8];
    /// Id of the PCI capability
    fn id(&self) -> PciCapabilityId;
}

// This encodes the BAR size as expected by the software running inside the guest.
// It assumes that bar_size is not 0
fn encode_64_bits_bar_size(bar_size: u64) -> (u32, u32) {
    assert_ne!(bar_size, 0);
    let result = !(bar_size - 1);
    let result_hi = (result >> 32) as u32;
    let result_lo = (result & 0xffff_ffff) as u32;
    (result_hi, result_lo)
}

// This decoes the BAR size from the value stored in the BAR registers.
fn decode_64_bits_bar_size(bar_size_hi: u32, bar_size_lo: u32) -> u64 {
    let bar_size: u64 = ((bar_size_hi as u64) << 32) | (bar_size_lo as u64);
    let size = !bar_size + 1;
    assert_ne!(size, 0);
    size
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
struct PciBar {
    addr: u32,
    size: u32,
    used: bool,
}

/// PCI configuration space state for (de)serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PciConfigurationState {
    registers: Vec<u32>,
    writable_bits: Vec<u32>,
    bars: Vec<PciBar>,
    last_capability: Option<(u8, u8)>,
    msix_cap_reg_idx: Option<u16>,
}

#[derive(Debug)]
/// Contains the configuration space of a PCI node.
///
/// See the [specification](https://en.wikipedia.org/wiki/PCI_configuration_space).
/// The configuration space is accessed with DWORD reads and writes from the guest.
pub struct PciConfiguration {
    registers: [u32; NUM_CONFIGURATION_REGISTERS],
    writable_bits: [u32; NUM_CONFIGURATION_REGISTERS], // writable bits for each register.
    bars: [PciBar; NUM_BAR_REGS],
    // Contains the byte offset and size of the last capability.
    last_capability: Option<(u8, u8)>,
    msix_cap_reg_idx: Option<u16>,
    msix_config: Option<Arc<Mutex<MsixConfig>>>,
}

impl PciConfiguration {
    #[allow(clippy::too_many_arguments)]
    /// Create a new type 0 PCI configuration
    pub fn new_type0(
        vendor_id: u16,
        device_id: u16,
        revision_id: u8,
        class_code: PciClassCode,
        subclass: u8,
        subsystem_vendor_id: u16,
        subsystem_id: u16,
        msix_config: Option<Arc<Mutex<MsixConfig>>>,
    ) -> Self {
        let mut registers = [0u32; NUM_CONFIGURATION_REGISTERS];
        let mut writable_bits = [0u32; NUM_CONFIGURATION_REGISTERS];
        registers[0] = (u32::from(device_id) << 16) | u32::from(vendor_id);
        // TODO(dverkamp): Status should be write-1-to-clear
        writable_bits[1] = 0x0000_ffff; // Status (r/o), command (r/w)
        registers[2] = (u32::from(class_code as u8) << 24)
            | (u32::from(subclass) << 16)
            | u32::from(revision_id);
        writable_bits[3] = 0x0000_00ff; // Cacheline size (r/w)
        registers[3] = 0x0000_0000; // Header type 0 (device)
        writable_bits[15] = 0x0000_00ff; // IRQ line (r/w)
        registers[11] = (u32::from(subsystem_id) << 16) | u32::from(subsystem_vendor_id);

        PciConfiguration {
            registers,
            writable_bits,
            bars: [PciBar::default(); NUM_BAR_REGS],
            last_capability: None,
            msix_cap_reg_idx: None,
            msix_config,
        }
    }

    /// Create a type 0 PCI configuration from snapshot state
    pub fn type0_from_state(
        state: PciConfigurationState,
        msix_config: Option<Arc<Mutex<MsixConfig>>>,
    ) -> Result<Self, PciConfigurationError> {
        let reg_len = state.registers.len();
        let registers = state
            .registers
            .try_into()
            .map_err(|_| PciConfigurationError::InvalidRegistersLength(reg_len))?;

        let wb_len = state.writable_bits.len();
        let writable_bits = state
            .writable_bits
            .try_into()
            .map_err(|_| PciConfigurationError::InvalidWritableBitsLength(wb_len))?;

        let bar_len = state.bars.len();
        let bars = state
            .bars
            .try_into()
            .map_err(|_| PciConfigurationError::InvalidBarsLength(bar_len))?;

        Ok(PciConfiguration {
            registers,
            writable_bits,
            bars,
            last_capability: state.last_capability,
            msix_cap_reg_idx: state.msix_cap_reg_idx,
            msix_config,
        })
    }

    /// Create PCI configuration space state
    pub fn state(&self) -> PciConfigurationState {
        PciConfigurationState {
            registers: self.registers.to_vec(),
            writable_bits: self.writable_bits.to_vec(),
            bars: self.bars.to_vec(),
            last_capability: self.last_capability,
            msix_cap_reg_idx: self.msix_cap_reg_idx,
        }
    }

    /// Reads a 32bit register from `reg_idx` in the register map.
    pub fn read_reg(&self, reg_idx: u16) -> u32 {
        *(self.registers.get(reg_idx as usize).unwrap_or(&0xffff_ffff))
    }

    /// Writes a 32bit register to `reg_idx` in the register map.
    pub fn write_reg(&mut self, reg_idx: u16, value: u32) {
        let mut mask = self.writable_bits[reg_idx as usize];

        if (BAR0_REG as usize..BAR0_REG as usize + NUM_BAR_REGS).contains(&(reg_idx as usize)) {
            // Handle very specific case where the BAR is being written with
            // all 1's to retrieve the BAR size during next BAR reading.
            if value == 0xffff_ffff {
                mask &= self.bars[(reg_idx - BAR0_REG) as usize].size;
            }
        } else if reg_idx == ROM_BAR_REG {
            // Handle very specific case where the BAR is being written with
            // all 1's on bits 31-11 to retrieve the BAR size during next BAR
            // reading.
            if value & ROM_BAR_ADDR_MASK == ROM_BAR_ADDR_MASK {
                mask = 0;
            }
        }

        if let Some(r) = self.registers.get_mut(reg_idx as usize) {
            *r = (*r & !self.writable_bits[reg_idx as usize]) | (value & mask);
        } else {
            warn!("bad PCI register write {}", reg_idx);
        }
    }

    /// Writes a 16bit word to `offset`. `offset` must be 16bit aligned.
    pub fn write_word(&mut self, offset: u16, value: u16) {
        let shift = match offset % 4 {
            0 => 0,
            2 => 16,
            _ => {
                warn!("bad PCI config write offset {}", offset);
                return;
            }
        };
        let reg_idx = (offset / 4) as usize;

        if let Some(r) = self.registers.get_mut(reg_idx) {
            let writable_mask = self.writable_bits[reg_idx];
            let mask = (0xffffu32 << shift) & writable_mask;
            let shifted_value = (u32::from(value) << shift) & writable_mask;
            *r = *r & !mask | shifted_value;
        } else {
            warn!("bad PCI config write offset {}", offset);
        }
    }

    /// Writes a byte to `offset`.
    pub fn write_byte(&mut self, offset: u16, value: u8) {
        self.write_byte_internal(offset, value, true);
    }

    /// Writes a byte to `offset`, optionally enforcing read-only bits.
    fn write_byte_internal(&mut self, offset: u16, value: u8, apply_writable_mask: bool) {
        let shift = (offset as usize % 4) * 8;
        let reg_idx = offset as usize / 4;

        if let Some(r) = self.registers.get_mut(reg_idx) {
            let writable_mask = if apply_writable_mask {
                self.writable_bits[reg_idx]
            } else {
                0xffff_ffff
            };
            let mask = (0xffu32 << shift) & writable_mask;
            let shifted_value = (u32::from(value) << shift) & writable_mask;
            *r = *r & !mask | shifted_value;
        } else {
            warn!("bad PCI config write offset {}", offset);
        }
    }

    /// Add the [addr, addr + size) BAR region.
    ///
    /// Configures the specified BAR to report this region and size to the guest kernel.
    /// Enforces a few constraints (i.e, region size must be power of two, register not already
    /// used).
    pub fn add_pci_bar(&mut self, bar_idx: u8, addr: u64, size: u64) {
        let reg_idx = (BAR0_REG + u16::from(bar_idx)) as usize;

        // These are a few constraints that are imposed due to the fact
        // that only VirtIO devices are actually allocating a BAR. Moreover, this is
        // a single 64-bit BAR. Not conforming to these requirements is an internal
        // Firecracker bug.

        // We are only using BAR 0
        assert_eq!(bar_idx, 0);
        // We shouldn't be trying to use the same BAR twice
        assert!(!self.bars[0].used);
        assert!(!self.bars[1].used);
        // We can't have a size of 0
        assert_ne!(size, 0);
        // BAR size needs to be a power of two
        assert!(size.is_power_of_two());
        // We should not be overflowing the address space
        addr.checked_add(size - 1).unwrap();

        // Encode the BAR size as expected by the software running in
        // the guest.
        let (bar_size_hi, bar_size_lo) = encode_64_bits_bar_size(size);

        self.registers[reg_idx + 1] = (addr >> 32) as u32;
        self.writable_bits[reg_idx + 1] = 0xffff_ffff;
        self.bars[bar_idx as usize + 1].addr = self.registers[reg_idx + 1];
        self.bars[bar_idx as usize].size = bar_size_lo;
        self.bars[bar_idx as usize + 1].size = bar_size_hi;
        self.bars[bar_idx as usize + 1].used = true;

        // Addresses of memory BARs are 16-byte aligned so the lower 4 bits are always 0. Within
        // the register we use this 4 bits to encode extra information about the BAR. The meaning
        // of these bits is:
        //
        // |    Bit 3     | Bits 2-1 |  Bit 0   |
        // | Prefetchable |   type   | Always 0 |
        //
        // Non-prefetchable, 64 bits BAR region
        self.registers[reg_idx] = (((addr & 0xffff_ffff) as u32) & BAR_MEM_ADDR_MASK) | 4u32;
        self.writable_bits[reg_idx] = BAR_MEM_ADDR_MASK;
        self.bars[bar_idx as usize].addr = self.registers[reg_idx];
        self.bars[bar_idx as usize].used = true;
    }

    /// Returns the address of the given BAR region.
    ///
    /// This assumes that `bar_idx` is a valid BAR register.
    pub fn get_bar_addr(&self, bar_idx: u8) -> u64 {
        assert!((bar_idx as usize) < NUM_BAR_REGS);

        let reg_idx = (BAR0_REG + u16::from(bar_idx)) as usize;

        (u64::from(self.bars[bar_idx as usize].addr & self.writable_bits[reg_idx]))
            | (u64::from(self.bars[bar_idx as usize + 1].addr) << 32)
    }

    /// Adds the capability `cap_data` to the list of capabilities.
    ///
    /// `cap_data` should not include the two-byte PCI capability header (type, next).
    /// Correct values will be generated automatically based on `cap_data.id()` and
    /// `cap_data.len()`.
    pub fn add_capability(&mut self, cap_data: &dyn PciCapability) -> u8 {
        let total_len = cap_data.bytes().len() + 2;
        assert!(total_len < usize::from(u8::MAX));
        // We assert that the len fit in u8
        #[allow(clippy::cast_possible_truncation)]
        let total_len = total_len as u8;

        let (cap_offset, tail_offset) = match self.last_capability {
            Some((offset, len)) => (Self::next_dword(offset, len), offset + 1),
            None => (FIRST_CAPABILITY_OFFSET, CAPABILITY_LIST_HEAD_OFFSET),
        };

        // We know that the capabilities we are using have a valid size (doesn't overflow) and that
        // we add capabilities that fit in the available space. If any of these requirements don't
        // hold, this is due to a Firecracker bug.
        let end_offset = u16::from(cap_offset) + u16::from(total_len);
        assert!(end_offset <= CAPABILITY_MAX_OFFSET);
        self.registers[STATUS_REG] |= STATUS_REG_CAPABILITIES_USED_MASK;
        self.write_byte_internal(u16::from(tail_offset), cap_offset, false);
        self.write_byte_internal(u16::from(cap_offset), cap_data.id() as u8, false);
        self.write_byte_internal(u16::from(cap_offset) + 1, 0, false); // Next pointer.
        for (i, byte) in cap_data.bytes().iter().enumerate() {
            // We asserted that the number of bytes fit into u8 and so in u16
            #[allow(clippy::cast_possible_truncation)]
            let i = i as u16;
            self.write_byte_internal(u16::from(cap_offset) + i + 2, *byte, false);
        }
        self.last_capability = Some((cap_offset, total_len));

        match cap_data.id() {
            PciCapabilityId::MessageSignalledInterrupts => {
                self.writable_bits[(cap_offset / 4) as usize] = MSI_CAPABILITY_REGISTER_MASK;
            }
            PciCapabilityId::MsiX => {
                self.msix_cap_reg_idx = Some(u16::from(cap_offset) / 4);
                self.writable_bits[self.msix_cap_reg_idx.unwrap() as usize] =
                    MSIX_CAPABILITY_REGISTER_MASK;
            }
            _ => {}
        }

        cap_offset
    }

    // Find the next aligned offset after the one given.
    fn next_dword(offset: u8, len: u8) -> u8 {
        let next = offset + len;
        (next + 3) & !3
    }

    /// Write a PCI configuration register
    pub fn write_config_register(&mut self, reg_idx: u16, offset: u8, data: &[u8]) {
        if reg_idx as usize >= NUM_CONFIGURATION_REGISTERS {
            return;
        }

        if offset as usize + data.len() > 4 {
            return;
        }

        // Handle potential write to MSI-X message control register
        if let Some(msix_cap_reg_idx) = self.msix_cap_reg_idx
            && let Some(msix_config) = &self.msix_config
        {
            if msix_cap_reg_idx == reg_idx && offset == 2 && data.len() == 2 {
                // 2-bytes write in the Message Control field
                msix_config
                    .lock()
                    .unwrap()
                    .set_msg_ctl(LittleEndian::read_u16(data));
            } else if msix_cap_reg_idx == reg_idx && offset == 0 && data.len() == 4 {
                // 4 bytes write at the beginning. Ignore the first 2 bytes which are the
                // capability id and next capability pointer
                msix_config
                    .lock()
                    .unwrap()
                    .set_msg_ctl((LittleEndian::read_u32(data) >> 16) as u16);
            }
        }

        match data.len() {
            1 => self.write_byte(reg_idx * 4 + offset as u16, data[0]),
            2 => self.write_word(
                reg_idx * 4 + offset as u16,
                u16::from(data[0]) | (u16::from(data[1]) << 8),
            ),
            4 => self.write_reg(reg_idx, LittleEndian::read_u32(data)),
            _ => (),
        }
    }

    /// Detect whether the guest wants to reprogram the address of a BAR
    pub fn detect_bar_reprogramming(
        &mut self,
        reg_idx: u16,
        data: &[u8],
    ) -> Option<BarReprogrammingParams> {
        if data.len() != 4 {
            return None;
        }

        let value = LittleEndian::read_u32(data);

        let mask = self.writable_bits[reg_idx as usize];
        if !(BAR0_REG as usize..BAR0_REG as usize + NUM_BAR_REGS).contains(&(reg_idx as usize)) {
            return None;
        }

        // Ignore the case where the BAR size is being asked for.
        if value == 0xffff_ffff {
            return None;
        }

        let bar_idx = (reg_idx - BAR0_REG) as usize;

        // Do not reprogram BARs we are not using
        if !self.bars[bar_idx].used {
            return None;
        }

        // We are always using 64bit BARs, so two BAR registers. We don't do anything until
        // the upper BAR is modified, otherwise we would be moving the BAR to a wrong
        // location in memory.
        if bar_idx == 0 {
            return None;
        }

        // The lower BAR (of this 64bit BAR) has been reprogrammed to a different value
        // than it used to be
        let reg_idx = reg_idx as usize;
        if (self.registers[reg_idx - 1] & self.writable_bits[reg_idx - 1])
                    != (self.bars[bar_idx - 1].addr & self.writable_bits[reg_idx - 1]) ||
                    // Or the lower BAR hasn't been changed but the upper one is being reprogrammed
                    // now to a different value
                    (value & mask) != (self.bars[bar_idx].addr & mask)
        {
            info!(
                "Detected BAR reprogramming: (BAR {}) 0x{:x}->0x{:x}",
                reg_idx, self.registers[reg_idx], value
            );
            let old_base = (u64::from(self.bars[bar_idx].addr & mask) << 32)
                | u64::from(self.bars[bar_idx - 1].addr & self.writable_bits[reg_idx - 1]);
            let new_base = (u64::from(value & mask) << 32)
                | u64::from(self.registers[reg_idx - 1] & self.writable_bits[reg_idx - 1]);
            let len = decode_64_bits_bar_size(self.bars[bar_idx].size, self.bars[bar_idx - 1].size);

            self.bars[bar_idx].addr = value;
            self.bars[bar_idx - 1].addr = self.registers[reg_idx - 1];

            return Some(BarReprogrammingParams {
                old_base,
                new_base,
                len,
            });
        }

        None
    }
}

#[cfg(test)]
// There ase some constants that still use bigger types than needed, but we
// only cast them to smaller types in unit tests.
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use vm_memory::ByteValued;

    use super::*;
    use crate::pci::PciMultimediaSubclass;
    use crate::pci::msix::MsixCap;

    #[repr(C, packed)]
    #[derive(Clone, Copy, Default)]
    #[allow(dead_code)]
    struct TestCap {
        len: u8,
        foo: u8,
    }

    // SAFETY: All members are simple numbers and any value is valid.
    unsafe impl ByteValued for TestCap {}

    impl PciCapability for TestCap {
        fn bytes(&self) -> &[u8] {
            self.as_slice()
        }

        fn id(&self) -> PciCapabilityId {
            PciCapabilityId::VendorSpecific
        }
    }

    struct BadCap {
        data: Vec<u8>,
    }

    impl BadCap {
        fn new(len: u8) -> Self {
            Self {
                data: (0..len).collect(),
            }
        }
    }

    impl PciCapability for BadCap {
        fn bytes(&self) -> &[u8] {
            &self.data
        }

        fn id(&self) -> PciCapabilityId {
            PciCapabilityId::VendorSpecific
        }
    }

    #[test]
    #[should_panic]
    fn test_too_big_capability() {
        let mut cfg = default_pci_config();
        cfg.add_capability(&BadCap::new(127));
    }

    #[test]
    #[should_panic]
    fn test_capability_space_overflow() {
        let mut cfg = default_pci_config();
        cfg.add_capability(&BadCap::new(62));
        cfg.add_capability(&BadCap::new(62));
        cfg.add_capability(&BadCap::new(0));
    }

    #[test]
    fn test_add_capability() {
        let mut cfg = default_pci_config();

        // Reset capabilities
        cfg.last_capability = None;

        // Add two capabilities with different contents.
        let cap1 = TestCap { len: 4, foo: 0xAA };
        let cap1_offset = cfg.add_capability(&cap1);
        assert_eq!(cap1_offset % 4, 0);

        let cap2 = TestCap {
            len: 0x04,
            foo: 0x55,
        };
        let cap2_offset = cfg.add_capability(&cap2);
        assert_eq!(cap2_offset % 4, 0);

        // The capability list head should be pointing to cap1.
        let cap_ptr = cfg.read_reg(u16::from(CAPABILITY_LIST_HEAD_OFFSET) / 4) & 0xFF;
        assert_eq!(cap1_offset as u32, cap_ptr);

        // Verify the contents of the capabilities.
        let cap1_data = cfg.read_reg(u16::from(cap1_offset) / 4);
        assert_eq!(cap1_data & 0xFF, 0x09); // capability ID
        assert_eq!((cap1_data >> 8) & 0xFF, u32::from(cap2_offset)); // next capability pointer
        assert_eq!((cap1_data >> 16) & 0xFF, 0x04); // cap1.len
        assert_eq!((cap1_data >> 24) & 0xFF, 0xAA); // cap1.foo

        let cap2_data = cfg.read_reg(u16::from(cap2_offset) / 4);
        assert_eq!(cap2_data & 0xFF, 0x09); // capability ID
        assert_eq!((cap2_data >> 8) & 0xFF, 0x00); // next capability pointer
        assert_eq!((cap2_data >> 16) & 0xFF, 0x04); // cap2.len
        assert_eq!((cap2_data >> 24) & 0xFF, 0x55); // cap2.foo
    }

    #[test]
    fn test_msix_capability() {
        let mut cfg = default_pci_config();

        // Information about the MSI-X capability layout: https://wiki.osdev.org/PCI#Enabling_MSI-X
        let msix_cap = MsixCap::new(
            3,      // Using BAR3 for message control table
            1024,   // 1024 MSI-X vectors
            0x4000, // Offset of message control table inside the BAR
            4,      // BAR4 used for pending control bit
            0x420,  // Offset of pending bit array (PBA) inside BAR
        );
        cfg.add_capability(&msix_cap);

        let cap_reg = u16::from(FIRST_CAPABILITY_OFFSET) / 4;
        let reg = cfg.read_reg(cap_reg);
        // Capability ID is MSI-X
        assert_eq!(
            PciCapabilityId::from((reg & 0xff) as u8),
            PciCapabilityId::MsiX
        );
        // We only have one capability, so `next` should be 0
        assert_eq!(((reg >> 8) & 0xff) as u8, 0);
        let msg_ctl = (reg >> 16) as u16;

        // MSI-X is enabled
        assert_eq!(msg_ctl & 0x8000, 0x8000);
        // Vectors are not masked
        assert_eq!(msg_ctl & 0x4000, 0x0);
        // Reserved bits are 0
        assert_eq!(msg_ctl & 0x3800, 0x0);
        // We've got 1024 vectors (Table size is N-1 encoded)
        assert_eq!((msg_ctl & 0x7ff) + 1, 1024);

        let reg = cfg.read_reg(cap_reg + 1);
        // We are using BAR3
        assert_eq!(reg & 0x7, 3);
        // Message Control Table is located in offset 0x4000 inside the BAR
        // We don't need to shift. Offset needs to be 8-byte aligned - so BIR
        // is stored in its last 3 bits (which we need to mask out).
        assert_eq!(reg & 0xffff_fff8, 0x4000);

        let reg = cfg.read_reg(cap_reg + 2);
        // PBA is 0x420 bytes inside BAR4
        assert_eq!(reg & 0x7, 4);
        assert_eq!(reg & 0xffff_fff8, 0x420);

        // Check read/write mask
        // Capability Id of MSI-X is 0x11
        cfg.write_config_register(cap_reg, 0, &[0x0]);
        assert_eq!(
            PciCapabilityId::from((cfg.read_reg(cap_reg) & 0xff) as u8),
            PciCapabilityId::MsiX
        );
        // Cannot override next capability pointer
        cfg.write_config_register(cap_reg, 1, &[0x42]);
        assert_eq!((cfg.read_reg(cap_reg) >> 8) & 0xff, 0);

        // We are writing this:
        //
        // meaning: | MSI enabled | Vectors Masked | Reserved | Table size |
        // bit:     |     15      |       14       |  13 - 11 |   0 - 10   |
        // R/W:     |     R/W     |       R/W      |     R    |     R      |
        let msg_ctl = (cfg.read_reg(cap_reg) >> 16) as u16;
        // Try to flip all bits
        cfg.write_config_register(cap_reg, 2, &u16::to_le_bytes(!msg_ctl));
        let msg_ctl = (cfg.read_reg(cap_reg) >> 16) as u16;
        // MSI enabled and Vectors masked should be flipped (MSI disabled and vectors masked)
        assert_eq!(msg_ctl & 0xc000, 0x4000);
        // Reserved bits should still be 0
        assert_eq!(msg_ctl & 0x3800, 0);
        // Table size should not have changed
        assert_eq!((msg_ctl & 0x07ff) + 1, 1024);

        // Table offset is read only
        let table_offset = cfg.read_reg(cap_reg + 1);
        // Try to flip all bits
        cfg.write_config_register(cap_reg + 1, 0, &u32::to_le_bytes(!table_offset));
        // None should be flipped
        assert_eq!(cfg.read_reg(cap_reg + 1), table_offset);

        // PBA offset also
        let pba_offset = cfg.read_reg(cap_reg + 2);
        // Try to flip all bits
        cfg.write_config_register(cap_reg + 2, 0, &u32::to_le_bytes(!pba_offset));
        // None should be flipped
        assert_eq!(cfg.read_reg(cap_reg + 2), pba_offset);
    }

    fn default_pci_config() -> PciConfiguration {
        PciConfiguration::new_type0(
            0x1234,
            0x5678,
            0x1,
            PciClassCode::MultimediaController,
            PciMultimediaSubclass::AudioController as u8,
            0xABCD,
            0x2468,
            None,
        )
    }

    #[test]
    fn class_code() {
        let cfg = default_pci_config();
        let class_reg = cfg.read_reg(2);
        let class_code = (class_reg >> 24) & 0xFF;
        let subclass = (class_reg >> 16) & 0xFF;
        let prog_if = (class_reg >> 8) & 0xFF;
        assert_eq!(class_code, 0x04);
        assert_eq!(subclass, 0x01);
        assert_eq!(prog_if, 0x0);
    }

    #[test]
    #[should_panic]
    fn test_encode_zero_sized_bar() {
        encode_64_bits_bar_size(0);
    }

    #[test]
    #[should_panic]
    fn test_decode_zero_sized_bar() {
        decode_64_bits_bar_size(0, 0);
    }

    #[test]
    fn test_bar_size_encoding() {
        // According to OSDev wiki (https://wiki.osdev.org/PCI#Address_and_size_of_the_BAR):
        //
        // > To determine the amount of address space needed by a PCI device, you must save the
        // > original value of the BAR, write a value of all 1's to the register, then read it back.
        // > The amount of memory can then be determined by masking the information bits, performing
        // > a bitwise NOT ('~' in C), and incrementing the value by 1. The original value of the
        // BAR > should then be restored. The BAR register is naturally aligned and as such you can
        // only > modify the bits that are set. For example, if a device utilizes 16 MB it will
        // have BAR0 > filled with 0xFF000000 (0x1000000 after decoding) and you can only modify
        // the upper > 8-bits.
        //
        // So, we encode a 64 bits size and then store it as a 2 32bit addresses (we use
        // two BARs).
        let (hi, lo) = encode_64_bits_bar_size(0xffff_ffff_ffff_fff0);
        assert_eq!(hi, 0);
        assert_eq!(lo, 0x0000_0010);
        assert_eq!(decode_64_bits_bar_size(hi, lo), 0xffff_ffff_ffff_fff0);
    }

    #[test]
    #[should_panic]
    fn test_bar_size_no_power_of_two() {
        let mut pci_config = default_pci_config();
        pci_config.add_pci_bar(0, 0x1000, 0x1001);
    }

    #[test]
    #[should_panic]
    fn test_bad_bar_index() {
        let mut pci_config = default_pci_config();
        pci_config.add_pci_bar(NUM_BAR_REGS as u8, 0x1000, 0x1000);
    }

    #[test]
    #[should_panic]
    fn test_bad_64bit_bar_index() {
        let mut pci_config = default_pci_config();
        pci_config.add_pci_bar((NUM_BAR_REGS - 1) as u8, 0x1000, 0x1000);
    }

    #[test]
    #[should_panic]
    fn test_bar_size_overflows() {
        let mut pci_config = default_pci_config();
        pci_config.add_pci_bar(0, u64::MAX, 0x2);
    }

    #[test]
    #[should_panic]
    fn test_lower_bar_free_upper_used() {
        let mut pci_config = default_pci_config();
        pci_config.add_pci_bar(1, 0x1000, 0x1000);
        pci_config.add_pci_bar(0, 0x1000, 0x1000);
    }

    #[test]
    #[should_panic]
    fn test_lower_bar_used() {
        let mut pci_config = default_pci_config();
        pci_config.add_pci_bar(0, 0x1000, 0x1000);
        pci_config.add_pci_bar(0, 0x1000, 0x1000);
    }

    #[test]
    #[should_panic]
    fn test_upper_bar_used() {
        let mut pci_config = default_pci_config();
        pci_config.add_pci_bar(0, 0x1000, 0x1000);
        pci_config.add_pci_bar(1, 0x1000, 0x1000);
    }

    #[test]
    fn test_add_pci_bar() {
        let mut pci_config = default_pci_config();

        pci_config.add_pci_bar(0, 0x1_0000_0000, 0x1000);

        assert_eq!(pci_config.get_bar_addr(0), 0x1_0000_0000);
        assert_eq!(pci_config.read_reg(BAR0_REG) & 0xffff_fff0, 0x0);
        assert!(pci_config.bars[0].used);
        assert_eq!(pci_config.read_reg(BAR0_REG + 1), 1);
        assert!(pci_config.bars[0].used);
    }

    #[test]
    fn test_access_invalid_reg() {
        let mut pci_config = default_pci_config();

        // Can't read past the end of the configuration space
        assert_eq!(
            pci_config.read_reg(NUM_CONFIGURATION_REGISTERS as u16),
            0xffff_ffff
        );

        // Read out all of configuration space
        let config_space: Vec<u32> = (0..NUM_CONFIGURATION_REGISTERS as u16)
            .map(|reg_idx| pci_config.read_reg(reg_idx))
            .collect();

        // Various invalid write accesses

        // Past the end of config space
        pci_config.write_config_register(NUM_CONFIGURATION_REGISTERS as u16, 0, &[0x42]);
        pci_config.write_config_register(NUM_CONFIGURATION_REGISTERS as u16, 0, &[0x42, 0x42]);
        pci_config.write_config_register(
            NUM_CONFIGURATION_REGISTERS as u16,
            0,
            &[0x42, 0x42, 0x42, 0x42],
        );

        // Past register boundaries
        pci_config.write_config_register(
            NUM_CONFIGURATION_REGISTERS as u16,
            1,
            &[0x42, 0x42, 0x42, 0x42],
        );
        pci_config.write_config_register(
            NUM_CONFIGURATION_REGISTERS as u16,
            2,
            &[0x42, 0x42, 0x42],
        );
        pci_config.write_config_register(NUM_CONFIGURATION_REGISTERS as u16, 3, &[0x42, 0x42]);
        pci_config.write_config_register(NUM_CONFIGURATION_REGISTERS as u16, 4, &[0x42]);
        pci_config.write_config_register(NUM_CONFIGURATION_REGISTERS as u16, 5, &[]);

        for (reg_idx, reg) in config_space.iter().enumerate() {
            assert_eq!(*reg, pci_config.read_reg(reg_idx as u16));
        }
    }

    #[test]
    fn test_detect_bar_reprogramming() {
        let mut pci_config = default_pci_config();

        // Trying to reprogram with something less than 4 bytes (length of the address) should fail
        assert!(
            pci_config
                .detect_bar_reprogramming(BAR0_REG, &[0x13])
                .is_none()
        );
        assert!(
            pci_config
                .detect_bar_reprogramming(BAR0_REG, &[0x13, 0x12])
                .is_none()
        );
        assert!(
            pci_config
                .detect_bar_reprogramming(BAR0_REG, &[0x13, 0x12])
                .is_none()
        );
        assert!(
            pci_config
                .detect_bar_reprogramming(BAR0_REG, &[0x13, 0x12, 0x16])
                .is_none()
        );

        // Writing all 1s is a special case where we're actually asking for the size of the BAR
        assert!(
            pci_config
                .detect_bar_reprogramming(BAR0_REG, &u32::to_le_bytes(0xffff_ffff))
                .is_none()
        );

        // Trying to reprogram a BAR that hasn't be initialized does nothing
        for reg_idx in BAR0_REG..BAR0_REG + NUM_BAR_REGS as u16 {
            assert!(
                pci_config
                    .detect_bar_reprogramming(reg_idx, &u32::to_le_bytes(0x1312_4243))
                    .is_none()
            );
        }

        // Reprogramming of a 64bit BAR
        pci_config.add_pci_bar(0, 0x13_1200_0000, 0x8000);

        // First we write the lower 32 bits and this shouldn't cause any reprogramming
        assert!(
            pci_config
                .detect_bar_reprogramming(BAR0_REG, &u32::to_le_bytes(0x4200_0000))
                .is_none()
        );
        pci_config.write_config_register(BAR0_REG, 0, &u32::to_le_bytes(0x4200_0000));

        // Writing the upper 32 bits should trigger the reprogramming
        assert_eq!(
            pci_config.detect_bar_reprogramming(BAR0_REG + 1, &u32::to_le_bytes(0x84)),
            Some(BarReprogrammingParams {
                old_base: 0x13_1200_0000,
                new_base: 0x84_4200_0000,
                len: 0x8000,
            })
        );
        pci_config.write_config_register(BAR0_REG + 1, 0, &u32::to_le_bytes(0x84));

        // Trying to reprogram the upper bits directly (without first touching the lower bits)
        // should trigger a reprogramming
        assert_eq!(
            pci_config.detect_bar_reprogramming(BAR0_REG + 1, &u32::to_le_bytes(0x1312)),
            Some(BarReprogrammingParams {
                old_base: 0x84_4200_0000,
                new_base: 0x1312_4200_0000,
                len: 0x8000,
            })
        );
        pci_config.write_config_register(BAR0_REG + 1, 0, &u32::to_le_bytes(0x1312));

        // Attempting to reprogram the BAR with the same address should not have any effect
        assert!(
            pci_config
                .detect_bar_reprogramming(BAR0_REG, &u32::to_le_bytes(0x4200_0000))
                .is_none()
        );
        assert!(
            pci_config
                .detect_bar_reprogramming(BAR0_REG + 1, &u32::to_le_bytes(0x1312))
                .is_none()
        );
    }

    #[test]
    fn test_rom_bar() {
        let mut pci_config = default_pci_config();

        // ROM BAR address should always be 0 and writes to it shouldn't do anything
        assert_eq!(pci_config.read_reg(ROM_BAR_REG), 0);
        pci_config.write_reg(ROM_BAR_REG, 0x42);
        assert_eq!(pci_config.read_reg(ROM_BAR_REG), 0);

        // Reading the size of the BAR should always return 0 as well
        pci_config.write_reg(ROM_BAR_REG, 0xffff_ffff);
        assert_eq!(pci_config.read_reg(ROM_BAR_REG), 0);
    }
}
