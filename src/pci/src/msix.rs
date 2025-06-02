// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//

use std::sync::Arc;
use std::{io, result};

use byteorder::{ByteOrder, LittleEndian};
use serde::{Deserialize, Serialize};
use vm_device::interrupt::{
    InterruptIndex, InterruptSourceConfig, InterruptSourceGroup, MsiIrqSourceConfig,
};
use vm_memory::ByteValued;

use crate::{PciCapability, PciCapabilityId};

const MAX_MSIX_VECTORS_PER_DEVICE: u16 = 2048;
const MSIX_TABLE_ENTRIES_MODULO: u64 = 16;
const MSIX_PBA_ENTRIES_MODULO: u64 = 8;
const BITS_PER_PBA_ENTRY: usize = 64;
const FUNCTION_MASK_BIT: u8 = 14;
const MSIX_ENABLE_BIT: u8 = 15;
const FUNCTION_MASK_MASK: u16 = (1 << FUNCTION_MASK_BIT) as u16;
const MSIX_ENABLE_MASK: u16 = (1 << MSIX_ENABLE_BIT) as u16;
pub const MSIX_TABLE_ENTRY_SIZE: usize = 16;
pub const MSIX_CONFIG_ID: &str = "msix_config";

#[derive(Debug)]
pub enum Error {
    /// Failed enabling the interrupt route.
    EnableInterruptRoute(io::Error),
    /// Failed updating the interrupt route.
    UpdateInterruptRoute(io::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct MsixTableEntry {
    pub msg_addr_lo: u32,
    pub msg_addr_hi: u32,
    pub msg_data: u32,
    pub vector_ctl: u32,
}

impl MsixTableEntry {
    pub fn masked(&self) -> bool {
        self.vector_ctl & 0x1 == 0x1
    }
}

impl Default for MsixTableEntry {
    fn default() -> Self {
        MsixTableEntry {
            msg_addr_lo: 0,
            msg_addr_hi: 0,
            msg_data: 0,
            vector_ctl: 0x1,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct MsixConfigState {
    table_entries: Vec<MsixTableEntry>,
    pba_entries: Vec<u64>,
    masked: bool,
    enabled: bool,
}

pub struct MsixConfig {
    pub table_entries: Vec<MsixTableEntry>,
    pub pba_entries: Vec<u64>,
    pub devid: u32,
    interrupt_source_group: Arc<dyn InterruptSourceGroup>,
    masked: bool,
    enabled: bool,
}

impl std::fmt::Debug for MsixConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MsixConfig")
            .field("table_entries", &self.table_entries)
            .field("pba_entries", &self.pba_entries)
            .field("devid", &self.devid)
            .field("masked", &self.masked)
            .field("enabled", &self.enabled)
            .finish()
    }
}

impl MsixConfig {
    pub fn new(
        msix_vectors: u16,
        interrupt_source_group: Arc<dyn InterruptSourceGroup>,
        devid: u32,
        state: Option<MsixConfigState>,
    ) -> result::Result<Self, Error> {
        assert!(msix_vectors <= MAX_MSIX_VECTORS_PER_DEVICE);

        let (table_entries, pba_entries, masked, enabled) = if let Some(state) = state {
            if state.enabled && !state.masked {
                for (idx, table_entry) in state.table_entries.iter().enumerate() {
                    if table_entry.masked() {
                        continue;
                    }

                    let config = MsiIrqSourceConfig {
                        high_addr: table_entry.msg_addr_hi,
                        low_addr: table_entry.msg_addr_lo,
                        data: table_entry.msg_data,
                        devid,
                    };

                    interrupt_source_group
                        .update(
                            idx as InterruptIndex,
                            InterruptSourceConfig::MsiIrq(config),
                            state.masked,
                            true,
                        )
                        .map_err(Error::UpdateInterruptRoute)?;

                    interrupt_source_group
                        .enable()
                        .map_err(Error::EnableInterruptRoute)?;
                }
            }

            (
                state.table_entries,
                state.pba_entries,
                state.masked,
                state.enabled,
            )
        } else {
            let mut table_entries: Vec<MsixTableEntry> = Vec::new();
            table_entries.resize_with(msix_vectors as usize, Default::default);
            let mut pba_entries: Vec<u64> = Vec::new();
            let num_pba_entries: usize = ((msix_vectors as usize) / BITS_PER_PBA_ENTRY) + 1;
            pba_entries.resize_with(num_pba_entries, Default::default);

            (table_entries, pba_entries, true, false)
        };

        Ok(MsixConfig {
            table_entries,
            pba_entries,
            devid,
            interrupt_source_group,
            masked,
            enabled,
        })
    }

    pub fn state(&self) -> MsixConfigState {
        MsixConfigState {
            table_entries: self.table_entries.clone(),
            pba_entries: self.pba_entries.clone(),
            masked: self.masked,
            enabled: self.enabled,
        }
    }

    pub fn masked(&self) -> bool {
        self.masked
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_msg_ctl(&mut self, reg: u16) {
        let old_masked = self.masked;
        let old_enabled = self.enabled;

        self.masked = ((reg >> FUNCTION_MASK_BIT) & 1u16) == 1u16;
        self.enabled = ((reg >> MSIX_ENABLE_BIT) & 1u16) == 1u16;

        // Update interrupt routing
        if old_masked != self.masked || old_enabled != self.enabled {
            if self.enabled && !self.masked {
                debug!("MSI-X enabled for device 0x{:x}", self.devid);
                for (idx, table_entry) in self.table_entries.iter().enumerate() {
                    let config = MsiIrqSourceConfig {
                        high_addr: table_entry.msg_addr_hi,
                        low_addr: table_entry.msg_addr_lo,
                        data: table_entry.msg_data,
                        devid: self.devid,
                    };

                    if let Err(e) = self.interrupt_source_group.update(
                        idx as InterruptIndex,
                        InterruptSourceConfig::MsiIrq(config),
                        table_entry.masked(),
                        true,
                    ) {
                        error!("Failed updating vector: {:?}", e);
                    }
                }
            } else if old_enabled || !old_masked {
                debug!("MSI-X disabled for device 0x{:x}", self.devid);
                if let Err(e) = self.interrupt_source_group.disable() {
                    error!("Failed disabling irq_fd: {:?}", e);
                }
            }
        }

        // If the Function Mask bit was set, and has just been cleared, it's
        // important to go through the entire PBA to check if there was any
        // pending MSI-X message to inject, given that the vector is not
        // masked.
        if old_masked && !self.masked {
            for (index, entry) in self.table_entries.clone().iter().enumerate() {
                if !entry.masked() && self.get_pba_bit(index as u16) == 1 {
                    self.inject_msix_and_clear_pba(index);
                }
            }
        }
    }

    pub fn read_table(&self, offset: u64, data: &mut [u8]) {
        assert!((data.len() == 4 || data.len() == 8));

        let index: usize = (offset / MSIX_TABLE_ENTRIES_MODULO) as usize;
        let modulo_offset = offset % MSIX_TABLE_ENTRIES_MODULO;

        if index >= self.table_entries.len() {
            debug!("Invalid MSI-X table entry index {index}");
            data.copy_from_slice(&[0xff; 8][..data.len()]);
            return;
        }

        match data.len() {
            4 => {
                let value = match modulo_offset {
                    0x0 => self.table_entries[index].msg_addr_lo,
                    0x4 => self.table_entries[index].msg_addr_hi,
                    0x8 => self.table_entries[index].msg_data,
                    0xc => self.table_entries[index].vector_ctl,
                    _ => {
                        error!("invalid offset");
                        0
                    }
                };

                debug!("MSI_R TABLE offset 0x{:x} data 0x{:x}", offset, value);
                LittleEndian::write_u32(data, value);
            }
            8 => {
                let value = match modulo_offset {
                    0x0 => {
                        (u64::from(self.table_entries[index].msg_addr_hi) << 32)
                            | u64::from(self.table_entries[index].msg_addr_lo)
                    }
                    0x8 => {
                        (u64::from(self.table_entries[index].vector_ctl) << 32)
                            | u64::from(self.table_entries[index].msg_data)
                    }
                    _ => {
                        error!("invalid offset");
                        0
                    }
                };

                debug!("MSI_R TABLE offset 0x{:x} data 0x{:x}", offset, value);
                LittleEndian::write_u64(data, value);
            }
            _ => {
                error!("invalid data length");
            }
        }
    }

    pub fn write_table(&mut self, offset: u64, data: &[u8]) {
        assert!((data.len() == 4 || data.len() == 8));

        let index: usize = (offset / MSIX_TABLE_ENTRIES_MODULO) as usize;
        let modulo_offset = offset % MSIX_TABLE_ENTRIES_MODULO;

        if index >= self.table_entries.len() {
            debug!("Invalid MSI-X table entry index {index}");
            return;
        }

        // Store the value of the entry before modification
        let old_entry = self.table_entries[index].clone();

        match data.len() {
            4 => {
                let value = LittleEndian::read_u32(data);
                match modulo_offset {
                    0x0 => self.table_entries[index].msg_addr_lo = value,
                    0x4 => self.table_entries[index].msg_addr_hi = value,
                    0x8 => self.table_entries[index].msg_data = value,
                    0xc => {
                        self.table_entries[index].vector_ctl = value;
                    }
                    _ => error!("invalid offset"),
                };

                debug!("MSI_W TABLE offset 0x{:x} data 0x{:x}", offset, value);
            }
            8 => {
                let value = LittleEndian::read_u64(data);
                match modulo_offset {
                    0x0 => {
                        self.table_entries[index].msg_addr_lo = (value & 0xffff_ffffu64) as u32;
                        self.table_entries[index].msg_addr_hi = (value >> 32) as u32;
                    }
                    0x8 => {
                        self.table_entries[index].msg_data = (value & 0xffff_ffffu64) as u32;
                        self.table_entries[index].vector_ctl = (value >> 32) as u32;
                    }
                    _ => error!("invalid offset"),
                };

                debug!("MSI_W TABLE offset 0x{:x} data 0x{:x}", offset, value);
            }
            _ => error!("invalid data length"),
        };

        let table_entry = &self.table_entries[index];

        // Optimisation to avoid excessive updates
        if &old_entry == table_entry {
            return;
        }

        // Update interrupt routes
        // Optimisation: only update routes if the entry is not masked;
        // this is safe because if the entry is masked (starts masked as per spec)
        // in the table then it won't be triggered. (See: #4273)
        if self.enabled && !self.masked && !table_entry.masked() {
            let config = MsiIrqSourceConfig {
                high_addr: table_entry.msg_addr_hi,
                low_addr: table_entry.msg_addr_lo,
                data: table_entry.msg_data,
                devid: self.devid,
            };

            if let Err(e) = self.interrupt_source_group.update(
                index as InterruptIndex,
                InterruptSourceConfig::MsiIrq(config),
                table_entry.masked(),
                true,
            ) {
                error!("Failed updating vector: {:?}", e);
            }
        }

        // After the MSI-X table entry has been updated, it is necessary to
        // check if the vector control masking bit has changed. In case the
        // bit has been flipped from 1 to 0, we need to inject a MSI message
        // if the corresponding pending bit from the PBA is set. Once the MSI
        // has been injected, the pending bit in the PBA needs to be cleared.
        // All of this is valid only if MSI-X has not been masked for the whole
        // device.

        // Check if bit has been flipped
        if !self.masked()
            && self.enabled()
            && old_entry.masked()
            && !table_entry.masked()
            && self.get_pba_bit(index as u16) == 1
        {
            self.inject_msix_and_clear_pba(index);
        }
    }

    pub fn read_pba(&mut self, offset: u64, data: &mut [u8]) {
        assert!((data.len() == 4 || data.len() == 8));

        let index: usize = (offset / MSIX_PBA_ENTRIES_MODULO) as usize;
        let modulo_offset = offset % MSIX_PBA_ENTRIES_MODULO;

        if index >= self.pba_entries.len() {
            debug!("Invalid MSI-X PBA entry index {index}");
            data.copy_from_slice(&[0xff; 8][..data.len()]);
            return;
        }

        match data.len() {
            4 => {
                let value: u32 = match modulo_offset {
                    0x0 => (self.pba_entries[index] & 0xffff_ffffu64) as u32,
                    0x4 => (self.pba_entries[index] >> 32) as u32,
                    _ => {
                        error!("invalid offset");
                        0
                    }
                };

                debug!("MSI_R PBA offset 0x{:x} data 0x{:x}", offset, value);
                LittleEndian::write_u32(data, value);
            }
            8 => {
                let value: u64 = match modulo_offset {
                    0x0 => self.pba_entries[index],
                    _ => {
                        error!("invalid offset");
                        0
                    }
                };

                debug!("MSI_R PBA offset 0x{:x} data 0x{:x}", offset, value);
                LittleEndian::write_u64(data, value);
            }
            _ => {
                error!("invalid data length");
            }
        }
    }

    pub fn write_pba(&mut self, _offset: u64, _data: &[u8]) {
        error!("Pending Bit Array is read only");
    }

    pub fn set_pba_bit(&mut self, vector: u16, reset: bool) {
        assert!(vector < MAX_MSIX_VECTORS_PER_DEVICE);

        let index: usize = (vector as usize) / BITS_PER_PBA_ENTRY;
        let shift: usize = (vector as usize) % BITS_PER_PBA_ENTRY;
        let mut mask: u64 = (1 << shift) as u64;

        if reset {
            mask = !mask;
            self.pba_entries[index] &= mask;
        } else {
            self.pba_entries[index] |= mask;
        }
    }

    fn get_pba_bit(&self, vector: u16) -> u8 {
        assert!(vector < MAX_MSIX_VECTORS_PER_DEVICE);

        let index: usize = (vector as usize) / BITS_PER_PBA_ENTRY;
        let shift: usize = (vector as usize) % BITS_PER_PBA_ENTRY;

        ((self.pba_entries[index] >> shift) & 0x0000_0001u64) as u8
    }

    fn inject_msix_and_clear_pba(&mut self, vector: usize) {
        // Inject the MSI message
        match self
            .interrupt_source_group
            .trigger(vector as InterruptIndex)
        {
            Ok(_) => debug!("MSI-X injected on vector control flip"),
            Err(e) => error!("failed to inject MSI-X: {}", e),
        }

        // Clear the bit from PBA
        self.set_pba_bit(vector as u16, true);
    }
}

#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Clone, Copy, Default, Serialize, Deserialize)]
pub struct MsixCap {
    // Message Control Register
    //   10-0:  MSI-X Table size
    //   13-11: Reserved
    //   14:    Mask. Mask all MSI-X when set.
    //   15:    Enable. Enable all MSI-X when set.
    pub msg_ctl: u16,
    // Table. Contains the offset and the BAR indicator (BIR)
    //   2-0:  Table BAR indicator (BIR). Can be 0 to 5.
    //   31-3: Table offset in the BAR pointed by the BIR.
    pub table: u32,
    // Pending Bit Array. Contains the offset and the BAR indicator (BIR)
    //   2-0:  PBA BAR indicator (BIR). Can be 0 to 5.
    //   31-3: PBA offset in the BAR pointed by the BIR.
    pub pba: u32,
}

// SAFETY: All members are simple numbers and any value is valid.
unsafe impl ByteValued for MsixCap {}

impl PciCapability for MsixCap {
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }

    fn id(&self) -> PciCapabilityId {
        PciCapabilityId::MsiX
    }
}

impl MsixCap {
    pub fn new(
        table_pci_bar: u8,
        table_size: u16,
        table_off: u32,
        pba_pci_bar: u8,
        pba_off: u32,
    ) -> Self {
        assert!(table_size < MAX_MSIX_VECTORS_PER_DEVICE);

        // Set the table size and enable MSI-X.
        let msg_ctl: u16 = 0x8000u16 + table_size - 1;

        MsixCap {
            msg_ctl,
            table: (table_off & 0xffff_fff8u32) | u32::from(table_pci_bar & 0x7u8),
            pba: (pba_off & 0xffff_fff8u32) | u32::from(pba_pci_bar & 0x7u8),
        }
    }

    pub fn set_msg_ctl(&mut self, data: u16) {
        self.msg_ctl = (self.msg_ctl & !(FUNCTION_MASK_MASK | MSIX_ENABLE_MASK))
            | (data & (FUNCTION_MASK_MASK | MSIX_ENABLE_MASK));
    }

    pub fn masked(&self) -> bool {
        (self.msg_ctl >> FUNCTION_MASK_BIT) & 0x1 == 0x1
    }

    pub fn enabled(&self) -> bool {
        (self.msg_ctl >> MSIX_ENABLE_BIT) & 0x1 == 0x1
    }

    pub fn table_offset(&self) -> u32 {
        self.table & 0xffff_fff8
    }

    pub fn pba_offset(&self) -> u32 {
        self.pba & 0xffff_fff8
    }

    pub fn table_set_offset(&mut self, addr: u32) {
        self.table &= 0x7;
        self.table += addr;
    }

    pub fn pba_set_offset(&mut self, addr: u32) {
        self.pba &= 0x7;
        self.pba += addr;
    }

    pub fn table_bir(&self) -> u32 {
        self.table & 0x7
    }

    pub fn pba_bir(&self) -> u32 {
        self.pba & 0x7
    }

    pub fn table_size(&self) -> u16 {
        (self.msg_ctl & 0x7ff) + 1
    }

    pub fn table_range(&self) -> (u64, u64) {
        // The table takes 16 bytes per entry.
        let size = self.table_size() as u64 * 16;
        (self.table_offset() as u64, size)
    }

    pub fn pba_range(&self) -> (u64, u64) {
        // The table takes 1 bit per entry modulo 8 bytes.
        let size = ((self.table_size() as u64 / 64) + 1) * 8;
        (self.pba_offset() as u64, size)
    }
}
