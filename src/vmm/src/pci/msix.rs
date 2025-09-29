// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//

use std::sync::Arc;

use byteorder::{ByteOrder, LittleEndian};
use pci::PciCapabilityId;
use serde::{Deserialize, Serialize};
use vm_memory::ByteValued;

use crate::Vm;
use crate::logger::{debug, error, warn};
use crate::pci::configuration::PciCapability;
use crate::snapshot::Persist;
use crate::vstate::interrupts::{InterruptError, MsixVectorConfig, MsixVectorGroup};

const MAX_MSIX_VECTORS_PER_DEVICE: u16 = 2048;
const MSIX_TABLE_ENTRIES_MODULO: u64 = 16;
const MSIX_PBA_ENTRIES_MODULO: u64 = 8;
const BITS_PER_PBA_ENTRY: usize = 64;
const FUNCTION_MASK_BIT: u8 = 14;
const MSIX_ENABLE_BIT: u8 = 15;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
/// MSI-X table entries
pub struct MsixTableEntry {
    /// Lower 32 bits of the vector address
    pub msg_addr_lo: u32,
    /// Upper 32 bits of the vector address
    pub msg_addr_hi: u32,
    /// Vector data
    pub msg_data: u32,
    /// Enable/Disable and (un)masking control
    pub vector_ctl: u32,
}

impl MsixTableEntry {
    /// Returns `true` if the vector is masked
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

#[derive(Debug, Clone, Serialize, Deserialize)]
/// State for (de)serializing MSI-X configuration
pub struct MsixConfigState {
    table_entries: Vec<MsixTableEntry>,
    pba_entries: Vec<u64>,
    masked: bool,
    enabled: bool,
    vectors: Vec<u32>,
}

/// MSI-X configuration
pub struct MsixConfig {
    /// Vector table entries
    pub table_entries: Vec<MsixTableEntry>,
    /// Pending bit array
    pub pba_entries: Vec<u64>,
    /// Id of the device using this set of vectors
    pub devid: u32,
    /// Interrupts vectors used
    pub vectors: Arc<MsixVectorGroup>,
    /// Whether vectors are masked
    pub masked: bool,
    /// Whether vectors are enabled
    pub enabled: bool,
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
    /// Create a new MSI-X configuration
    pub fn new(vectors: Arc<MsixVectorGroup>, devid: u32) -> Self {
        assert!(vectors.num_vectors() <= MAX_MSIX_VECTORS_PER_DEVICE);

        let mut table_entries: Vec<MsixTableEntry> = Vec::new();
        table_entries.resize_with(vectors.num_vectors() as usize, Default::default);
        let mut pba_entries: Vec<u64> = Vec::new();
        let num_pba_entries: usize = (vectors.num_vectors() as usize).div_ceil(BITS_PER_PBA_ENTRY);
        pba_entries.resize_with(num_pba_entries, Default::default);

        MsixConfig {
            table_entries,
            pba_entries,
            devid,
            vectors,
            masked: true,
            enabled: false,
        }
    }

    /// Create an MSI-X configuration from snapshot state
    pub fn from_state(
        state: MsixConfigState,
        vm: Arc<Vm>,
        devid: u32,
    ) -> Result<Self, InterruptError> {
        let vectors = Arc::new(MsixVectorGroup::restore(vm, &state.vectors)?);
        if state.enabled && !state.masked {
            for (idx, table_entry) in state.table_entries.iter().enumerate() {
                if table_entry.masked() {
                    continue;
                }

                let config = MsixVectorConfig {
                    high_addr: table_entry.msg_addr_hi,
                    low_addr: table_entry.msg_addr_lo,
                    data: table_entry.msg_data,
                    devid,
                };

                vectors.update(idx, config, state.masked, true)?;
                vectors.enable()?;
            }
        }

        Ok(MsixConfig {
            table_entries: state.table_entries,
            pba_entries: state.pba_entries,
            devid,
            vectors,
            masked: state.masked,
            enabled: state.enabled,
        })
    }

    /// Create the state object for serializing MSI-X vectors
    pub fn state(&self) -> MsixConfigState {
        MsixConfigState {
            table_entries: self.table_entries.clone(),
            pba_entries: self.pba_entries.clone(),
            masked: self.masked,
            enabled: self.enabled,
            vectors: self.vectors.save(),
        }
    }

    /// Set the MSI-X control message (enable/disable, (un)mask)
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
                    let config = MsixVectorConfig {
                        high_addr: table_entry.msg_addr_hi,
                        low_addr: table_entry.msg_addr_lo,
                        data: table_entry.msg_data,
                        devid: self.devid,
                    };

                    if let Err(e) = self.vectors.update(idx, config, table_entry.masked(), true) {
                        error!("Failed updating vector: {:?}", e);
                    }
                }
            } else if old_enabled || !old_masked {
                debug!("MSI-X disabled for device 0x{:x}", self.devid);
                if let Err(e) = self.vectors.disable() {
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
                if !entry.masked() && self.get_pba_bit(index.try_into().unwrap()) == 1 {
                    self.inject_msix_and_clear_pba(index);
                }
            }
        }
    }

    /// Read an MSI-X table entry
    pub fn read_table(&self, offset: u64, data: &mut [u8]) {
        assert!(data.len() <= 8);

        let index: usize = (offset / MSIX_TABLE_ENTRIES_MODULO) as usize;
        let modulo_offset = offset % MSIX_TABLE_ENTRIES_MODULO;

        if index >= self.table_entries.len() {
            warn!("Invalid MSI-X table entry index {index}");
            data.fill(0xff);
            return;
        }

        match data.len() {
            4 => {
                let value = match modulo_offset {
                    0x0 => self.table_entries[index].msg_addr_lo,
                    0x4 => self.table_entries[index].msg_addr_hi,
                    0x8 => self.table_entries[index].msg_data,
                    0xc => self.table_entries[index].vector_ctl,
                    off => {
                        warn!("msi-x: invalid offset in table entry read: {off}");
                        0xffff_ffff
                    }
                };

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
                    off => {
                        warn!("msi-x: invalid offset in table entry read: {off}");
                        0xffff_ffff_ffff_ffff
                    }
                };

                LittleEndian::write_u64(data, value);
            }
            len => {
                warn!("msi-x: invalid length in table entry read: {len}");
                data.fill(0xff);
            }
        }
    }

    /// Write an MSI-X table entry
    pub fn write_table(&mut self, offset: u64, data: &[u8]) {
        assert!(data.len() <= 8);

        let index: usize = (offset / MSIX_TABLE_ENTRIES_MODULO) as usize;
        let modulo_offset = offset % MSIX_TABLE_ENTRIES_MODULO;

        if index >= self.table_entries.len() {
            warn!("msi-x: invalid table entry index {index}");
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
                    off => warn!("msi-x: invalid offset in table entry write: {off}"),
                };
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
                    off => warn!("msi-x: invalid offset in table entry write: {off}"),
                };
            }
            len => warn!("msi-x: invalid length in table entry write: {len}"),
        };

        let table_entry = &self.table_entries[index];

        // Optimisation to avoid excessive updates
        if &old_entry == table_entry {
            return;
        }

        // Update interrupt routes
        // Optimisation: only update routes if the entry is not masked;
        // this is safe because if the entry is masked (starts masked as per spec)
        // in the table then it won't be triggered.
        if self.enabled && !self.masked && !table_entry.masked() {
            let config = MsixVectorConfig {
                high_addr: table_entry.msg_addr_hi,
                low_addr: table_entry.msg_addr_lo,
                data: table_entry.msg_data,
                devid: self.devid,
            };

            if let Err(e) = self
                .vectors
                .update(index, config, table_entry.masked(), true)
            {
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
        if !self.masked
            && self.enabled
            && old_entry.masked()
            && !table_entry.masked()
            && self.get_pba_bit(index.try_into().unwrap()) == 1
        {
            self.inject_msix_and_clear_pba(index);
        }
    }

    /// Read a pending bit array entry
    pub fn read_pba(&self, offset: u64, data: &mut [u8]) {
        let index: usize = (offset / MSIX_PBA_ENTRIES_MODULO) as usize;
        let modulo_offset = offset % MSIX_PBA_ENTRIES_MODULO;

        if index >= self.pba_entries.len() {
            warn!("msi-x: invalid PBA entry index {index}");
            data.fill(0xff);
            return;
        }

        match data.len() {
            4 => {
                let value: u32 = match modulo_offset {
                    0x0 => (self.pba_entries[index] & 0xffff_ffffu64) as u32,
                    0x4 => (self.pba_entries[index] >> 32) as u32,
                    off => {
                        warn!("msi-x: invalid offset in pba entry read: {off}");
                        0xffff_ffff
                    }
                };

                LittleEndian::write_u32(data, value);
            }
            8 => {
                let value: u64 = match modulo_offset {
                    0x0 => self.pba_entries[index],
                    off => {
                        warn!("msi-x: invalid offset in pba entry read: {off}");
                        0xffff_ffff_ffff_ffff
                    }
                };

                LittleEndian::write_u64(data, value);
            }
            len => {
                warn!("msi-x: invalid length in table entry read: {len}");
                data.fill(0xff);
            }
        }
    }

    /// Write a pending bit array entry
    pub fn write_pba(&mut self, _offset: u64, _data: &[u8]) {
        error!("Pending Bit Array is read only");
    }

    /// Set PBA bit for a vector
    pub fn set_pba_bit(&mut self, vector: u16, reset: bool) {
        assert!(vector < MAX_MSIX_VECTORS_PER_DEVICE);

        if (vector as usize) >= self.table_entries.len() {
            return;
        }

        let index: usize = (vector as usize) / BITS_PER_PBA_ENTRY;
        let shift: usize = (vector as usize) % BITS_PER_PBA_ENTRY;
        let mut mask: u64 = 1u64 << shift;

        if reset {
            mask = !mask;
            self.pba_entries[index] &= mask;
        } else {
            self.pba_entries[index] |= mask;
        }
    }

    /// Get the PBA bit for a vector
    fn get_pba_bit(&self, vector: u16) -> u8 {
        assert!(vector < MAX_MSIX_VECTORS_PER_DEVICE);

        if (vector as usize) >= self.table_entries.len() {
            return 0xff;
        }

        let index: usize = (vector as usize) / BITS_PER_PBA_ENTRY;
        let shift: usize = (vector as usize) % BITS_PER_PBA_ENTRY;

        ((self.pba_entries[index] >> shift) & 0x0000_0001u64) as u8
    }

    /// Inject an MSI-X interrupt and clear the PBA bit for a vector
    fn inject_msix_and_clear_pba(&mut self, vector: usize) {
        // Inject the MSI message
        match self.vectors.trigger(vector) {
            Ok(_) => debug!("MSI-X injected on vector control flip"),
            Err(e) => error!("failed to inject MSI-X: {}", e),
        }

        // Clear the bit from PBA
        self.set_pba_bit(vector.try_into().unwrap(), true);
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
/// MSI-X PCI capability
pub struct MsixCap {
    /// Message Control Register
    ///   10-0:  MSI-X Table size
    ///   13-11: Reserved
    ///   14:    Mask. Mask all MSI-X when set.
    ///   15:    Enable. Enable all MSI-X when set.
    pub msg_ctl: u16,
    /// Table. Contains the offset and the BAR indicator (BIR)
    ///   2-0:  Table BAR indicator (BIR). Can be 0 to 5.
    ///   31-3: Table offset in the BAR pointed by the BIR.
    pub table: u32,
    /// Pending Bit Array. Contains the offset and the BAR indicator (BIR)
    ///   2-0:  PBA BAR indicator (BIR). Can be 0 to 5.
    ///   31-3: PBA offset in the BAR pointed by the BIR.
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
    /// Create a new MSI-X capability object
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::tests::default_vmm;
    use crate::logger::{IncMetric, METRICS};
    use crate::{Vm, check_metric_after_block};

    fn msix_vector_group(nr_vectors: u16) -> Arc<MsixVectorGroup> {
        let vmm = default_vmm();
        Arc::new(Vm::create_msix_group(vmm.vm.clone(), nr_vectors).unwrap())
    }

    #[test]
    #[should_panic]
    fn test_too_many_vectors() {
        MsixConfig::new(msix_vector_group(2049), 0x42);
    }

    #[test]
    fn test_new_msix_config() {
        let config = MsixConfig::new(msix_vector_group(2), 0x42);
        assert_eq!(config.devid, 0x42);
        assert!(config.masked);
        assert!(!config.enabled);
        assert_eq!(config.table_entries.len(), 2);
        assert_eq!(config.pba_entries.len(), 1);
    }

    #[test]
    fn test_enable_msix_vectors() {
        let mut config = MsixConfig::new(msix_vector_group(2), 0x42);

        assert!(!config.enabled);
        assert!(config.masked);

        // Bit 15 marks whether MSI-X is enabled
        // Bit 14 marks whether vectors are masked
        config.set_msg_ctl(0x8000);
        assert!(config.enabled);
        assert!(!config.masked);

        config.set_msg_ctl(0x4000);
        assert!(!config.enabled);
        assert!(config.masked);

        config.set_msg_ctl(0xC000);
        assert!(config.enabled);
        assert!(config.masked);

        config.set_msg_ctl(0x0);
        assert!(!config.enabled);
        assert!(!config.masked);
    }

    #[test]
    #[should_panic]
    fn test_table_access_read_too_big() {
        let config = MsixConfig::new(msix_vector_group(2), 0x42);
        let mut buffer = [0u8; 16];

        config.read_table(0, &mut buffer);
    }

    #[test]
    fn test_read_table_past_end() {
        let config = MsixConfig::new(msix_vector_group(2), 0x42);
        let mut buffer = [0u8; 8];

        // We have 2 vectors (16 bytes each), so we should be able to read up to 32 bytes.
        // Past that the device should respond with all 1s
        config.read_table(32, &mut buffer);
        assert_eq!(buffer, [0xff; 8]);
    }

    #[test]
    fn test_read_table_bad_length() {
        let config = MsixConfig::new(msix_vector_group(2), 0x42);
        let mut buffer = [0u8; 8];

        // We can either read 4 or 8 bytes
        config.read_table(0, &mut buffer[..0]);
        assert_eq!(buffer, [0x0; 8]);
        config.read_table(0, &mut buffer[..1]);
        assert_eq!(buffer[..1], [0xff; 1]);
        config.read_table(0, &mut buffer[..2]);
        assert_eq!(buffer[..2], [0xff; 2]);
        config.read_table(0, &mut buffer[..3]);
        assert_eq!(buffer[..3], [0xff; 3]);
        config.read_table(0, &mut buffer[..5]);
        assert_eq!(buffer[..5], [0xff; 5]);
        config.read_table(0, &mut buffer[..6]);
        assert_eq!(buffer[..6], [0xff; 6]);
        config.read_table(0, &mut buffer[..7]);
        assert_eq!(buffer[..7], [0xff; 7]);
        config.read_table(0, &mut buffer[..4]);
        assert_eq!(buffer, u64::to_le_bytes(0x00ff_ffff_0000_0000));
        config.read_table(0, &mut buffer);
        assert_eq!(buffer, u64::to_le_bytes(0));
    }

    #[test]
    fn test_access_table() {
        let mut config = MsixConfig::new(msix_vector_group(2), 0x42);
        // enabled and not masked
        check_metric_after_block!(
            METRICS.interrupts.config_updates,
            2,
            config.set_msg_ctl(0x8000)
        );
        let mut buffer = [0u8; 8];

        // Write first vector's address with a single 8-byte write
        // It's still masked so shouldn't be updated
        check_metric_after_block!(
            METRICS.interrupts.config_updates,
            0,
            config.write_table(0, &u64::to_le_bytes(0x0000_1312_0000_1110))
        );

        // Same for control and message data
        // Now, we enabled it, so we should see an update
        check_metric_after_block!(
            METRICS.interrupts.config_updates,
            1,
            config.write_table(8, &u64::to_le_bytes(0x0_0000_0020))
        );

        // Write second vector's fields with 4-byte writes
        // low 32 bits of the address (still masked)
        check_metric_after_block!(
            METRICS.interrupts.config_updates,
            0,
            config.write_table(16, &u32::to_le_bytes(0x4241))
        );
        // high 32 bits of the address (still masked)
        check_metric_after_block!(
            METRICS.interrupts.config_updates,
            0,
            config.write_table(20, &u32::to_le_bytes(0x4443))
        );
        // message data (still masked)
        check_metric_after_block!(
            METRICS.interrupts.config_updates,
            0,
            config.write_table(24, &u32::to_le_bytes(0x21))
        );
        // vector control (now unmasked)
        check_metric_after_block!(
            METRICS.interrupts.config_updates,
            1,
            config.write_table(28, &u32::to_le_bytes(0x0))
        );

        assert_eq!(config.table_entries[0].msg_addr_hi, 0x1312);
        assert_eq!(config.table_entries[0].msg_addr_lo, 0x1110);
        assert_eq!(config.table_entries[0].msg_data, 0x20);
        assert_eq!(config.table_entries[0].vector_ctl, 0);

        assert_eq!(config.table_entries[1].msg_addr_hi, 0x4443);
        assert_eq!(config.table_entries[1].msg_addr_lo, 0x4241);
        assert_eq!(config.table_entries[1].msg_data, 0x21);
        assert_eq!(config.table_entries[1].vector_ctl, 0);

        assert_eq!(config.table_entries.len(), 2);
        assert_eq!(config.pba_entries.len(), 1);

        // reading at a bad offset should return all 1s
        config.read_table(1, &mut buffer[..4]);
        assert_eq!(buffer[..4], [0xff; 4]);
        // read low address for first vector
        config.read_table(0, &mut buffer[..4]);
        assert_eq!(
            buffer[..4],
            u32::to_le_bytes(config.table_entries[0].msg_addr_lo)
        );
        // read the high address for first vector
        config.read_table(4, &mut buffer[4..]);
        assert_eq!(0x0000_1312_0000_1110, u64::from_le_bytes(buffer));
        // read msg_data from second vector
        config.read_table(24, &mut buffer[..4]);
        assert_eq!(u32::to_le_bytes(0x21), &buffer[..4]);
        // read vector control for second vector
        config.read_table(28, &mut buffer[..4]);
        assert_eq!(u32::to_le_bytes(0x0), &buffer[..4]);

        // reading with 8 bytes at bad offset should also return all 1s
        config.read_table(19, &mut buffer);
        assert_eq!(buffer, [0xff; 8]);

        // Read the second vector's address using an 8 byte read
        config.read_table(16, &mut buffer);
        assert_eq!(0x0000_4443_0000_4241, u64::from_le_bytes(buffer));

        // Read the first vector's ctrl and data with a single 8 byte read
        config.read_table(8, &mut buffer);
        assert_eq!(0x0_0000_0020, u64::from_le_bytes(buffer));

        // If we mask the interrupts we shouldn't see any update
        check_metric_after_block!(METRICS.interrupts.config_updates, 0, {
            config.write_table(12, &u32::to_le_bytes(0x1));
            config.write_table(28, &u32::to_le_bytes(0x1));
        });

        // Un-masking them should update them
        check_metric_after_block!(METRICS.interrupts.config_updates, 2, {
            config.write_table(12, &u32::to_le_bytes(0x0));
            config.write_table(28, &u32::to_le_bytes(0x0));
        });

        // Setting up the same config should have no effect
        check_metric_after_block!(METRICS.interrupts.config_updates, 0, {
            config.write_table(12, &u32::to_le_bytes(0x0));
            config.write_table(28, &u32::to_le_bytes(0x0));
        });
    }

    #[test]
    #[should_panic]
    fn test_table_access_write_too_big() {
        let mut config = MsixConfig::new(msix_vector_group(2), 0x42);
        let buffer = [0u8; 16];

        config.write_table(0, &buffer);
    }

    #[test]
    fn test_pba_read_too_big() {
        let config = MsixConfig::new(msix_vector_group(2), 0x42);
        let mut buffer = [0u8; 16];

        config.read_pba(0, &mut buffer);
        assert_eq!(buffer, [0xff; 16]);
    }

    #[test]
    fn test_pba_invalid_offset() {
        let config = MsixConfig::new(msix_vector_group(2), 0x42);
        let mut buffer = [0u8; 8];

        // Past the end of the PBA array
        config.read_pba(128, &mut buffer);
        assert_eq!(buffer, [0xffu8; 8]);

        // Invalid offset within a valid entry
        let mut buffer = [0u8; 8];
        config.read_pba(3, &mut buffer[..4]);
        assert_eq!(buffer[..4], [0xffu8; 4]);
        config.read_pba(3, &mut buffer);
        assert_eq!(buffer, [0xffu8; 8]);
    }

    #[test]
    #[should_panic]
    fn test_set_pba_bit_vector_too_big() {
        let mut config = MsixConfig::new(msix_vector_group(2), 0x42);

        config.set_pba_bit(2048, false);
    }

    #[test]
    #[should_panic]
    fn test_get_pba_bit_vector_too_big() {
        let config = MsixConfig::new(msix_vector_group(2), 0x42);

        config.get_pba_bit(2048);
    }

    #[test]
    fn test_pba_bit_invalid_vector() {
        let mut config = MsixConfig::new(msix_vector_group(2), 0x42);

        // We have two vectors, so setting the pending bit for the third one
        // should be ignored
        config.set_pba_bit(2, false);
        assert_eq!(config.pba_entries[0], 0);

        // Same for getting the bit
        assert_eq!(config.get_pba_bit(2), 0xff);
    }

    #[test]
    fn test_pba_read() {
        let mut config = MsixConfig::new(msix_vector_group(128), 0x42);
        let mut buffer = [0u8; 8];

        config.set_pba_bit(1, false);
        assert_eq!(config.pba_entries[0], 2);
        assert_eq!(config.pba_entries[1], 0);
        config.read_pba(0, &mut buffer);
        assert_eq!(0x2, u64::from_le_bytes(buffer));

        let mut buffer = [0u8; 4];
        config.set_pba_bit(96, false);
        assert_eq!(config.pba_entries[0], 2);
        assert_eq!(config.pba_entries[1], 0x1_0000_0000);
        config.read_pba(8, &mut buffer);
        assert_eq!(0x0, u32::from_le_bytes(buffer));
        config.read_pba(12, &mut buffer);
        assert_eq!(0x1, u32::from_le_bytes(buffer));
    }

    #[test]
    fn test_pending_interrupt() {
        let mut config = MsixConfig::new(msix_vector_group(2), 0x42);
        config.set_pba_bit(1, false);
        assert_eq!(config.get_pba_bit(1), 1);
        // Enable MSI-X vector and unmask interrupts
        // Individual vectors are still masked, so no change
        check_metric_after_block!(METRICS.interrupts.triggers, 0, config.set_msg_ctl(0x8000));

        // Enable all vectors
        // Vector one had a pending bit, so we must have triggered an interrupt for it
        // and cleared the pending bit
        check_metric_after_block!(METRICS.interrupts.triggers, 1, {
            config.write_table(8, &u64::to_le_bytes(0x0_0000_0020));
            config.write_table(24, &u64::to_le_bytes(0x0_0000_0020));
        });
        assert_eq!(config.get_pba_bit(1), 0);

        // Check that interrupt is sent as well for enabled vectors once we unmask from
        // Message Control

        // Mask vectors and set pending bit for vector 0
        check_metric_after_block!(METRICS.interrupts.triggers, 0, {
            config.set_msg_ctl(0xc000);
            config.set_pba_bit(0, false);
        });

        // Unmask them
        check_metric_after_block!(METRICS.interrupts.triggers, 1, config.set_msg_ctl(0x8000));
        assert_eq!(config.get_pba_bit(0), 0);
    }
}
