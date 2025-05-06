// Copyright © 2019 Intel Corporation
// Copyright 2023 Rivos, Inc.
// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

use vm_memory::{GuestAddress, GuestMemory, GuestMemoryError};

pub mod aml;
pub mod dsdt;
pub mod fadt;
pub mod madt;
pub mod rsdp;
pub mod xsdt;

pub use aml::Aml;
pub use dsdt::Dsdt;
pub use fadt::Fadt;
pub use madt::Madt;
pub use rsdp::Rsdp;
pub use xsdt::Xsdt;
use zerocopy::little_endian::{U32, U64};
use zerocopy::{Immutable, IntoBytes};

// This is the creator ID that we will embed in ACPI tables that are created using this crate.
const FC_ACPI_CREATOR_ID: [u8; 4] = *b"FCAT";
// This is the created ID revision that we will embed in ACPI tables that are created using this
// crate.
const FC_ACPI_CREATOR_REVISION: u32 = 0x20240119;

fn checksum(buf: &[&[u8]]) -> u8 {
    (255 - buf
        .iter()
        .flat_map(|b| b.iter())
        .fold(0u8, |acc, x| acc.wrapping_add(*x)))
    .wrapping_add(1)
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum AcpiError {
    /// Guest memory error: {0}
    GuestMemory(#[from] GuestMemoryError),
    /// Invalid guest address
    InvalidGuestAddress,
    /// Invalid register size
    InvalidRegisterSize,
}

pub type Result<T> = std::result::Result<T, AcpiError>;

/// ACPI type representing memory addresses
#[repr(C, packed)]
#[derive(IntoBytes, Immutable, Clone, Copy, Debug, Default)]
pub struct GenericAddressStructure {
    pub address_space_id: u8,
    pub register_bit_width: u8,
    pub register_bit_offset: u8,
    pub access_size: u8,
    pub address: U64,
}

impl GenericAddressStructure {
    pub fn new(
        address_space_id: u8,
        register_bit_width: u8,
        register_bit_offset: u8,
        access_size: u8,
        address: u64,
    ) -> Self {
        Self {
            address_space_id,
            register_bit_width,
            register_bit_offset,
            access_size,
            address: U64::new(address),
        }
    }
}

/// Header included in all System Descriptor Tables
#[repr(C, packed)]
#[derive(Clone, Debug, Copy, Default, IntoBytes, Immutable)]
pub struct SdtHeader {
    pub signature: [u8; 4],
    pub length: U32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: [u8; 8],
    pub oem_revision: U32,
    pub creator_id: [u8; 4],
    pub creator_revison: U32,
}

impl SdtHeader {
    pub(crate) fn new(
        signature: [u8; 4],
        length: u32,
        table_revision: u8,
        oem_id: [u8; 6],
        oem_table_id: [u8; 8],
        oem_revision: u32,
    ) -> Self {
        SdtHeader {
            signature,
            length: U32::new(length),
            revision: table_revision,
            checksum: 0,
            oem_id,
            oem_table_id,
            oem_revision: U32::new(oem_revision),
            creator_id: FC_ACPI_CREATOR_ID,
            creator_revison: U32::new(FC_ACPI_CREATOR_REVISION),
        }
    }
}

/// A trait for functionality around System Descriptor Tables.
pub trait Sdt {
    /// Get the length of the table
    fn len(&self) -> usize;

    /// Return true if Sdt is empty
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Write the table in guest memory
    fn write_to_guest<M: GuestMemory>(&mut self, mem: &M, address: GuestAddress) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::checksum;

    #[test]
    fn test_checksum() {
        assert_eq!(checksum(&[&[]]), 0u8);
        assert_eq!(checksum(&[]), 0u8);
        assert_eq!(checksum(&[&[1, 2, 3]]), 250u8);
        assert_eq!(checksum(&[&[1, 2, 3], &[]]), 250u8);
        assert_eq!(checksum(&[&[1, 2], &[3]]), 250u8);
        assert_eq!(checksum(&[&[1, 2], &[3], &[250]]), 0u8);
        assert_eq!(checksum(&[&[255]]), 1u8);
        assert_eq!(checksum(&[&[1, 2], &[3], &[250], &[255]]), 1u8);
    }
}
