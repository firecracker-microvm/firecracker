// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vm_memory::{ByteValued, GuestAddress, GuestMemoryMmap};

use crate::{Result, FC_OEM_ID};

const FC_OEM_REVISION: u32 = 1u32;
const FC_ACPI_CREATOR: [u8; 4] = *b"FCVM";

/// Header included in all System Descriptor Tables
#[repr(packed)]
#[derive(Clone, Copy, Default)]
pub(crate) struct SdtHeader {
    pub(crate) _signature: [u8; 4],
    pub(crate) length: u32,
    pub(crate) _revision: u8,
    pub(crate) checksum: u8,
    pub(crate) _oem_id: [u8; 6],
    pub(crate) _oem_table_id: [u8; 8],
    pub(crate) _oem_revision: [u8; 4],
    pub(crate) _creator_id: [u8; 4],
    pub(crate) _creator_revison: [u8; 4],
}

// SdtHeader only contains plain data
unsafe impl ByteValued for SdtHeader {}

impl SdtHeader {
    pub(crate) fn new(
        _signature: [u8; 4],
        length: u32,
        _revision: u8,
        _oem_table_id: [u8; 8],
    ) -> Self {
        SdtHeader {
            _signature,
            length,
            _revision,
            checksum: 0,
            _oem_id: FC_OEM_ID,
            _oem_table_id,
            _oem_revision: FC_OEM_REVISION.to_le_bytes(),
            _creator_id: FC_ACPI_CREATOR,
            _creator_revison: 0u32.to_le_bytes(),
        }
    }

    pub(crate) fn set_checksum(&mut self, checksum: u8) {
        self.checksum = checksum;
    }
}

pub trait Sdt {
    /// Get the length of the table
    fn len(&self) -> usize;

    /// Return true if Sdt is empty
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Write the table in guest memory
    fn write_to_guest(&self, mem: &GuestMemoryMmap, address: GuestAddress) -> Result<()>;
}
