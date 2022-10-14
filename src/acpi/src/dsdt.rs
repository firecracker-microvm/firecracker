// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::mem::size_of;

use vm_memory::{Address, ByteValued, Bytes, GuestAddress, GuestMemoryMmap};

use crate::sdt::{Sdt, SdtHeader};
use crate::{checksum, AcpiError, Result};

pub struct Dsdt {
    header: SdtHeader,
    definition_block: Vec<u8>,
}

impl Dsdt {
    pub fn new(definition_block: Vec<u8>) -> Self {
        let header = SdtHeader::new(
            *b"DSDT",
            (size_of::<SdtHeader>() + definition_block.len()) as u32,
            2,
            *b"FCVMDSDT",
        );

        let mut dsdt = Dsdt {
            header,
            definition_block,
        };

        dsdt.header.set_checksum(checksum(&[
            dsdt.header.as_slice(),
            dsdt.definition_block.as_slice(),
        ]));
        dsdt
    }
}

impl Sdt for Dsdt {
    fn len(&self) -> usize {
        self.header.length as usize
    }

    fn write_to_guest(&self, mem: &GuestMemoryMmap, address: GuestAddress) -> Result<()> {
        mem.write_slice(self.header.as_slice(), address)?;
        let address = address
            .checked_add(size_of::<SdtHeader>() as u64)
            .ok_or(AcpiError::InvalidGuestAddress)?;
        mem.write_slice(self.definition_block.as_slice(), address)?;

        Ok(())
    }
}
