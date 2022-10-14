// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::mem::size_of;

use vm_memory::{Address, ByteValued, Bytes, GuestAddress, GuestMemoryMmap};

use crate::arch::{create_apic_structures, local_interrupt_controller_address};
use crate::sdt::{Sdt, SdtHeader};
use crate::{checksum, AcpiError, Result};

pub struct Madt {
    header: SdtHeader,
    base_address: u32,
    flags: u32,
    interrupt_controllers: Vec<u8>,
}

impl Madt {
    pub fn new(num_cpus: usize) -> Self {
        let interrupt_controllers = create_apic_structures(num_cpus);
        let header = SdtHeader::new(
            *b"APIC",
            (size_of::<SdtHeader>() + interrupt_controllers.len() + 8) as u32,
            6,
            *b"FCVMMADT",
        );

        let mut madt = Madt {
            header,
            base_address: local_interrupt_controller_address(),
            flags: 0,
            interrupt_controllers,
        };

        madt.header.set_checksum(checksum(&[
            madt.header.as_slice(),
            &madt.base_address.to_le_bytes(),
            &madt.flags.to_le_bytes(),
            madt.interrupt_controllers.as_slice(),
        ]));

        madt
    }
}

impl Sdt for Madt {
    fn len(&self) -> usize {
        self.header.length as usize
    }

    fn write_to_guest(&self, mem: &GuestMemoryMmap, address: GuestAddress) -> Result<()> {
        mem.write_slice(self.header.as_slice(), address)?;
        let address = address
            .checked_add(size_of::<SdtHeader>() as u64)
            .ok_or(AcpiError::InvalidGuestAddress)?;
        mem.write_obj(self.base_address, address)?;
        let address = address
            .checked_add(size_of::<u32>() as u64)
            .ok_or(AcpiError::InvalidGuestAddress)?;
        mem.write_obj(self.flags, address)?;
        let address = address
            .checked_add(size_of::<u32>() as u64)
            .ok_or(AcpiError::InvalidGuestAddress)?;
        mem.write_slice(self.interrupt_controllers.as_slice(), address)?;

        Ok(())
    }
}
