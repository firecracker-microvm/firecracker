// Copyright © 2019 Intel Corporation
// Copyright © 2023 Rivos, Inc.
// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

use vm_memory::{Bytes, GuestAddress, GuestMemory};
use zerocopy::little_endian::{U32, U64};
use zerocopy::{Immutable, IntoBytes};

use crate::{Result, Sdt, checksum};

// clippy doesn't understand that we actually "use" the fields of this struct when we serialize
// them as bytes in guest memory, so here we just ignore dead code to avoid having to name
// everything with an underscore prefix
#[allow(dead_code)]
/// Root System Description Pointer
///
/// This is the root pointer to the ACPI hierarchy. This is what OSs
/// are looking for in the memory when initializing ACPI. It includes
/// a pointer to XSDT
/// More information about this structure can be found in the ACPI specification:
/// https://uefi.org/specs/ACPI/6.5/05_ACPI_Software_Programming_Model.html#root-system-description-pointer-rsdp
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default, IntoBytes, Immutable)]
pub struct Rsdp {
    signature: [u8; 8],
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_addr: U32,
    length: U32,
    xsdt_addr: U64,
    extended_checksum: u8,
    reserved: [u8; 3],
}

impl Rsdp {
    pub fn new(oem_id: [u8; 6], xsdt_addr: u64) -> Self {
        let mut rsdp = Rsdp {
            // Space in the end of string is needed!
            signature: *b"RSD PTR ",
            checksum: 0,
            oem_id,
            revision: 2,
            rsdt_addr: U32::ZERO,
            length: U32::new(std::mem::size_of::<Rsdp>().try_into().unwrap()),
            xsdt_addr: U64::new(xsdt_addr),
            extended_checksum: 0,
            reserved: [0u8; 3],
        };

        rsdp.checksum = checksum(&[&rsdp.as_bytes()[..20]]);
        rsdp.extended_checksum = checksum(&[rsdp.as_bytes()]);
        rsdp
    }
}

impl Sdt for Rsdp {
    fn len(&self) -> usize {
        self.as_bytes().len()
    }

    fn write_to_guest<M: GuestMemory>(&mut self, mem: &M, address: GuestAddress) -> Result<()> {
        mem.write_slice(self.as_bytes(), address)?;
        Ok(())
    }
}
