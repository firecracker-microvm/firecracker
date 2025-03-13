// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright 2023 Rivos, Inc.
//
// SPDX-License-Identifier: Apache-2.0

use std::mem::size_of;

use vm_memory::{Address, Bytes, GuestAddress, GuestMemory};
use zerocopy::IntoBytes;

use crate::{AcpiError, Result, Sdt, SdtHeader, checksum};

/// Extended System Description Table (XSDT)
///
/// This table provides 64bit addresses to the rest of the ACPI tables defined by the platform
/// More information about this table can be found in the ACPI specification:
/// https://uefi.org/specs/ACPI/6.5/05_ACPI_Software_Programming_Model.html#extended-system-description-table-xsdt
#[derive(Clone, Default, Debug)]
pub struct Xsdt {
    header: SdtHeader,
    tables: Vec<u8>,
}

impl Xsdt {
    pub fn new(
        oem_id: [u8; 6],
        oem_table_id: [u8; 8],
        oem_revision: u32,
        tables: Vec<u64>,
    ) -> Self {
        let mut tables_bytes = Vec::with_capacity(8 * tables.len());
        for addr in tables {
            tables_bytes.extend(&addr.to_le_bytes());
        }

        let header = SdtHeader::new(
            *b"XSDT",
            (std::mem::size_of::<SdtHeader>() + tables_bytes.len())
                .try_into()
                .unwrap(),
            1,
            oem_id,
            oem_table_id,
            oem_revision,
        );

        let mut xsdt = Xsdt {
            header,

            tables: tables_bytes,
        };

        xsdt.header.checksum = checksum(&[xsdt.header.as_bytes(), (xsdt.tables.as_slice())]);

        xsdt
    }
}

impl Sdt for Xsdt {
    fn len(&self) -> usize {
        std::mem::size_of::<SdtHeader>() + self.tables.len()
    }

    fn write_to_guest<M: GuestMemory>(&mut self, mem: &M, address: GuestAddress) -> Result<()> {
        mem.write_slice(self.header.as_bytes(), address)?;
        let address = address
            .checked_add(size_of::<SdtHeader>() as u64)
            .ok_or(AcpiError::InvalidGuestAddress)?;
        mem.write_slice(self.tables.as_slice(), address)?;
        Ok(())
    }
}
