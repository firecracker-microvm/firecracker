// Copyright © 2019 Intel Corporation
// Copyright © 2023 Rivos, Inc.
// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::mem::size_of;

use vm_memory::{Bytes, GuestAddress, GuestMemory};
use zerocopy::{Immutable, IntoBytes};

use crate::{Result, Sdt, SdtHeader, checksum};

#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Default, Debug, IntoBytes, Clone, Copy, Immutable)]
struct PciRangeEntry {
    pub base_address: u64,
    pub segment: u16,
    pub start: u8,
    pub end: u8,
    _reserved: u32,
}

#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default, IntoBytes, Immutable)]
pub struct Mcfg {
    header: SdtHeader,
    _reserved: u64,
    pci_range_entry: PciRangeEntry,
}

impl Mcfg {
    pub fn new(
        oem_id: [u8; 6],
        oem_table_id: [u8; 8],
        oem_revision: u32,
        pci_mmio_config_addr: u64,
    ) -> Self {
        let header = SdtHeader::new(
            *b"MCFG",
            size_of::<Mcfg>().try_into().unwrap(),
            1,
            oem_id,
            oem_table_id,
            oem_revision,
        );

        let mut mcfg = Mcfg {
            header,
            pci_range_entry: PciRangeEntry {
                base_address: pci_mmio_config_addr,
                segment: 0,
                start: 0,
                end: 0,
                ..Default::default()
            },
            ..Default::default()
        };

        mcfg.header.checksum = checksum(&[mcfg.as_bytes()]);

        mcfg
    }
}

impl Sdt for Mcfg {
    fn len(&self) -> usize {
        self.as_bytes().len()
    }

    fn write_to_guest<M: GuestMemory>(&mut self, mem: &M, address: GuestAddress) -> Result<()> {
        mem.write_slice(self.as_bytes(), address)?;
        Ok(())
    }
}
