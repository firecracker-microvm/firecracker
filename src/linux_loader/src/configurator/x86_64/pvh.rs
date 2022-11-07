// Copyright © 2020, Oracle and/or its affiliates.
//
// Copyright (c) 2019 Intel Corporation. All rights reserved.
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! Traits and structs for configuring and loading boot parameters on `x86_64` using the PVH boot
//! protocol.

#![cfg(any(feature = "elf", feature = "bzimage"))]

use vm_memory::{ByteValued, Bytes, GuestMemory};

use crate::configurator::{BootConfigurator, BootParams, Error as BootConfiguratorError, Result};
use crate::loader_gen::start_info::{hvm_memmap_table_entry, hvm_modlist_entry, hvm_start_info};

use std::fmt;

/// Boot configurator for the PVH boot protocol.
pub struct PvhBootConfigurator {}

/// Errors specific to the PVH boot protocol configuration.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The starting address for the memory map wasn't passed to the boot configurator.
    MemmapTableAddressMissing,
    /// No memory map wasn't passed to the boot configurator.
    MemmapTableMissing,
    /// The memory map table extends past the end of guest memory.
    MemmapTablePastRamEnd,
    /// Error writing memory map table to guest memory.
    MemmapTableSetup,
    /// The hvm_start_info structure extends past the end of guest memory.
    StartInfoPastRamEnd,
    /// Error writing hvm_start_info to guest memory.
    StartInfoSetup,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;
        let desc = match self {
            MemmapTableAddressMissing => {
                "the starting address for the memory map wasn't passed to the boot configurator."
            }
            MemmapTableMissing => "no memory map was passed to the boot configurator.",
            MemmapTablePastRamEnd => "the memory map table extends past the end of guest memory.",
            MemmapTableSetup => "error writing memory map table to guest memory.",
            StartInfoPastRamEnd => {
                "the hvm_start_info structure extends past the end of guest memory."
            }
            StartInfoSetup => "error writing hvm_start_info to guest memory.",
        };

        write!(f, "PVH Boot Configurator: {}", desc)
    }
}

impl std::error::Error for Error {}

impl From<Error> for BootConfiguratorError {
    fn from(err: Error) -> Self {
        BootConfiguratorError::Pvh(err)
    }
}

unsafe impl ByteValued for hvm_start_info {}
unsafe impl ByteValued for hvm_memmap_table_entry {}
unsafe impl ByteValued for hvm_modlist_entry {}

impl BootConfigurator for PvhBootConfigurator {
    /// Writes the boot parameters (configured elsewhere) into guest memory.
    ///
    /// # Arguments
    ///
    /// * `params` - boot parameters. The header contains a [`hvm_start_info`] struct. The
    ///              sections contain the memory map in a vector of [`hvm_memmap_table_entry`]
    ///              structs. The modules, if specified, contain [`hvm_modlist_entry`] structs.
    /// * `guest_memory` - guest's physical memory.
    ///
    /// [`hvm_start_info`]: ../loader/elf/start_info/struct.hvm_start_info.html
    /// [`hvm_memmap_table_entry`]: ../loader/elf/start_info/struct.hvm_memmap_table_entry.html
    /// [`hvm_modlist_entry`]: ../loader/elf/start_info/struct.hvm_modlist_entry.html
    ///
    /// # Examples
    ///
    /// ```rust
    /// # extern crate vm_memory;
    /// # use linux_loader::configurator::{BootConfigurator, BootParams};
    /// # use linux_loader::configurator::pvh::PvhBootConfigurator;
    /// # use linux_loader::loader::elf::start_info::{hvm_start_info, hvm_memmap_table_entry};
    /// # use vm_memory::{Address, ByteValued, GuestMemory, GuestMemoryMmap, GuestAddress};
    /// # const XEN_HVM_START_MAGIC_VALUE: u32 = 0x336ec578;
    /// # const MEM_SIZE: u64 = 0x100_0000;
    /// # const E820_RAM: u32 = 1;
    /// fn create_guest_memory() -> GuestMemoryMmap {
    ///     GuestMemoryMmap::from_ranges(&[(GuestAddress(0x0), (MEM_SIZE as usize))]).unwrap()
    /// }
    ///
    /// fn build_boot_params() -> (hvm_start_info, Vec<hvm_memmap_table_entry>) {
    ///     let mut start_info = hvm_start_info::default();
    ///     let memmap_entry = hvm_memmap_table_entry {
    ///         addr: 0x7000,
    ///         size: 0,
    ///         type_: E820_RAM,
    ///         reserved: 0,
    ///     };
    ///     start_info.magic = XEN_HVM_START_MAGIC_VALUE;
    ///     start_info.version = 1;
    ///     start_info.nr_modules = 0;
    ///     start_info.memmap_entries = 0;
    ///     (start_info, vec![memmap_entry])
    /// }
    ///
    /// fn main() {
    ///     let guest_mem = create_guest_memory();
    ///     let (mut start_info, memmap_entries) = build_boot_params();
    ///     let start_info_addr = GuestAddress(0x6000);
    ///     let memmap_addr = GuestAddress(0x7000);
    ///     start_info.memmap_paddr = memmap_addr.raw_value();
    ///
    ///     let mut boot_params = BootParams::new::<hvm_start_info>(&start_info, start_info_addr);
    ///     boot_params.set_sections::<hvm_memmap_table_entry>(&memmap_entries, memmap_addr);
    ///     PvhBootConfigurator::write_bootparams::<GuestMemoryMmap>(&boot_params, &guest_mem).unwrap();
    /// }
    /// ```
    fn write_bootparams<M>(params: &BootParams, guest_memory: &M) -> Result<()>
    where
        M: GuestMemory,
    {
        // The VMM has filled an `hvm_start_info` struct and a `Vec<hvm_memmap_table_entry>`
        // and has passed them on to this function.
        // The `hvm_start_info` will be written at `addr` and the memmap entries at
        // `start_info.0.memmap_paddr`.
        let memmap = params.sections.as_ref().ok_or(Error::MemmapTableMissing)?;
        let memmap_addr = params
            .sections_start
            .ok_or(Error::MemmapTableAddressMissing)?;

        guest_memory
            .checked_offset(memmap_addr, memmap.len())
            .ok_or(Error::MemmapTablePastRamEnd)?;
        guest_memory
            .write_slice(memmap.as_slice(), memmap_addr)
            .map_err(|_| Error::MemmapTableSetup)?;

        guest_memory
            .checked_offset(params.header_start, params.header.len())
            .ok_or(Error::StartInfoPastRamEnd)?;
        guest_memory
            .write_slice(params.header.as_slice(), params.header_start)
            .map_err(|_| Error::StartInfoSetup)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;
    use vm_memory::{Address, GuestAddress, GuestMemoryMmap};

    const XEN_HVM_START_MAGIC_VALUE: u32 = 0x336ec578;
    const MEM_SIZE: u64 = 0x100_0000;
    const E820_RAM: u32 = 1;

    fn create_guest_mem() -> GuestMemoryMmap {
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0x0), (MEM_SIZE as usize))]).unwrap()
    }

    fn build_bootparams_common() -> (hvm_start_info, Vec<hvm_memmap_table_entry>) {
        let mut start_info = hvm_start_info::default();
        let memmap_entry = hvm_memmap_table_entry {
            addr: 0x7000,
            size: 0,
            type_: E820_RAM,
            reserved: 0,
        };

        start_info.magic = XEN_HVM_START_MAGIC_VALUE;
        start_info.version = 1;
        start_info.nr_modules = 0;
        start_info.memmap_entries = 0;

        (start_info, vec![memmap_entry])
    }

    #[test]
    fn test_configure_pvh_boot() {
        let (mut start_info, memmap_entries) = build_bootparams_common();
        let guest_memory = create_guest_mem();

        let start_info_addr = GuestAddress(0x6000);
        let memmap_addr = GuestAddress(0x7000);
        start_info.memmap_paddr = memmap_addr.raw_value();

        let mut boot_params = BootParams::new::<hvm_start_info>(&start_info, start_info_addr);

        // Error case: configure without memory map.
        assert_eq!(
            PvhBootConfigurator::write_bootparams::<GuestMemoryMmap>(&boot_params, &guest_memory,)
                .err(),
            Some(Error::MemmapTableMissing.into())
        );

        // Error case: start_info doesn't fit in guest memory.
        let bad_start_info_addr = GuestAddress(
            guest_memory.last_addr().raw_value() - mem::size_of::<hvm_start_info>() as u64 + 1,
        );
        boot_params.set_sections::<hvm_memmap_table_entry>(&memmap_entries, memmap_addr);
        boot_params.header_start = bad_start_info_addr;
        assert_eq!(
            PvhBootConfigurator::write_bootparams::<GuestMemoryMmap>(&boot_params, &guest_memory,)
                .err(),
            Some(Error::StartInfoPastRamEnd.into())
        );

        // Error case: memory map doesn't fit in guest memory.
        let himem_start = GuestAddress(0x100000);
        boot_params.header_start = himem_start;
        let bad_memmap_addr = GuestAddress(
            guest_memory.last_addr().raw_value() - mem::size_of::<hvm_memmap_table_entry>() as u64
                + 1,
        );
        boot_params.set_sections::<hvm_memmap_table_entry>(&memmap_entries, bad_memmap_addr);

        assert_eq!(
            PvhBootConfigurator::write_bootparams::<GuestMemoryMmap>(&boot_params, &guest_memory,)
                .err(),
            Some(Error::MemmapTablePastRamEnd.into())
        );

        boot_params.set_sections::<hvm_memmap_table_entry>(&memmap_entries, memmap_addr);
        assert!(PvhBootConfigurator::write_bootparams::<GuestMemoryMmap>(
            &boot_params,
            &guest_memory,
        )
        .is_ok());
    }

    #[test]
    fn test_error_messages() {
        assert_eq!(
            format!("{}", Error::MemmapTableMissing),
            "PVH Boot Configurator: no memory map was passed to the boot configurator."
        );
        assert_eq!(
            format!("{}", Error::MemmapTablePastRamEnd),
            "PVH Boot Configurator: the memory map table extends past the end of guest memory."
        );
        assert_eq!(
            format!("{}", Error::MemmapTableSetup),
            "PVH Boot Configurator: error writing memory map table to guest memory."
        );
        assert_eq!(format!("{}", Error::StartInfoPastRamEnd), "PVH Boot Configurator: the hvm_start_info structure extends past the end of guest memory.");
        assert_eq!(
            format!("{}", Error::StartInfoSetup),
            "PVH Boot Configurator: error writing hvm_start_info to guest memory."
        );
    }
}
