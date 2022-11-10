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

//! Traits and structs for configuring and loading boot parameters on `x86_64` using the Linux
//! boot protocol.

use vm_memory::{Bytes, GuestMemory};

use crate::configurator::{BootConfigurator, BootParams, Error as BootConfiguratorError, Result};

use std::fmt;

/// Boot configurator for the Linux boot protocol.
pub struct LinuxBootConfigurator {}

/// Errors specific to the Linux boot protocol configuration.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The zero page extends past the end of guest memory.
    ZeroPagePastRamEnd,
    /// Error writing to the zero page of guest memory.
    ZeroPageSetup,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;
        let desc = match self {
            ZeroPagePastRamEnd => "the zero page extends past the end of guest memory.",
            ZeroPageSetup => "error writing to the zero page of guest memory.",
        };

        write!(f, "Linux Boot Configurator: {}", desc,)
    }
}

impl std::error::Error for Error {}

impl From<Error> for BootConfiguratorError {
    fn from(err: Error) -> Self {
        BootConfiguratorError::Linux(err)
    }
}

impl BootConfigurator for LinuxBootConfigurator {
    /// Writes the boot parameters (configured elsewhere) into guest memory.
    ///
    /// # Arguments
    ///
    /// * `params` - boot parameters. The header contains a [`boot_params`] struct. The `sections`
    ///              and `modules` are unused.
    /// * `guest_memory` - guest's physical memory.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # extern crate vm_memory;
    /// # use linux_loader::configurator::{BootConfigurator, BootParams};
    /// # use linux_loader::configurator::linux::LinuxBootConfigurator;
    /// # use linux_loader::loader::bootparam::boot_params;
    /// # use vm_memory::{Address, ByteValued, GuestMemory, GuestMemoryMmap, GuestAddress};
    /// # const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
    /// # const KERNEL_HDR_MAGIC: u32 = 0x53726448;
    /// # const KERNEL_LOADER_OTHER: u8 = 0xff;
    /// # const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x1000000;
    /// # const MEM_SIZE: u64 = 0x100_0000;
    /// # fn create_guest_memory() -> GuestMemoryMmap {
    /// #   GuestMemoryMmap::from_ranges(&[(GuestAddress(0x0), (MEM_SIZE as usize))]).unwrap()
    /// # }
    /// fn build_bootparams() -> boot_params {
    ///     let mut params = boot_params::default();
    ///     params.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC;
    ///     params.hdr.header = KERNEL_HDR_MAGIC;
    ///     params.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;
    ///     params.hdr.type_of_loader = KERNEL_LOADER_OTHER;
    ///     params
    /// }
    ///
    /// fn main() {
    /// #   let zero_page_addr = GuestAddress(0x30000);
    ///     let guest_memory = create_guest_memory();
    ///     let params = build_bootparams();
    ///     let mut bootparams = BootParams::new::<boot_params>(&params, zero_page_addr);
    ///     LinuxBootConfigurator::write_bootparams::<GuestMemoryMmap>(&bootparams, &guest_memory)
    ///         .unwrap();
    /// }
    /// ```
    ///
    /// [`boot_params`]: ../loader/bootparam/struct.boot_params.html
    fn write_bootparams<M>(params: &BootParams, guest_memory: &M) -> Result<()>
    where
        M: GuestMemory,
    {
        // The VMM has filled a `boot_params` struct and its e820 map.
        // This will be written in guest memory at the zero page.
        guest_memory
            .checked_offset(params.header_start, params.header.len())
            .ok_or(Error::ZeroPagePastRamEnd)?;
        guest_memory
            .write_slice(params.header.as_slice(), params.header_start)
            .map_err(|_| Error::ZeroPageSetup)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader_gen::bootparam::boot_params;
    use std::mem;
    use vm_memory::{Address, GuestAddress, GuestMemoryMmap};

    const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
    const KERNEL_HDR_MAGIC: u32 = 0x53726448;
    const KERNEL_LOADER_OTHER: u8 = 0xff;
    const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x1000000;
    const MEM_SIZE: u64 = 0x100_0000;

    fn create_guest_mem() -> GuestMemoryMmap {
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0x0), (MEM_SIZE as usize))]).unwrap()
    }

    fn build_bootparams_common() -> boot_params {
        let mut params = boot_params::default();
        params.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC;
        params.hdr.header = KERNEL_HDR_MAGIC;
        params.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;
        params.hdr.type_of_loader = KERNEL_LOADER_OTHER;
        params
    }

    #[test]
    fn test_configure_linux_boot() {
        let zero_page_addr = GuestAddress(0x30000);

        let params = build_bootparams_common();
        // This is where we'd append e820 entries, cmdline, PCI, ACPI etc.

        let guest_memory = create_guest_mem();

        // Error case: boot params don't fit in guest memory (zero page address too close to end).
        let bad_zeropg_addr = GuestAddress(
            guest_memory.last_addr().raw_value() - mem::size_of::<boot_params>() as u64 + 1,
        );
        let mut bootparams = BootParams::new::<boot_params>(&params, bad_zeropg_addr);
        assert_eq!(
            LinuxBootConfigurator::write_bootparams::<GuestMemoryMmap>(&bootparams, &guest_memory,)
                .err(),
            Some(Error::ZeroPagePastRamEnd.into()),
        );

        // Success case.
        bootparams.header_start = zero_page_addr;
        assert!(LinuxBootConfigurator::write_bootparams::<GuestMemoryMmap>(
            &bootparams,
            &guest_memory,
        )
        .is_ok());
    }

    #[test]
    fn test_error_messages() {
        assert_eq!(
            format!("{}", Error::ZeroPagePastRamEnd),
            "Linux Boot Configurator: the zero page extends past the end of guest memory."
        );
        assert_eq!(
            format!("{}", Error::ZeroPageSetup),
            "Linux Boot Configurator: error writing to the zero page of guest memory."
        );
    }
}
