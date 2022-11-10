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

//! Traits and structs for loading kernels into guest memory.
//! - [KernelLoader](trait.KernelLoader.html): load kernel image into guest memory.
//! - [KernelLoaderResult](struct.KernelLoaderResult.html): structure passed to the VMM to assist
//!   zero page construction and boot environment setup.
//! - [Elf](elf/struct.Elf.html): elf image loader.
//! - [BzImage](bzimage/struct.BzImage.html): bzImage loader.
//! - [PE](pe/struct.PE.html): PE image loader.

extern crate vm_memory;

use std::fmt;
use std::io::{Read, Seek};

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use vm_memory::ByteValued;
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestUsize};

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use crate::loader_gen::bootparam;

pub use crate::cmdline::Cmdline;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86_64;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use x86_64::*;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::*;

#[derive(Debug, PartialEq, Eq)]
/// Kernel loader errors.
pub enum Error {
    /// Failed to load bzimage.
    #[cfg(all(feature = "bzimage", any(target_arch = "x86", target_arch = "x86_64")))]
    Bzimage(bzimage::Error),

    /// Failed to load elf image.
    #[cfg(all(feature = "elf", any(target_arch = "x86", target_arch = "x86_64")))]
    Elf(elf::Error),

    /// Failed to load PE image.
    #[cfg(all(feature = "pe", target_arch = "aarch64"))]
    Pe(pe::Error),

    /// Invalid command line.
    InvalidCommandLine,
    /// Failed writing command line to guest memory.
    CommandLineCopy,
    /// Command line overflowed guest memory.
    CommandLineOverflow,
    /// Invalid kernel start address.
    InvalidKernelStartAddress,
    /// Memory to load kernel image is too small.
    MemoryOverflow,
}

/// A specialized [`Result`] type for the kernel loader.
///
/// [`Result`]: https://doc.rust-lang.org/std/result/enum.Result.html
pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let desc = match self {
            #[cfg(all(feature = "bzimage", any(target_arch = "x86", target_arch = "x86_64")))]
            Error::Bzimage(ref _e) => "failed to load bzImage kernel image",
            #[cfg(all(feature = "elf", any(target_arch = "x86", target_arch = "x86_64")))]
            Error::Elf(ref _e) => "failed to load ELF kernel image",
            #[cfg(all(feature = "pe", target_arch = "aarch64"))]
            Error::Pe(ref _e) => "failed to load PE kernel image",

            Error::InvalidCommandLine => "invalid command line provided",
            Error::CommandLineCopy => "failed writing command line to guest memory",
            Error::CommandLineOverflow => "command line overflowed guest memory",
            Error::InvalidKernelStartAddress => "invalid kernel start address",
            Error::MemoryOverflow => "memory to load kernel image is not enough",
        };

        write!(f, "Kernel Loader: {}", desc)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            #[cfg(all(feature = "bzimage", any(target_arch = "x86", target_arch = "x86_64")))]
            Error::Bzimage(ref e) => Some(e),
            #[cfg(all(feature = "elf", any(target_arch = "x86", target_arch = "x86_64")))]
            Error::Elf(ref e) => Some(e),
            #[cfg(all(feature = "pe", target_arch = "aarch64"))]
            Error::Pe(ref e) => Some(e),

            Error::InvalidCommandLine => None,
            Error::CommandLineCopy => None,
            Error::CommandLineOverflow => None,
            Error::InvalidKernelStartAddress => None,
            Error::MemoryOverflow => None,
        }
    }
}

#[cfg(all(feature = "elf", any(target_arch = "x86", target_arch = "x86_64")))]
impl From<elf::Error> for Error {
    fn from(err: elf::Error) -> Self {
        Error::Elf(err)
    }
}

#[cfg(all(feature = "bzimage", any(target_arch = "x86", target_arch = "x86_64")))]
impl From<bzimage::Error> for Error {
    fn from(err: bzimage::Error) -> Self {
        Error::Bzimage(err)
    }
}

#[cfg(all(feature = "pe", target_arch = "aarch64"))]
impl From<pe::Error> for Error {
    fn from(err: pe::Error) -> Self {
        Error::Pe(err)
    }
}

/// Result of [`KernelLoader.load()`](trait.KernelLoader.html#tymethod.load).
///
/// This specifies where the kernel is loading and passes additional
/// information for the rest of the boot process to be completed by
/// the VMM.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct KernelLoaderResult {
    /// Address in the guest memory where the kernel image starts to be loaded.
    pub kernel_load: GuestAddress,
    /// Offset in guest memory corresponding to the end of kernel image, in case the device tree
    /// blob and initrd will be loaded adjacent to kernel image.
    pub kernel_end: GuestUsize,
    /// Configuration for the VMM to use to fill zero page for bzImage direct boot.
    /// See https://www.kernel.org/doc/Documentation/x86/boot.txt.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub setup_header: Option<bootparam::setup_header>,
    /// Availability of a PVH entry point. Only used for ELF boot, indicates whether the kernel
    /// supports the PVH boot protocol as described in:
    /// https://xenbits.xen.org/docs/unstable/misc/pvh.html
    #[cfg(all(feature = "elf", any(target_arch = "x86", target_arch = "x86_64")))]
    pub pvh_boot_cap: elf::PvhBootCapability,
}

/// Trait that specifies kernel image loading support.
pub trait KernelLoader {
    /// How to load a specific kernel image format into the guest memory.
    ///
    /// # Arguments
    ///
    /// * `guest_mem`: [`GuestMemory`] to load the kernel in.
    /// * `kernel_offset`: Usage varies between implementations.
    /// * `kernel_image`: Kernel image to be loaded.
    /// * `highmem_start_address`: Address where high memory starts.
    ///
    /// [`GuestMemory`]: https://docs.rs/vm-memory/latest/vm_memory/guest_memory/trait.GuestMemory.html
    fn load<F, M: GuestMemory>(
        guest_mem: &M,
        kernel_offset: Option<GuestAddress>,
        kernel_image: &mut F,
        highmem_start_address: Option<GuestAddress>,
    ) -> Result<KernelLoaderResult>
    where
        F: Read + Seek;
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe impl ByteValued for bootparam::setup_header {}
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe impl ByteValued for bootparam::boot_params {}

/// Writes the command line string to the given guest memory slice.
///
/// # Arguments
///
/// * `guest_mem` - [`GuestMemory`] that will be partially overwritten by the command line.
/// * `guest_addr` - The address in `guest_mem` at which to load the command line.
/// * `cmdline` - The kernel command line.
///
/// [`GuestMemory`]: https://docs.rs/vm-memory/latest/vm_memory/guest_memory/trait.GuestMemory.html
///
/// # Examples
///
/// ```rust
/// # use std::ffi::CStr;
/// # extern crate vm_memory;
/// # use linux_loader::loader::*;
/// # use vm_memory::{Bytes, GuestAddress};
/// # type GuestMemoryMmap = vm_memory::GuestMemoryMmap<()>;
/// let mem_size: usize = 0x1000000;
/// let gm = GuestMemoryMmap::from_ranges(&[(GuestAddress(0x0), mem_size)]).unwrap();
/// let mut cl = Cmdline::new(10).unwrap();
/// cl.insert("foo", "bar");
/// let mut buf = vec![0u8;8];
/// let result = load_cmdline(&gm, GuestAddress(0x1000), &cl).unwrap();
/// gm.read_slice(buf.as_mut_slice(), GuestAddress(0x1000)).unwrap();
/// assert_eq!(buf.as_slice(), "foo=bar\0".as_bytes());
pub fn load_cmdline<M: GuestMemory>(
    guest_mem: &M,
    guest_addr: GuestAddress,
    cmdline: &Cmdline,
) -> Result<()> {
    // We need a null terminated string because that's what the Linux
    // kernel expects when parsing the command line:
    // https://elixir.bootlin.com/linux/v5.10.139/source/kernel/params.c#L179
    let cmdline_string = cmdline
        .as_cstring()
        .map_err(|_| Error::InvalidCommandLine)?;

    let cmdline_bytes = cmdline_string.as_bytes_with_nul();

    let end = guest_addr
        // Underflow not possible because the cmdline contains at least
        // a byte (null terminator)
        .checked_add((cmdline_bytes.len() - 1) as u64)
        .ok_or(Error::CommandLineOverflow)?;
    if end > guest_mem.last_addr() {
        return Err(Error::CommandLineOverflow);
    }

    guest_mem
        .write_slice(cmdline_bytes, guest_addr)
        .map_err(|_| Error::CommandLineCopy)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vm_memory::{Address, GuestAddress};
    type GuestMemoryMmap = vm_memory::GuestMemoryMmap<()>;

    const MEM_SIZE: u64 = 0x100_0000;

    fn create_guest_mem() -> GuestMemoryMmap {
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0x0), (MEM_SIZE as usize))]).unwrap()
    }

    #[test]
    fn test_cmdline_overflow() {
        let gm = create_guest_mem();
        let mut cl = Cmdline::new(10).unwrap();
        cl.insert_str("12345").unwrap();

        let cmdline_address = GuestAddress(u64::MAX - 5);
        assert_eq!(
            Err(Error::CommandLineOverflow),
            load_cmdline(&gm, cmdline_address, &cl)
        );

        let cmdline_address = GuestAddress(MEM_SIZE - 5);
        assert_eq!(
            Err(Error::CommandLineOverflow),
            load_cmdline(&gm, cmdline_address, &cl)
        );
        let cmdline_address = GuestAddress(MEM_SIZE - 6);
        assert!(load_cmdline(&gm, cmdline_address, &cl).is_ok());
    }

    #[test]
    fn test_cmdline_write_end_regresion() {
        let gm = create_guest_mem();
        let mut cmdline_address = GuestAddress(45);
        let sample_buf = &[1; 100];

        // Fill in guest memory with non zero bytes
        gm.write(sample_buf, cmdline_address).unwrap();

        let mut cl = Cmdline::new(10).unwrap();

        // Test loading an empty cmdline
        load_cmdline(&gm, cmdline_address, &cl).unwrap();
        let val: u8 = gm.read_obj(cmdline_address).unwrap();
        assert_eq!(val, b'\0');

        // Test loading an non-empty cmdline
        cl.insert_str("123").unwrap();
        load_cmdline(&gm, cmdline_address, &cl).unwrap();

        let val: u8 = gm.read_obj(cmdline_address).unwrap();
        assert_eq!(val, b'1');
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj(cmdline_address).unwrap();
        assert_eq!(val, b'2');
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj(cmdline_address).unwrap();
        assert_eq!(val, b'3');
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj(cmdline_address).unwrap();
        assert_eq!(val, b'\0');
    }
}
