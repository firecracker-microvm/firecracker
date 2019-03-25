// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std;
use std::ffi::CStr;
use std::fmt;
use std::io::{Read, Seek, SeekFrom};
use std::mem;

use memory_model::{GuestAddress, GuestMemory};
use sys_util;

#[allow(non_camel_case_types)]
mod elf;

#[derive(Debug, PartialEq)]
pub enum Error {
    BigEndianElfOnLittle,
    CommandLineCopy,
    CommandLineOverflow,
    InvalidElfMagicNumber,
    InvalidEntryAddress,
    InvalidProgramHeaderSize,
    InvalidProgramHeaderOffset,
    InvalidProgramHeaderAddress,
    ReadElfHeader,
    ReadKernelImage,
    ReadProgramHeader,
    SeekKernelStart,
    SeekElfStart,
    SeekProgramHeader,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                Error::BigEndianElfOnLittle => "Unsupported ELF File byte order",
                Error::CommandLineCopy => "Failed to copy the command line string to guest memory",
                Error::CommandLineOverflow => "Command line string overflows guest memory",
                Error::InvalidElfMagicNumber => "Invalid ELF magic number",
                Error::InvalidEntryAddress => "Invalid entry address found in ELF header",
                Error::InvalidProgramHeaderSize => "Invalid ELF program header size",
                Error::InvalidProgramHeaderOffset => "Invalid ELF program header offset",
                Error::InvalidProgramHeaderAddress => "Invalid ELF program header address",
                Error::ReadElfHeader => "Failed to read ELF header",
                Error::ReadKernelImage => "Failed to write kernel image to guest memory",
                Error::ReadProgramHeader => "Failed to read ELF program header",
                Error::SeekKernelStart => {
                    "Failed to seek to file offset as pointed by the ELF program header"
                }
                Error::SeekElfStart => "Failed to seek to start of kernel image",
                Error::SeekProgramHeader => "Failed to seek to ELF program header",
            }
        )
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Loads a kernel from a vmlinux elf image to a slice
///
/// # Arguments
///
/// * `guest_mem` - The guest memory region the kernel is written to.
/// * `kernel_image` - Input vmlinux image.
/// * `start_address` - For x86_64, this is the start of the high memory. Kernel should reside above it.
///
/// Returns the entry address of the kernel.
pub fn load_kernel<F>(
    guest_mem: &GuestMemory,
    kernel_image: &mut F,
    start_address: usize,
) -> Result<GuestAddress>
where
    F: Read + Seek,
{
    let mut ehdr: elf::Elf64_Ehdr = Default::default();
    kernel_image
        .seek(SeekFrom::Start(0))
        .map_err(|_| Error::SeekElfStart)?;
    unsafe {
        // read_struct is safe when reading a POD struct.  It can be used and dropped without issue.
        sys_util::read_struct(kernel_image, &mut ehdr).map_err(|_| Error::ReadElfHeader)?;
    }

    // Sanity checks
    if ehdr.e_ident[elf::EI_MAG0 as usize] != elf::ELFMAG0 as u8
        || ehdr.e_ident[elf::EI_MAG1 as usize] != elf::ELFMAG1
        || ehdr.e_ident[elf::EI_MAG2 as usize] != elf::ELFMAG2
        || ehdr.e_ident[elf::EI_MAG3 as usize] != elf::ELFMAG3
    {
        return Err(Error::InvalidElfMagicNumber);
    }
    if ehdr.e_ident[elf::EI_DATA as usize] != elf::ELFDATA2LSB as u8 {
        return Err(Error::BigEndianElfOnLittle);
    }
    if ehdr.e_phentsize as usize != mem::size_of::<elf::Elf64_Phdr>() {
        return Err(Error::InvalidProgramHeaderSize);
    }
    if (ehdr.e_phoff as usize) < mem::size_of::<elf::Elf64_Ehdr>() {
        // If the program header is backwards, bail.
        return Err(Error::InvalidProgramHeaderOffset);
    }
    if (ehdr.e_entry as usize) < start_address {
        return Err(Error::InvalidEntryAddress);
    }

    kernel_image
        .seek(SeekFrom::Start(ehdr.e_phoff))
        .map_err(|_| Error::SeekProgramHeader)?;
    let phdrs: Vec<elf::Elf64_Phdr> = unsafe {
        // Reading the structs is safe for a slice of POD structs.
        sys_util::read_struct_slice(kernel_image, ehdr.e_phnum as usize)
            .map_err(|_| Error::ReadProgramHeader)?
    };

    // Read in each section pointed to by the program headers.
    for phdr in &phdrs {
        if (phdr.p_type & elf::PT_LOAD) == 0 || phdr.p_filesz == 0 {
            continue;
        }

        kernel_image
            .seek(SeekFrom::Start(phdr.p_offset))
            .map_err(|_| Error::SeekKernelStart)?;

        let mem_offset = GuestAddress(phdr.p_paddr as usize);
        if mem_offset.offset() < start_address {
            return Err(Error::InvalidProgramHeaderAddress);
        }

        guest_mem
            .read_to_memory(mem_offset, kernel_image, phdr.p_filesz as usize)
            .map_err(|_| Error::ReadKernelImage)?;
    }

    Ok(GuestAddress(ehdr.e_entry as usize))
}

/// Writes the command line string to the given memory slice.
///
/// # Arguments
///
/// * `guest_mem` - A u8 slice that will be partially overwritten by the command line.
/// * `guest_addr` - The address in `guest_mem` at which to load the command line.
/// * `cmdline` - The kernel command line.
pub fn load_cmdline(
    guest_mem: &GuestMemory,
    guest_addr: GuestAddress,
    cmdline: &CStr,
) -> Result<()> {
    let len = cmdline.to_bytes().len();
    if len == 0 {
        return Ok(());
    }

    let end = guest_addr
        .checked_add(len + 1)
        .ok_or(Error::CommandLineOverflow)?; // Extra for null termination.
    if end > guest_mem.end_addr() {
        return Err(Error::CommandLineOverflow)?;
    }

    guest_mem
        .write_slice_at_addr(cmdline.to_bytes_with_nul(), guest_addr)
        .map_err(|_| Error::CommandLineCopy)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use memory_model::{GuestAddress, GuestMemory};
    use std::io::Cursor;

    const MEM_SIZE: usize = 0x18_0000;

    fn create_guest_mem() -> GuestMemory {
        GuestMemory::new(&[(GuestAddress(0x0), MEM_SIZE)]).unwrap()
    }

    #[test]
    fn cmdline_overflow() {
        let gm = create_guest_mem();
        let cmdline_address = GuestAddress(MEM_SIZE - 5);
        assert_eq!(
            Err(Error::CommandLineOverflow),
            load_cmdline(
                &gm,
                cmdline_address,
                CStr::from_bytes_with_nul(b"12345\0").unwrap(),
            )
        );
    }

    #[test]
    fn cmdline_write_end() {
        let gm = create_guest_mem();
        let mut cmdline_address = GuestAddress(45);
        assert_eq!(
            Ok(()),
            load_cmdline(
                &gm,
                cmdline_address,
                CStr::from_bytes_with_nul(b"1234\0").unwrap(),
            )
        );
        let val: u8 = gm.read_obj_from_addr(cmdline_address).unwrap();
        assert_eq!(val, b'1');
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj_from_addr(cmdline_address).unwrap();
        assert_eq!(val, b'2');
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj_from_addr(cmdline_address).unwrap();
        assert_eq!(val, b'3');
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj_from_addr(cmdline_address).unwrap();
        assert_eq!(val, b'4');
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj_from_addr(cmdline_address).unwrap();
        assert_eq!(val, b'\0');
    }

    // Elf64 image that prints hello world on x86_64.
    fn make_elf_bin() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(include_bytes!("test_elf.bin"));
        v
    }

    #[test]
    fn load_elf() {
        let gm = create_guest_mem();
        let image = make_elf_bin();
        assert_eq!(
            Ok(GuestAddress(0x10_0000)),
            load_kernel(&gm, &mut Cursor::new(&image), 0)
        );
    }

    #[test]
    fn bad_magic() {
        let gm = create_guest_mem();
        let mut bad_image = make_elf_bin();
        bad_image[0x1] = 0x33;
        assert_eq!(
            Err(Error::InvalidElfMagicNumber),
            load_kernel(&gm, &mut Cursor::new(&bad_image), 0)
        );
    }

    #[test]
    fn bad_endian() {
        // Only little endian is supported
        let gm = create_guest_mem();
        let mut bad_image = make_elf_bin();
        bad_image[0x5] = 2;
        assert_eq!(
            Err(Error::BigEndianElfOnLittle),
            load_kernel(&gm, &mut Cursor::new(&bad_image), 0)
        );
    }

    #[test]
    fn bad_phoff() {
        // program header has to be past the end of the elf header
        let gm = create_guest_mem();
        let mut bad_image = make_elf_bin();
        bad_image[0x20] = 0x10;
        assert_eq!(
            Err(Error::InvalidProgramHeaderOffset),
            load_kernel(&gm, &mut Cursor::new(&bad_image), 0)
        );
    }
}
