// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Helper for loading a kernel image in the guest memory.

use std;
use std::fmt;
use std::io::{Read, Seek, SeekFrom};
use std::mem;

use sys_util;

#[allow(non_camel_case_types)]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
// Add here any other architecture that uses as kernel image an ELF file.
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
    SeekKernelImage,
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
                Error::SeekKernelImage => "Failed to seek to offset of kernel image",
                Error::SeekProgramHeader => "Failed to seek to ELF program header",
            }
        )
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
/// Loads a kernel from a vmlinux elf image using a given callback.
///
/// # Arguments
///
/// * `kernel_image` - Input vmlinux image.
/// * `start_address` - For x86_64, this is the start of the high memory. Kernel should reside above it.
/// * `write_to_memory` - Closure to write the contents of the image.
///                      The closure is called with the following arguments:
///                      dst-offset-in-guest-mem, src, size
///
/// Returns the entry address of the kernel.
pub fn load_kernel<R, F>(
    kernel_image: &mut R,
    start_address: usize,
    write_to_memory: F,
) -> Result<usize>
where
    R: Read + Seek,
    F: Fn(usize, &mut R, usize) -> Result<()>,
{
    let mut ehdr: elf::Elf64_Ehdr = Default::default();
    kernel_image
        .seek(SeekFrom::Start(0))
        .map_err(|_| Error::SeekKernelImage)?;
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

        if (phdr.p_paddr as usize) < start_address {
            return Err(Error::InvalidProgramHeaderAddress);
        }

        write_to_memory(phdr.p_paddr as usize, kernel_image, phdr.p_filesz as usize)?;
    }

    Ok(ehdr.e_entry as usize)
}

#[cfg(target_arch = "aarch64")]
/// Loads a kernel from a vmlinux image using a given callback.
///
/// # Arguments
///
/// * `kernel_image` - Input vmlinux image.
/// * `start_address` - Kernel start address in the guest memory.
/// * `write_to_memory` - Closure to write the contents of the image.
///                      The closure is called with the following arguments:
///                      dst-offset-in-guest-mem, src, size
///
/// Returns the entry address of the kernel.
pub fn load_kernel<R, F>(
    kernel_image: &mut R,
    start_address: usize,
    write_to_memory: F,
) -> Result<usize>
where
    R: Read + Seek,
    F: Fn(usize, &mut R, usize) -> Result<()>,
{
    /* Kernel boot protocol is specified in the kernel docs
    Documentation/arm/Booting and Documentation/arm64/booting.txt.

    ======aarch64 kernel header========
    u32 code0;			/* Executable code */
    u32 code1;			/* Executable code */
    u64 text_offset;		/* Image load offset, little endian */
    u64 image_size;		/* Effective Image size, little endian */
    u64 flags;			/* kernel flags, little endian */
    u64 res2	= 0;		/* reserved */
    u64 res3	= 0;		/* reserved */
    u64 res4	= 0;		/* reserved */
    u32 magic	= 0x644d5241;	/* Magic number, little endian, "ARM\x64" */
    u32 res5;			/* reserved (used for PE COFF offset) */
    ====================================
     */
    const AARCH64_KERNEL_LOAD_ADDR: usize = 0x80000;
    const AARCH64_MAGIC_NUMBER: u32 = 0x644d_5241;
    const AARCH64_MAGIC_OFFSET_HEADER: u64 =
        2 * mem::size_of::<u32>() as u64 + 6 * mem::size_of::<u64>() as u64; // This should total 56.
    const AARCH64_TEXT_OFFSET: u64 = 2 * mem::size_of::<u32>() as u64;
    let mut kernel_load_offset = AARCH64_KERNEL_LOAD_ADDR;

    /* Look for the magic number inside the elf header. */
    kernel_image
        .seek(SeekFrom::Start(AARCH64_MAGIC_OFFSET_HEADER))
        .map_err(|_| Error::SeekKernelImage)?;
    let mut magic_number: u32 = 0;
    unsafe {
        sys_util::read_struct(kernel_image, &mut magic_number)
            .map_err(|_| Error::ReadProgramHeader)?
    }
    if u32::from_le(magic_number) != AARCH64_MAGIC_NUMBER {
        return Err(Error::InvalidElfMagicNumber);
    }

    /* Look for the `text_offset` from the elf header. */
    kernel_image
        .seek(SeekFrom::Start(AARCH64_TEXT_OFFSET)) // This should total 8.
        .map_err(|_| Error::SeekKernelImage)?;
    let mut hdrvals: [u64; 2] = [0; 2];
    unsafe {
        /* `read_struct` is safe when reading a POD struct. It can be used and dropped without issue. */
        sys_util::read_struct(kernel_image, &mut hdrvals).map_err(|_| Error::ReadProgramHeader)?;
    }
    /* Following the boot protocol mentioned above. */
    if u64::from_le(hdrvals[1]) != 0 {
        kernel_load_offset = u64::from_le(hdrvals[0]) as usize;
    }
    /* Get the total size of kernel image. */
    let kernel_size = kernel_image
        .seek(SeekFrom::End(0))
        .map_err(|_| Error::SeekKernelImage)?;

    /* Last `seek` will leave the image with the cursor at its end, rewind it to start. */
    kernel_image
        .seek(SeekFrom::Start(0))
        .map_err(|_| Error::SeekKernelImage)?;

    kernel_load_offset = kernel_load_offset + start_address;
    write_to_memory(kernel_load_offset, kernel_image, kernel_size as usize)?;

    Ok(kernel_load_offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn make_test_bin() -> Vec<u8> {
        include_bytes!("test_elf.bin").to_vec()
    }

    #[cfg(target_arch = "aarch64")]
    fn make_test_bin() -> Vec<u8> {
        include_bytes!("test_pe.bin").to_vec()
    }

    #[test]
    // Tests that loading the kernel is successful on different archs.
    fn test_load_kernel() {
        let image = make_test_bin();
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        let load_addr = 0x10_0000;
        #[cfg(target_arch = "aarch64")]
        let load_addr = 0x8_0000;
        assert_eq!(
            Ok(load_addr),
            load_kernel(&mut Cursor::new(&image), 0, |_, _, _| Ok(()))
        );
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_load_bad_kernel() {
        let mut bad_image = make_test_bin();
        bad_image.truncate(56);
        assert_eq!(
            Err(Error::ReadProgramHeader),
            load_kernel(&mut Cursor::new(&bad_image), 0, |_, _, _| Ok(()))
        );
    }

    #[test]
    fn test_bad_kernel_magic() {
        let mut bad_image = make_test_bin();
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        let offset = 0x1;
        #[cfg(target_arch = "aarch64")]
        let offset = 0x38;
        bad_image[offset] = 0x33;
        assert_eq!(
            Err(Error::InvalidElfMagicNumber),
            load_kernel(&mut Cursor::new(&bad_image), 0, |_, _, _| Ok(()))
        );
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn test_bad_kernel_endian() {
        // Only little endian is supported.
        let mut bad_image = make_test_bin();
        bad_image[0x5] = 2;
        assert_eq!(
            Err(Error::BigEndianElfOnLittle),
            load_kernel(&mut Cursor::new(&bad_image), 0, |_, _, _| Ok(()))
        );
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn test_bad_kernel_phoff() {
        // program header has to be past the end of the elf header
        let mut bad_image = make_test_bin();
        bad_image[0x20] = 0x10;
        assert_eq!(
            Err(Error::InvalidProgramHeaderOffset),
            load_kernel(&mut Cursor::new(&bad_image), 0, |_, _, _| Ok(()))
        );
    }
}
