// Copyright © 2020, Oracle and/or its affiliates.
// Copyright (c) 2019 Intel Corporation. All rights reserved.
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! Traits and structs for loading elf image kernels into guest memory.

#![cfg(all(feature = "elf", any(target_arch = "x86", target_arch = "x86_64")))]

use std::fmt;
use std::io::{Read, Seek, SeekFrom};
use std::mem;
use std::result;

use vm_memory::{Address, ByteValued, Bytes, GuestAddress, GuestMemory, GuestUsize};

use crate::loader::{Error as KernelLoaderError, KernelLoader, KernelLoaderResult, Result};
use crate::loader_gen::elf;
pub use crate::loader_gen::start_info;

unsafe impl ByteValued for elf::Elf64_Ehdr {}
unsafe impl ByteValued for elf::Elf64_Nhdr {}
unsafe impl ByteValued for elf::Elf64_Phdr {}

#[derive(Debug, PartialEq, Eq)]
/// Elf kernel loader errors.
pub enum Error {
    /// Invalid alignment.
    Align,
    /// Loaded big endian binary on a little endian platform.
    BigEndianElfOnLittle,
    /// Invalid ELF magic number.
    InvalidElfMagicNumber,
    /// Invalid program header size.
    InvalidProgramHeaderSize,
    /// Invalid program header offset.
    InvalidProgramHeaderOffset,
    /// Invalid program header address.
    InvalidProgramHeaderAddress,
    /// Invalid entry address.
    InvalidEntryAddress,
    /// Overflow occurred during an arithmetic operation.
    Overflow,
    /// Unable to read ELF header.
    ReadElfHeader,
    /// Unable to read kernel image.
    ReadKernelImage,
    /// Unable to read program header.
    ReadProgramHeader,
    /// Unable to seek to kernel start.
    SeekKernelStart,
    /// Unable to seek to ELF start.
    SeekElfStart,
    /// Unable to seek to program header.
    SeekProgramHeader,
    /// Unable to seek to note header.
    SeekNoteHeader,
    /// Unable to read note header.
    ReadNoteHeader,
    /// Invalid PVH note.
    InvalidPvhNote,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let desc = match self {
            Error::Align => "Invalid alignment",
            Error::BigEndianElfOnLittle => {
                "Trying to load big-endian binary on little-endian machine"
            }
            Error::InvalidElfMagicNumber => "Invalid Elf magic number",
            Error::InvalidProgramHeaderSize => "Invalid program header size",
            Error::InvalidProgramHeaderOffset => "Invalid program header offset",
            Error::InvalidProgramHeaderAddress => "Invalid Program Header Address",
            Error::InvalidEntryAddress => "Invalid entry address",
            Error::Overflow => "Overflow occurred during an arithmetic operation",
            Error::ReadElfHeader => "Unable to read elf header",
            Error::ReadKernelImage => "Unable to read kernel image",
            Error::ReadProgramHeader => "Unable to read program header",
            Error::SeekKernelStart => "Unable to seek to kernel start",
            Error::SeekElfStart => "Unable to seek to elf start",
            Error::SeekProgramHeader => "Unable to seek to program header",
            Error::SeekNoteHeader => "Unable to seek to note header",
            Error::ReadNoteHeader => "Unable to read note header",
            Error::InvalidPvhNote => "Invalid PVH note header",
        };

        write!(f, "Kernel Loader: {}", desc)
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Availability of PVH entry point in the kernel, which allows the VMM
/// to use the PVH boot protocol to start guests.
pub enum PvhBootCapability {
    /// PVH entry point is present
    PvhEntryPresent(GuestAddress),
    /// PVH entry point is not present
    PvhEntryNotPresent,
    /// PVH entry point is ignored, even if available
    PvhEntryIgnored,
}

impl Default for PvhBootCapability {
    fn default() -> Self {
        PvhBootCapability::PvhEntryIgnored
    }
}

impl fmt::Display for PvhBootCapability {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::PvhBootCapability::*;
        match self {
            PvhEntryPresent(pvh_entry_addr) => write!(
                f,
                "PVH entry point present at guest address: {:#x}",
                pvh_entry_addr.raw_value()
            ),
            PvhEntryNotPresent => write!(f, "PVH entry point not present"),
            PvhEntryIgnored => write!(f, "PVH entry point ignored"),
        }
    }
}

/// Raw ELF (a.k.a. vmlinux) kernel image support.
pub struct Elf;

impl Elf {
    /// Verifies that magic numbers are present in the Elf header.
    fn validate_header(ehdr: &elf::Elf64_Ehdr) -> std::result::Result<(), Error> {
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
            return Err(Error::InvalidProgramHeaderOffset);
        }
        Ok(())
    }
}

impl KernelLoader for Elf {
    /// Loads a kernel from a vmlinux elf image into guest memory.
    ///
    /// By default, the kernel is loaded into guest memory at offset `phdr.p_paddr` specified
    /// by the elf image. When used, `kernel_offset` specifies a fixed offset from `phdr.p_paddr`
    /// at which to load the kernel. If `kernel_offset` is requested, the `pvh_entry_addr` field
    /// of the result will not be populated.
    ///
    /// # Arguments
    ///
    /// * `guest_mem`: [`GuestMemory`] to load the kernel in.
    /// * `kernel_offset`: Offset to be added to default kernel load address in guest memory.
    /// * `kernel_image` - Input vmlinux image.
    /// * `highmem_start_address`: Address where high memory starts.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # extern crate vm_memory;
    /// # use std::io::Cursor;
    /// # use linux_loader::loader::*;
    /// # use vm_memory::{Address, GuestAddress};
    /// # type GuestMemoryMmap = vm_memory::GuestMemoryMmap<()>;
    /// let mem_size: usize = 0x1000000;
    /// let himem_start = GuestAddress(0x0);
    /// let kernel_addr = GuestAddress(0x200000);
    /// let gm = GuestMemoryMmap::from_ranges(&[(GuestAddress(0x0), mem_size)]).unwrap();
    /// let mut kernel_image = vec![];
    /// kernel_image.extend_from_slice(include_bytes!("test_elf.bin"));
    /// elf::Elf::load(
    ///     &gm,
    ///     Some(kernel_addr),
    ///     &mut Cursor::new(&kernel_image),
    ///     Some(himem_start),
    /// )
    /// .unwrap();
    /// ```
    ///
    /// [`GuestMemory`]: https://docs.rs/vm-memory/latest/vm_memory/guest_memory/trait.GuestMemory.html
    fn load<F, M: GuestMemory>(
        guest_mem: &M,
        kernel_offset: Option<GuestAddress>,
        kernel_image: &mut F,
        highmem_start_address: Option<GuestAddress>,
    ) -> Result<KernelLoaderResult>
    where
        F: Read + Seek,
    {
        kernel_image
            .seek(SeekFrom::Start(0))
            .map_err(|_| Error::SeekElfStart)?;

        let mut ehdr = elf::Elf64_Ehdr::default();
        ehdr.as_bytes()
            .read_from(0, kernel_image, mem::size_of::<elf::Elf64_Ehdr>())
            .map_err(|_| Error::ReadElfHeader)?;

        // Sanity checks.
        Self::validate_header(&ehdr)?;
        if let Some(addr) = highmem_start_address {
            if (ehdr.e_entry as u64) < addr.raw_value() {
                return Err(Error::InvalidEntryAddress.into());
            }
        }

        let mut loader_result = KernelLoaderResult {
            kernel_load: match kernel_offset {
                Some(k_offset) => GuestAddress(
                    k_offset
                        .raw_value()
                        .checked_add(ehdr.e_entry as u64)
                        .ok_or(Error::Overflow)?,
                ),
                None => GuestAddress(ehdr.e_entry as u64),
            },
            ..Default::default()
        };

        kernel_image
            .seek(SeekFrom::Start(ehdr.e_phoff))
            .map_err(|_| Error::SeekProgramHeader)?;

        let phdr_sz = mem::size_of::<elf::Elf64_Phdr>();
        let mut phdrs: Vec<elf::Elf64_Phdr> = vec![];
        for _ in 0usize..ehdr.e_phnum as usize {
            let mut phdr = elf::Elf64_Phdr::default();
            phdr.as_bytes()
                .read_from(0, kernel_image, phdr_sz)
                .map_err(|_| Error::ReadProgramHeader)?;
            phdrs.push(phdr);
        }

        // Read in each section pointed to by the program headers.
        for phdr in phdrs {
            if phdr.p_type != elf::PT_LOAD || phdr.p_filesz == 0 {
                if phdr.p_type == elf::PT_NOTE {
                    // The PVH boot protocol currently requires that the kernel is loaded at
                    // the default kernel load address in guest memory (specified at kernel
                    // build time by the value of CONFIG_PHYSICAL_START). Therefore, only
                    // attempt to use PVH if an offset from the default load address has not
                    // been requested using the kernel_offset parameter.
                    if let Some(_offset) = kernel_offset {
                        loader_result.pvh_boot_cap = PvhBootCapability::PvhEntryIgnored;
                    } else {
                        // If kernel_offset is not requested, check if PVH entry point is present
                        loader_result.pvh_boot_cap = parse_elf_note(&phdr, kernel_image)?;
                    }
                }
                continue;
            }

            kernel_image
                .seek(SeekFrom::Start(phdr.p_offset))
                .map_err(|_| Error::SeekKernelStart)?;

            // if the vmm does not specify where the kernel should be loaded, just
            // load it to the physical address p_paddr for each segment.
            let mem_offset = match kernel_offset {
                Some(k_offset) => k_offset
                    .checked_add(phdr.p_paddr as u64)
                    .ok_or(Error::InvalidProgramHeaderAddress)?,
                None => GuestAddress(phdr.p_paddr as u64),
            };

            guest_mem
                .read_exact_from(mem_offset, kernel_image, phdr.p_filesz as usize)
                .map_err(|_| Error::ReadKernelImage)?;

            let kernel_end = mem_offset
                .raw_value()
                .checked_add(phdr.p_memsz as GuestUsize)
                .ok_or(KernelLoaderError::MemoryOverflow)?;
            loader_result.kernel_end = std::cmp::max(loader_result.kernel_end, kernel_end);
        }

        // elf image has no setup_header which is defined for bzImage
        loader_result.setup_header = None;

        Ok(loader_result)
    }
}

// Size of string "Xen", including the terminating NULL.
const PVH_NOTE_STR_SZ: usize = 4;

/// Examines a supplied elf program header of type `PT_NOTE` to determine if it contains an entry
/// of type `XEN_ELFNOTE_PHYS32_ENTRY` (0x12). Notes of this type encode a physical 32-bit entry
/// point address into the kernel, which is used when launching guests in 32-bit (protected) mode
/// with paging disabled, as described by the PVH boot protocol.
/// Returns the encoded entry point address, or `None` if no `XEN_ELFNOTE_PHYS32_ENTRY` entries
/// are found in the note header.
fn parse_elf_note<F>(phdr: &elf::Elf64_Phdr, kernel_image: &mut F) -> Result<PvhBootCapability>
where
    F: Read + Seek,
{
    // Type of note header that encodes a 32-bit entry point address to boot a guest kernel using
    // the PVH boot protocol.
    const XEN_ELFNOTE_PHYS32_ENTRY: u32 = 18;

    // Seek to the beginning of the note segment.
    kernel_image
        .seek(SeekFrom::Start(phdr.p_offset))
        .map_err(|_| Error::SeekNoteHeader)?;

    // Now that the segment has been found, we must locate an ELF note with the correct type that
    // encodes the PVH entry point if there is one.
    let mut nhdr: elf::Elf64_Nhdr = Default::default();
    let mut read_size: usize = 0;
    let nhdr_sz = mem::size_of::<elf::Elf64_Nhdr>();

    while read_size < phdr.p_filesz as usize {
        nhdr.as_bytes()
            .read_from(0, kernel_image, nhdr_sz)
            .map_err(|_| Error::ReadNoteHeader)?;

        // Check if the note header's name and type match the ones specified by the PVH ABI.
        if nhdr.n_type == XEN_ELFNOTE_PHYS32_ENTRY && nhdr.n_namesz as usize == PVH_NOTE_STR_SZ {
            let mut buf = [0u8; PVH_NOTE_STR_SZ];
            kernel_image
                .read_exact(&mut buf)
                .map_err(|_| Error::ReadNoteHeader)?;
            if buf == [b'X', b'e', b'n', b'\0'] {
                break;
            }
        }

        // Skip the note header plus the size of its fields (with alignment).
        let namesz_aligned = align_up(u64::from(nhdr.n_namesz), phdr.p_align)?;
        let descsz_aligned = align_up(u64::from(nhdr.n_descsz), phdr.p_align)?;

        // `namesz` and `descsz` are both `u32`s. We need to also verify for overflow, to be sure
        // we do not lose information.
        if namesz_aligned > u32::MAX.into() || descsz_aligned > u32::MAX.into() {
            return Err(Error::Overflow.into());
        }

        read_size = read_size
            .checked_add(nhdr_sz) // Skip the ELF_NOTE known sized fields.
            // Safe to truncate or change the type to `usize` (4 or 8 bytes depending on the
            // architecture 32/64 bits) since we validated that we do not lose information.
            .and_then(|read_size| read_size.checked_add(namesz_aligned as usize))
            .and_then(|read_size| read_size.checked_add(descsz_aligned as usize))
            .ok_or(Error::Overflow)?;

        kernel_image
            // The conversion here does not truncate, since `read_size` is of `usize` type, which
            // can be at maximum 8 bytes long.
            .seek(SeekFrom::Start(phdr.p_offset + read_size as u64))
            .map_err(|_| Error::SeekNoteHeader)?;
    }

    if read_size >= phdr.p_filesz as usize {
        // PVH ELF note not found, nothing else to do.
        return Ok(PvhBootCapability::PvhEntryNotPresent);
    }

    // Otherwise the correct note type was found.
    // The note header struct has already been read, so we can seek from the current position and
    // just skip the name field contents.
    kernel_image
        .seek(SeekFrom::Current(
            // Safe conversion since it is not losing data.
            align_up(u64::from(nhdr.n_namesz), phdr.p_align)? as i64 - PVH_NOTE_STR_SZ as i64,
        ))
        .map_err(|_| Error::SeekNoteHeader)?;

    // The PVH entry point is a 32-bit address, so the descriptor field must be capable of storing
    // all such addresses.
    if (nhdr.n_descsz as usize) < mem::size_of::<u32>() {
        return Err(Error::InvalidPvhNote.into());
    }

    let mut pvh_addr_bytes = [0; mem::size_of::<u32>()];

    // Read 32-bit address stored in the PVH note descriptor field.
    kernel_image
        .read_exact(&mut pvh_addr_bytes)
        .map_err(|_| Error::ReadNoteHeader)?;

    Ok(PvhBootCapability::PvhEntryPresent(GuestAddress(
        u32::from_le_bytes(pvh_addr_bytes).into(),
    )))
}

/// Align address upwards. Adapted from x86_64 crate:
/// https://docs.rs/x86_64/latest/x86_64/addr/fn.align_up.html
///
/// Returns the smallest x with alignment `align` so that x >= addr if the alignment is a power of
/// 2, or an error otherwise.
fn align_up(addr: u64, align: u64) -> result::Result<u64, Error> {
    if !align.is_power_of_two() {
        return Err(Error::Align);
    }
    let align_mask = align - 1;
    if addr & align_mask == 0 {
        Ok(addr) // already aligned
    } else {
        // Safe to unchecked add because this can be at maximum `2^64` - 1, which is not
        // overflowing.
        Ok((addr | align_mask) + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use vm_memory::{Address, GuestAddress};
    type GuestMemoryMmap = vm_memory::GuestMemoryMmap<()>;

    const MEM_SIZE: u64 = 0x100_0000;

    fn create_guest_mem() -> GuestMemoryMmap {
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0x0), (MEM_SIZE as usize))]).unwrap()
    }

    fn make_elf_bin() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(include_bytes!("test_elf.bin"));
        v
    }

    fn make_elfnote() -> Vec<u8> {
        include_bytes!("test_elfnote.bin").to_vec()
    }

    fn make_dummy_elfnote() -> Vec<u8> {
        include_bytes!("test_dummy_note.bin").to_vec()
    }

    fn make_invalid_pvh_note() -> Vec<u8> {
        include_bytes!("test_invalid_pvh_note.bin").to_vec()
    }

    fn make_bad_align() -> Vec<u8> {
        include_bytes!("test_bad_align.bin").to_vec()
    }

    #[test]
    fn test_load_elf() {
        let gm = create_guest_mem();
        let image = make_elf_bin();
        let kernel_addr = GuestAddress(0x200000);
        let mut highmem_start_address = GuestAddress(0x0);
        let mut loader_result = Elf::load(
            &gm,
            Some(kernel_addr),
            &mut Cursor::new(&image),
            Some(highmem_start_address),
        )
        .unwrap();
        assert_eq!(loader_result.kernel_load.raw_value(), 0x200400);

        loader_result = Elf::load(&gm, Some(kernel_addr), &mut Cursor::new(&image), None).unwrap();
        assert_eq!(loader_result.kernel_load.raw_value(), 0x200400);

        loader_result = Elf::load(
            &gm,
            None,
            &mut Cursor::new(&image),
            Some(highmem_start_address),
        )
        .unwrap();
        assert_eq!(loader_result.kernel_load.raw_value(), 0x400);

        highmem_start_address = GuestAddress(0xa00000);
        assert_eq!(
            Some(KernelLoaderError::Elf(Error::InvalidEntryAddress)),
            Elf::load(
                &gm,
                None,
                &mut Cursor::new(&image),
                Some(highmem_start_address)
            )
            .err()
        );
    }

    #[test]
    fn test_bad_magic_number() {
        let gm = create_guest_mem();
        let kernel_addr = GuestAddress(0x0);
        let mut bad_image = make_elf_bin();
        bad_image[0x1] = 0x33;
        assert_eq!(
            Some(KernelLoaderError::Elf(Error::InvalidElfMagicNumber)),
            Elf::load(&gm, Some(kernel_addr), &mut Cursor::new(&bad_image), None).err()
        );
    }

    #[test]
    fn test_bad_endian() {
        // Only little endian is supported.
        let gm = create_guest_mem();
        let kernel_addr = GuestAddress(0x0);
        let mut bad_image = make_elf_bin();
        bad_image[0x5] = 2;
        assert_eq!(
            Some(KernelLoaderError::Elf(Error::BigEndianElfOnLittle)),
            Elf::load(&gm, Some(kernel_addr), &mut Cursor::new(&bad_image), None).err()
        );
    }

    #[test]
    fn test_bad_phoff() {
        // Program header has to be past the end of the elf header.
        let gm = create_guest_mem();
        let kernel_addr = GuestAddress(0x0);
        let mut bad_image = make_elf_bin();
        bad_image[0x20] = 0x10;
        assert_eq!(
            Some(KernelLoaderError::Elf(Error::InvalidProgramHeaderOffset)),
            Elf::load(&gm, Some(kernel_addr), &mut Cursor::new(&bad_image), None).err()
        );
    }

    #[test]
    fn test_load_pvh() {
        let gm = create_guest_mem();
        let pvhnote_image = make_elfnote();
        let loader_result = Elf::load(&gm, None, &mut Cursor::new(&pvhnote_image), None).unwrap();
        assert_eq!(
            loader_result.pvh_boot_cap,
            PvhBootCapability::PvhEntryPresent(GuestAddress(0x1e1fe1f))
        );

        // Verify that PVH is ignored when kernel_start is requested
        let loader_result = Elf::load(
            &gm,
            Some(GuestAddress(0x0020_0000)),
            &mut Cursor::new(&pvhnote_image),
            None,
        )
        .unwrap();
        assert_eq!(
            loader_result.pvh_boot_cap,
            PvhBootCapability::PvhEntryIgnored
        );
    }

    #[test]
    fn test_dummy_elfnote() {
        let gm = create_guest_mem();
        let dummynote_image = make_dummy_elfnote();
        let loader_result = Elf::load(&gm, None, &mut Cursor::new(&dummynote_image), None).unwrap();
        assert_eq!(
            loader_result.pvh_boot_cap,
            PvhBootCapability::PvhEntryNotPresent
        );
    }

    #[test]
    fn test_bad_elfnote() {
        let gm = create_guest_mem();
        let badnote_image = make_invalid_pvh_note();
        assert_eq!(
            Some(KernelLoaderError::Elf(Error::InvalidPvhNote)),
            Elf::load(&gm, None, &mut Cursor::new(&badnote_image), None).err()
        );
    }

    #[test]
    fn test_bad_align() {
        let gm = GuestMemoryMmap::from_ranges(&[(GuestAddress(0x0), (0x1000_0000_usize))]).unwrap();
        let bad_align_image = make_bad_align();
        assert_eq!(
            Some(KernelLoaderError::Elf(Error::Align)),
            Elf::load(&gm, None, &mut Cursor::new(&bad_align_image), None).err()
        );
    }

    #[test]
    fn test_overflow_loadaddr() {
        let gm = create_guest_mem();
        let image = make_elf_bin();
        assert_eq!(
            Some(KernelLoaderError::Elf(Error::Overflow)),
            Elf::load(
                &gm,
                Some(GuestAddress(u64::MAX)),
                &mut Cursor::new(&image),
                None
            )
            .err()
        );
    }
}
