// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

mod gdt;
pub mod interrupts;
pub mod layout;
mod mptable;
pub mod regs;

use std::mem;

use super::HIMEM_START;
use arch_gen::x86::bootparam::{boot_params, E820_RAM};
use memory_model::{AddressRegionType, AddressSpace, GuestAddress, GuestMemory};

#[derive(Debug, PartialEq)]
pub enum Error {
    /// Invalid e820 setup params.
    E820Configuration,
    /// Error writing MP table to memory.
    MpTableSetup(mptable::Error),
    /// Failure in creating address space
    AddressSpaceSetup,
}

impl From<Error> for super::Error {
    fn from(e: Error) -> super::Error {
        super::Error::X86_64Setup(e)
    }
}

// Where BIOS/VGA magic would live on a real PC.
const EBDA_START: usize = 0x9fc00;
const FIRST_ADDR_PAST_32BITS: usize = (1 << 32);
const MEM_32BIT_GAP_SIZE: usize = (768 << 20);

/// Create the address space for the virtual machine.
/// These should be used to configure the GuestMemory structure for the platform.
/// For x86_64 all addresses are valid from the start of the kernel except a
/// carve out at the end of 32bit address space.
pub fn create_address_space(size: usize) -> Result<AddressSpace, Error> {
    let memory_gap_start = GuestAddress(FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE);
    let memory_gap_end = GuestAddress(FIRST_ADDR_PAST_32BITS);
    let requested_memory_size = GuestAddress(size);
    let mut address_space = AddressSpace::with_capacity(10);

    fn add_memory(
        address_space: &mut AddressSpace,
        base: GuestAddress,
        size: usize,
    ) -> Result<usize, Error> {
        address_space
            .add_default_memory(base, size)
            .map_err(|_| Error::AddressSpaceSetup)
    };

    // Guest memory is too small even no space for guest kernel
    if requested_memory_size <= GuestAddress(HIMEM_START) {
        return Err(Error::AddressSpaceSetup);
    }

    // Map memory below guest kernel, normal for boot info and BIOS
    add_memory(&mut address_space, GuestAddress(0), EBDA_START)?;
    address_space
        .add_region(
            AddressRegionType::BiosMemory,
            GuestAddress(EBDA_START),
            HIMEM_START - EBDA_START,
            None,
            0,
        )
        .map_err(|_| Error::AddressSpaceSetup)?;

    // case1: guest memory fits before the gap
    if requested_memory_size <= memory_gap_start {
        add_memory(
            &mut address_space,
            GuestAddress(HIMEM_START),
            size - HIMEM_START,
        )?;
    // case2: guest memory extends beyond the gap
    } else {
        // push memory before the gap
        add_memory(
            &mut address_space,
            GuestAddress(HIMEM_START),
            memory_gap_start.offset() - HIMEM_START,
        )?;
        add_memory(
            &mut address_space,
            memory_gap_end,
            requested_memory_size.offset_from(memory_gap_start),
        )?;
    }

    Ok(address_space)
}

/// X86 specific memory hole/memory mapped devices/reserved area.
pub fn get_32bit_gap_start() -> usize {
    FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE
}

/// Configures the system and should be called once per vm before starting vcpu threads.
///
/// # Arguments
///
/// * `boot_mem` - The memory used to boot the guest.
/// * `cmdline_addr` - Address in `guest_mem` where the kernel command line was loaded.
/// * `cmdline_size` - Size of the kernel command line in bytes including the null terminator.
/// * `num_cpus` - Number of virtual CPUs the guest will have.
pub fn configure_system(
    address_space: &AddressSpace,
    boot_mem: &GuestMemory,
    cmdline_addr: GuestAddress,
    cmdline_size: usize,
    num_cpus: u8,
) -> super::Result<()> {
    const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
    const KERNEL_HDR_MAGIC: u32 = 0x53726448;
    const KERNEL_LOADER_OTHER: u8 = 0xff;
    const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x1000000; // Must be non-zero.

    // Note that this puts the mptable at the last 1k of Linux's 640k base RAM
    mptable::setup_mptable(boot_mem, num_cpus).map_err(Error::MpTableSetup)?;

    let mut params: boot_params = Default::default();

    params.hdr.type_of_loader = KERNEL_LOADER_OTHER;
    params.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC;
    params.hdr.header = KERNEL_HDR_MAGIC;
    params.hdr.cmd_line_ptr = cmdline_addr.offset() as u32;
    params.hdr.cmdline_size = cmdline_size as u32;
    params.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;

    address_space
        .with_regions(|region| {
            let ty = region.get_type();
            if ty == AddressRegionType::DefaultMemory {
                add_e820_entry(
                    &mut params,
                    region.get_base().offset() as u64,
                    region.get_size() as u64,
                    E820_RAM,
                )?;
            }
            Ok(())
        })
        .map_err(|e: Error| e)?;

    let zero_page_addr = GuestAddress(layout::ZERO_PAGE_START);
    boot_mem
        .checked_offset(zero_page_addr, mem::size_of::<boot_params>())
        .ok_or(super::Error::ZeroPagePastRamEnd)?;
    boot_mem
        .write_obj_at_addr(params, zero_page_addr)
        .map_err(|_| super::Error::ZeroPageSetup)?;

    Ok(())
}

/// Add an e820 region to the e820 map.
/// Returns Ok(()) if successful, or an error if there is no space left in the map.
fn add_e820_entry(
    params: &mut boot_params,
    addr: u64,
    size: u64,
    mem_type: u32,
) -> Result<(), Error> {
    if params.e820_entries >= params.e820_map.len() as u8 {
        return Err(Error::E820Configuration);
    }

    params.e820_map[params.e820_entries as usize].addr = addr;
    params.e820_map[params.e820_entries as usize].size = size;
    params.e820_map[params.e820_entries as usize].type_ = mem_type;
    params.e820_entries += 1;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use arch_gen::x86::bootparam::e820entry;
    use memory_model::AddressRegionType;

    #[test]
    fn regions_lt_4gb() {
        let space = create_address_space(1usize << 29).unwrap();
        assert_eq!(3, space.len());

        let region = space.get_region(0).unwrap();
        assert_eq!(GuestAddress(0), region.get_base());
        assert_eq!(EBDA_START, region.get_size());

        let region = space.get_region(2).unwrap();
        assert_eq!(GuestAddress(HIMEM_START), region.get_base());
        assert_eq!((1usize << 29) - HIMEM_START, region.get_size());
    }

    #[test]
    fn regions_gt_4gb() {
        let space = create_address_space((1usize << 32) + 0x8000).unwrap();
        assert_eq!(4, space.len());

        let region = space.get_region(0).unwrap();
        assert_eq!(GuestAddress(0), region.get_base());
        let region = space.get_region(3).unwrap();
        assert_eq!(GuestAddress(1usize << 32), region.get_base());
    }

    #[test]
    fn test_32bit_gap() {
        assert_eq!(
            get_32bit_gap_start(),
            FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE
        );
    }

    #[test]
    fn test_system_configuration() {
        let no_vcpus = 4;
        let mem_types = [
            AddressRegionType::DefaultMemory,
            AddressRegionType::BiosMemory,
        ];

        // Too less memory
        let mem_size = HIMEM_START;
        match create_address_space(mem_size) {
            Err(Error::AddressSpaceSetup) => {}
            _ => panic!("should fail!"),
        }

        // Missing the BIOS memory area
        let mem_size = 128 << 20;
        let space = create_address_space(mem_size).unwrap();
        let gm = space
            .map_guest_memory(&[AddressRegionType::DefaultMemory])
            .unwrap();
        let config_err = configure_system(&space, &gm, GuestAddress(0), 0, 1);
        assert!(config_err.is_err());
        assert_eq!(
            config_err.unwrap_err(),
            super::super::Error::X86_64Setup(super::Error::MpTableSetup(
                mptable::Error::NotEnoughMemory
            ))
        );

        // Only the BIOS memory area
        let mem_size = 128 << 20;
        let space = create_address_space(mem_size).unwrap();
        let gm = space
            .map_guest_memory(&[AddressRegionType::BiosMemory])
            .unwrap();
        let config_err = configure_system(&space, &gm, GuestAddress(0), 0, 1);
        assert!(config_err.is_err());
        assert_eq!(
            config_err.unwrap_err(),
            super::super::Error::ZeroPagePastRamEnd
        );

        // Now assigning some memory that falls before the 32bit memory hole.
        let mem_size = 128 << 20;
        let space = create_address_space(mem_size).unwrap();
        let gm = space.map_guest_memory(&mem_types).unwrap();
        configure_system(&space, &gm, GuestAddress(0), 0, no_vcpus).unwrap();

        // Now assigning some memory that is equal to the start of the 32bit memory hole.
        let mem_size = 3328 << 20;
        let space = create_address_space(mem_size).unwrap();
        let gm = space.map_guest_memory(&mem_types).unwrap();
        configure_system(&space, &gm, GuestAddress(0), 0, no_vcpus).unwrap();

        // Now assigning some memory that falls after the 32bit memory hole.
        let mem_size = 3330 << 20;
        let space = create_address_space(mem_size).unwrap();
        let gm = space.map_guest_memory(&mem_types).unwrap();
        configure_system(&space, &gm, GuestAddress(0), 0, no_vcpus).unwrap();
    }

    #[test]
    fn test_add_e820_entry() {
        let e820_map = [(e820entry {
            addr: 0x1,
            size: 4,
            type_: 1,
        }); 128];

        let expected_params = boot_params {
            e820_map,
            e820_entries: 1,
            ..Default::default()
        };

        let mut params: boot_params = Default::default();
        add_e820_entry(
            &mut params,
            e820_map[0].addr,
            e820_map[0].size,
            e820_map[0].type_,
        )
        .unwrap();
        assert_eq!(
            format!("{:?}", params.e820_map[0]),
            format!("{:?}", expected_params.e820_map[0])
        );
        assert_eq!(params.e820_entries, expected_params.e820_entries);

        // Exercise the scenario where the field storing the length of the e820 entry table is
        // is bigger than the allocated memory.
        params.e820_entries = params.e820_map.len() as u8 + 1;
        assert!(add_e820_entry(
            &mut params,
            e820_map[0].addr,
            e820_map[0].size,
            e820_map[0].type_
        )
        .is_err());
    }
}
