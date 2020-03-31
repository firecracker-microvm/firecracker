// Copyright © 2020, Oracle and/or its affiliates.
//
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

mod gdt;
/// Contains logic for setting up Advanced Programmable Interrupt Controller (local version).
pub mod interrupts;
/// Layout for the x86_64 system.
pub mod layout;
mod mptable;
/// Logic for configuring x86_64 model specific registers (MSRs).
pub mod msr;
/// Logic for configuring x86_64 registers.
pub mod regs;

use arch_gen::x86::bootparam::{boot_params, E820_RAM};
use arch_gen::x86::start_info::{hvm_memmap_table_entry, hvm_modlist_entry, hvm_start_info};
use std::mem;
use vm_memory::{
    Address, ByteValued, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion,
};
use BootProtocol;
use InitrdConfig;

// This is a workaround to the Rust enforcement specifying that any implementation of a foreign
// trait (in this case `ByteValued`) where:
// *    the type that is implementing the trait is foreign or
// *    all of the parameters being passed to the trait (if there are any) are also foreign
// is prohibited.
#[derive(Copy, Clone, Default)]
struct BootParamsWrapper(boot_params);

// It is safe to initialize BootParamsWrap which is a wrapper over `boot_params` (a series of ints).
unsafe impl ByteValued for BootParamsWrapper {}

// Workaround for the Rust orphan rules that guarantee trait coherence by wrapping the foreign type
// in a tuple structure. Same approach is used by boot_params and BootParamsWrapper.
#[derive(Copy, Clone, Default)]
struct StartInfoWrapper(hvm_start_info);

#[derive(Copy, Clone, Default)]
struct MemmapTableEntryWrapper(hvm_memmap_table_entry);

#[derive(Copy, Clone, Default)]
struct ModlistEntryWrapper(hvm_modlist_entry);

// It is safe to initialize the following structures. They are wrappers over the structures
// defined by the start_info module, all of which are formed by fields of integer values.
unsafe impl ByteValued for StartInfoWrapper {}
unsafe impl ByteValued for MemmapTableEntryWrapper {}
unsafe impl ByteValued for ModlistEntryWrapper {}

const MEMMAP_TYPE_RAM: u32 = 1;

/// Errors thrown while configuring x86_64 system.
#[derive(Debug, PartialEq)]
pub enum Error {
    /// Invalid e820 setup params.
    E820Configuration,
    /// Error writing MP table to memory.
    MpTableSetup(mptable::Error),
    /// Error writing the zero page of guest memory.
    ZeroPageSetup,
    /// Failed to compute initrd address.
    InitrdAddress,
    /// Error writing module entry to guest memory.
    ModlistSetup,
    /// Error writing memory map table to guest memory.
    MemmapTableSetup,
    /// Error writing hvm_start_info to guest memory.
    StartInfoSetup,
}

// Where BIOS/VGA magic would live on a real PC.
const EBDA_START: u64 = 0x9fc00;
const FIRST_ADDR_PAST_32BITS: u64 = (1 << 32);
const MEM_32BIT_GAP_SIZE: u64 = (768 << 20);
/// The start of the memory area reserved for MMIO devices.
pub const MMIO_MEM_START: u64 = FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE;

/// Returns a Vec of the valid memory addresses.
/// These should be used to configure the GuestMemoryMmap structure for the platform.
/// For x86_64 all addresses are valid from the start of the kernel except a
/// carve out at the end of 32bit address space.
pub fn arch_memory_regions(size: usize) -> Vec<(GuestAddress, usize)> {
    // It's safe to cast MMIO_MEM_START to usize because it fits in a u32 variable
    // (It points to an address in the 32 bit space).
    match size.checked_sub(MMIO_MEM_START as usize) {
        // case1: guest memory fits before the gap
        None | Some(0) => vec![(GuestAddress(0), size)],
        // case2: guest memory extends beyond the gap
        Some(remaining) => vec![
            (GuestAddress(0), MMIO_MEM_START as usize),
            (GuestAddress(FIRST_ADDR_PAST_32BITS), remaining),
        ],
    }
}

/// Returns the memory address where the kernel could be loaded.
pub fn get_kernel_start() -> u64 {
    layout::HIMEM_START
}

/// Returns the memory address where the initrd could be loaded.
pub fn initrd_load_addr(guest_mem: &GuestMemoryMmap, initrd_size: usize) -> super::Result<u64> {
    let first_region = guest_mem
        .find_region(GuestAddress::new(0))
        .ok_or(Error::InitrdAddress)?;
    // It's safe to cast to usize because the size of a region can't be greater than usize.
    let lowmem_size = first_region.len() as usize;

    if lowmem_size < initrd_size {
        return Err(Error::InitrdAddress);
    }

    let align_to_pagesize = |address| address & !(super::PAGE_SIZE - 1);
    Ok(align_to_pagesize(lowmem_size - initrd_size) as u64)
}

/// Configures the system and should be called once per vm before starting vcpu threads.
///
/// # Arguments
///
/// * `guest_mem` - The memory to be used by the guest.
/// * `cmdline_addr` - Address in `guest_mem` where the kernel command line was loaded.
/// * `cmdline_size` - Size of the kernel command line in bytes including the null terminator.
/// * `initrd` - Information about where the ramdisk image was loaded in the `guest_mem`.
/// * `num_cpus` - Number of virtual CPUs the guest will have.
/// * `boot_prot` - Boot protocol that will be used to boot the guest.
pub fn configure_system(
    guest_mem: &GuestMemoryMmap,
    cmdline_addr: GuestAddress,
    cmdline_size: usize,
    initrd: &Option<InitrdConfig>,
    num_cpus: u8,
    boot_prot: BootProtocol,
) -> super::Result<()> {
    // Note that this puts the mptable at the last 1k of Linux's 640k base RAM
    mptable::setup_mptable(guest_mem, num_cpus).map_err(Error::MpTableSetup)?;

    match boot_prot {
        BootProtocol::PvhBoot => {
            configure_pvh(guest_mem, cmdline_addr, initrd)?;
        }
        BootProtocol::LinuxBoot => {
            configure_64bit_boot(guest_mem, cmdline_addr, cmdline_size, initrd)?;
        }
    }

    Ok(())
}

fn configure_pvh(
    guest_mem: &GuestMemoryMmap,
    cmdline_addr: GuestAddress,
    initrd: &Option<InitrdConfig>,
) -> super::Result<()> {
    const XEN_HVM_START_MAGIC_VALUE: u32 = 0x336e_c578;
    let first_addr_past_32bits = GuestAddress(FIRST_ADDR_PAST_32BITS);
    let end_32bit_gap_start = GuestAddress(MMIO_MEM_START);
    let himem_start = GuestAddress(layout::HIMEM_START);

    let mut start_info: StartInfoWrapper = StartInfoWrapper(hvm_start_info::default());

    start_info.0.magic = XEN_HVM_START_MAGIC_VALUE;
    start_info.0.version = 1; // pvh has version 1
    start_info.0.cmdline_paddr = cmdline_addr.raw_value();
    start_info.0.memmap_paddr = layout::MEMMAP_START;

    if let Some(initrd_config) = initrd {
        // The initrd has been written to guest memory already, here we just need to
        // create the module structure that describes it.
        let ramdisk_mod: ModlistEntryWrapper = ModlistEntryWrapper(hvm_modlist_entry {
            paddr: initrd_config.address.raw_value(),
            size: initrd_config.size as u64,
            ..Default::default()
        });

        start_info.0.nr_modules += 1;
        start_info.0.modlist_paddr = layout::MODLIST_START;

        // Write the modlist struct to guest memory.
        guest_mem
            .write_obj(ramdisk_mod, GuestAddress(layout::MODLIST_START))
            .map_err(|_| Error::ModlistSetup)?;
    }

    // Vector to hold the memory maps which needs to be written to guest memory
    // at MEMMAP_START after all of the mappings are recorded.
    let mut memmap: Vec<hvm_memmap_table_entry> = Vec::new();

    // Create the memory map entries.
    add_memmap_entry(&mut memmap, 0, EBDA_START, MEMMAP_TYPE_RAM)?;

    let last_addr = guest_mem.last_addr();
    if last_addr < end_32bit_gap_start {
        add_memmap_entry(
            &mut memmap,
            himem_start.raw_value() as u64,
            last_addr.unchecked_offset_from(himem_start) as u64 + 1,
            MEMMAP_TYPE_RAM,
        )?;
    } else {
        add_memmap_entry(
            &mut memmap,
            himem_start.raw_value(),
            end_32bit_gap_start.unchecked_offset_from(himem_start),
            MEMMAP_TYPE_RAM,
        )?;

        if last_addr > first_addr_past_32bits {
            add_memmap_entry(
                &mut memmap,
                first_addr_past_32bits.raw_value(),
                last_addr.unchecked_offset_from(first_addr_past_32bits) + 1,
                MEMMAP_TYPE_RAM,
            )?;
        }
    }

    start_info.0.memmap_entries = memmap.len() as u32;

    // Copy the vector with the memmap table to the MEMMAP_START address
    // which is already saved in the memmap_paddr field of hvm_start_info struct.
    let mut memmap_start_addr = GuestAddress(layout::MEMMAP_START);

    // For every entry in the memmap vector, create a MemmapTableEntryWrapper
    // and write it to guest memory.
    for memmap_entry in memmap {
        let map_entry_wrapper: MemmapTableEntryWrapper = MemmapTableEntryWrapper(memmap_entry);

        guest_mem
            .write_obj(map_entry_wrapper, memmap_start_addr)
            .map_err(|_| Error::MemmapTableSetup)?;
        memmap_start_addr =
            memmap_start_addr.unchecked_add(mem::size_of::<hvm_memmap_table_entry>() as u64);
    }

    // The hvm_start_info struct itself must be stored at PVH_START_INFO
    // address, and %rbx will be initialized to contain PVH_INFO_START prior to
    // starting the guest, as required by the PVH ABI.
    let start_info_addr = GuestAddress(layout::PVH_INFO_START);

    // Write the start_info struct to guest memory.
    guest_mem
        .write_obj(start_info, start_info_addr)
        .map_err(|_| Error::StartInfoSetup)?;

    Ok(())
}

fn add_memmap_entry(
    memmap: &mut Vec<hvm_memmap_table_entry>,
    addr: u64,
    size: u64,
    mem_type: u32,
) -> super::Result<()> {
    // Add the table entry to the vector
    memmap.push(hvm_memmap_table_entry {
        addr,
        size,
        type_: mem_type,
        reserved: 0,
    });

    Ok(())
}

fn configure_64bit_boot(
    guest_mem: &GuestMemoryMmap,
    cmdline_addr: GuestAddress,
    cmdline_size: usize,
    initrd: &Option<InitrdConfig>,
) -> super::Result<()> {
    const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
    const KERNEL_HDR_MAGIC: u32 = 0x5372_6448;
    const KERNEL_LOADER_OTHER: u8 = 0xff;
    const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x0100_0000; // Must be non-zero.
    let first_addr_past_32bits = GuestAddress(FIRST_ADDR_PAST_32BITS);
    let end_32bit_gap_start = GuestAddress(MMIO_MEM_START);

    let himem_start = GuestAddress(layout::HIMEM_START);

    let mut params: BootParamsWrapper = BootParamsWrapper(boot_params::default());

    params.0.hdr.type_of_loader = KERNEL_LOADER_OTHER;
    params.0.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC;
    params.0.hdr.header = KERNEL_HDR_MAGIC;
    params.0.hdr.cmd_line_ptr = cmdline_addr.raw_value() as u32;
    params.0.hdr.cmdline_size = cmdline_size as u32;
    params.0.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;
    if let Some(initrd_config) = initrd {
        params.0.hdr.ramdisk_image = initrd_config.address.raw_value() as u32;
        params.0.hdr.ramdisk_size = initrd_config.size as u32;
    }

    add_e820_entry(&mut params.0, 0, EBDA_START, E820_RAM)?;

    let last_addr = guest_mem.last_addr();
    if last_addr < end_32bit_gap_start {
        add_e820_entry(
            &mut params.0,
            himem_start.raw_value() as u64,
            // it's safe to use unchecked_offset_from because
            // mem_end > himem_start
            last_addr.unchecked_offset_from(himem_start) as u64 + 1,
            E820_RAM,
        )?;
    } else {
        add_e820_entry(
            &mut params.0,
            himem_start.raw_value(),
            // it's safe to use unchecked_offset_from because
            // end_32bit_gap_start > himem_start
            end_32bit_gap_start.unchecked_offset_from(himem_start),
            E820_RAM,
        )?;

        if last_addr > first_addr_past_32bits {
            add_e820_entry(
                &mut params.0,
                first_addr_past_32bits.raw_value(),
                // it's safe to use unchecked_offset_from because
                // mem_end > first_addr_past_32bits
                last_addr.unchecked_offset_from(first_addr_past_32bits) + 1,
                E820_RAM,
            )?;
        }
    }

    let zero_page_addr = GuestAddress(layout::ZERO_PAGE_START);
    guest_mem
        .write_obj(params, zero_page_addr)
        .map_err(|_| Error::ZeroPageSetup)?;

    Ok(())
}

/// Add an e820 region to the e820 map.
/// Returns Ok(()) if successful, or an error if there is no space left in the map.
fn add_e820_entry(
    params: &mut boot_params,
    addr: u64,
    size: u64,
    mem_type: u32,
) -> super::Result<()> {
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

    #[test]
    fn regions_lt_4gb() {
        let regions = arch_memory_regions(1usize << 29);
        assert_eq!(1, regions.len());
        assert_eq!(GuestAddress(0), regions[0].0);
        assert_eq!(1usize << 29, regions[0].1);
    }

    #[test]
    fn regions_gt_4gb() {
        let regions = arch_memory_regions((1usize << 32) + 0x8000);
        assert_eq!(2, regions.len());
        assert_eq!(GuestAddress(0), regions[0].0);
        assert_eq!(GuestAddress(1u64 << 32), regions[1].0);
    }

    #[test]
    fn test_system_configuration() {
        let no_vcpus = 4;
        let gm = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let config_err =
            configure_system(&gm, GuestAddress(0), 0, &None, 1, BootProtocol::LinuxBoot);
        assert!(config_err.is_err());
        assert_eq!(
            config_err.unwrap_err(),
            super::Error::MpTableSetup(mptable::Error::NotEnoughMemory)
        );

        // Now assigning some memory that falls before the 32bit memory hole.
        let mem_size = 128 << 20;
        let arch_mem_regions = arch_memory_regions(mem_size);
        let gm = GuestMemoryMmap::from_ranges(&arch_mem_regions).unwrap();
        configure_system(
            &gm,
            GuestAddress(0),
            0,
            &None,
            no_vcpus,
            BootProtocol::LinuxBoot,
        )
        .unwrap();

        configure_system(
            &gm,
            GuestAddress(0),
            0,
            &None,
            no_vcpus,
            BootProtocol::PvhBoot,
        )
        .unwrap();

        // Now assigning some memory that is equal to the start of the 32bit memory hole.
        let mem_size = 3328 << 20;
        let arch_mem_regions = arch_memory_regions(mem_size);
        let gm = GuestMemoryMmap::from_ranges(&arch_mem_regions).unwrap();
        configure_system(
            &gm,
            GuestAddress(0),
            0,
            &None,
            no_vcpus,
            BootProtocol::LinuxBoot,
        )
        .unwrap();

        configure_system(
            &gm,
            GuestAddress(0),
            0,
            &None,
            no_vcpus,
            BootProtocol::PvhBoot,
        )
        .unwrap();

        // Now assigning some memory that falls after the 32bit memory hole.
        let mem_size = 3330 << 20;
        let arch_mem_regions = arch_memory_regions(mem_size);
        let gm = GuestMemoryMmap::from_ranges(&arch_mem_regions).unwrap();
        configure_system(
            &gm,
            GuestAddress(0),
            0,
            &None,
            no_vcpus,
            BootProtocol::LinuxBoot,
        )
        .unwrap();

        configure_system(
            &gm,
            GuestAddress(0),
            0,
            &None,
            no_vcpus,
            BootProtocol::PvhBoot,
        )
        .unwrap();
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

    #[test]
    fn test_add_memmap_entry() {
        const MEMMAP_TYPE_RESERVED: u32 = 2;

        let mut memmap: Vec<hvm_memmap_table_entry> = Vec::new();

        let expected_memmap = vec![
            hvm_memmap_table_entry {
                addr: 0x0,
                size: 0x1000,
                type_: MEMMAP_TYPE_RAM,
                ..Default::default()
            },
            hvm_memmap_table_entry {
                addr: 0x10000,
                size: 0xa000,
                type_: MEMMAP_TYPE_RESERVED,
                ..Default::default()
            },
        ];

        add_memmap_entry(&mut memmap, 0, 0x1000, MEMMAP_TYPE_RAM).unwrap();
        add_memmap_entry(&mut memmap, 0x10000, 0xa000, MEMMAP_TYPE_RESERVED).unwrap();

        assert_eq!(format!("{:?}", memmap), format!("{:?}", expected_memmap));
    }
}
