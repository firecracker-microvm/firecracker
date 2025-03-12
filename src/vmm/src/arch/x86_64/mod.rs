// Copyright © 2020, Oracle and/or its affiliates.
//
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

/// Logic for handling x86_64 CPU models.
pub mod cpu_model;
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
/// Logic for configuring XSTATE features.
pub mod xstate;

#[allow(missing_docs)]
pub mod generated;

use linux_loader::configurator::linux::LinuxBootConfigurator;
use linux_loader::configurator::pvh::PvhBootConfigurator;
use linux_loader::configurator::{BootConfigurator, BootParams};
use linux_loader::loader::bootparam::boot_params;
use linux_loader::loader::elf::start_info::{
    hvm_memmap_table_entry, hvm_modlist_entry, hvm_start_info,
};

use crate::arch::{BootProtocol, InitrdConfig, SYSTEM_MEM_SIZE, SYSTEM_MEM_START};
use crate::device_manager::resources::ResourceAllocator;
use crate::utils::u64_to_usize;
use crate::vstate::memory::{
    Address, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion,
};

// Value taken from https://elixir.bootlin.com/linux/v5.10.68/source/arch/x86/include/uapi/asm/e820.h#L31
// Usable normal RAM
const E820_RAM: u32 = 1;

// Reserved area that should be avoided during memory allocations
const E820_RESERVED: u32 = 2;
const MEMMAP_TYPE_RAM: u32 = 1;

/// Errors thrown while configuring x86_64 system.
#[derive(Debug, PartialEq, Eq, thiserror::Error, displaydoc::Display)]
pub enum ConfigurationError {
    /// Invalid e820 setup params.
    E820Configuration,
    /// Error writing MP table to memory: {0}
    MpTableSetup(#[from] mptable::MptableError),
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

const FIRST_ADDR_PAST_32BITS: u64 = 1 << 32;

/// Size of MMIO gap at top of 32-bit address space.
pub const MEM_32BIT_GAP_SIZE: u64 = 768 << 20;
/// The start of the memory area reserved for MMIO devices.
pub const MMIO_MEM_START: u64 = FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE;
/// The size of the memory area reserved for MMIO devices.
pub const MMIO_MEM_SIZE: u64 = MEM_32BIT_GAP_SIZE;

/// Returns a Vec of the valid memory addresses.
/// These should be used to configure the GuestMemoryMmap structure for the platform.
/// For x86_64 all addresses are valid from the start of the kernel except a
/// carve out at the end of 32bit address space.
pub fn arch_memory_regions(size: usize) -> Vec<(GuestAddress, usize)> {
    // It's safe to cast MMIO_MEM_START to usize because it fits in a u32 variable
    // (It points to an address in the 32 bit space).
    match size.checked_sub(usize::try_from(MMIO_MEM_START).unwrap()) {
        // case1: guest memory fits before the gap
        None | Some(0) => vec![(GuestAddress(0), size)],
        // case2: guest memory extends beyond the gap
        Some(remaining) => vec![
            (GuestAddress(0), usize::try_from(MMIO_MEM_START).unwrap()),
            (GuestAddress(FIRST_ADDR_PAST_32BITS), remaining),
        ],
    }
}

/// Returns the memory address where the kernel could be loaded.
pub fn get_kernel_start() -> u64 {
    layout::HIMEM_START
}

/// Returns the memory address where the initrd could be loaded.
pub fn initrd_load_addr(
    guest_mem: &GuestMemoryMmap,
    initrd_size: usize,
) -> Result<u64, ConfigurationError> {
    let first_region = guest_mem
        .find_region(GuestAddress::new(0))
        .ok_or(ConfigurationError::InitrdAddress)?;
    let lowmem_size = u64_to_usize(first_region.len());

    if lowmem_size < initrd_size {
        return Err(ConfigurationError::InitrdAddress);
    }

    let align_to_pagesize = |address| address & !(super::GUEST_PAGE_SIZE - 1);
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
    resource_allocator: &mut ResourceAllocator,
    cmdline_addr: GuestAddress,
    cmdline_size: usize,
    initrd: &Option<InitrdConfig>,
    num_cpus: u8,
    boot_prot: BootProtocol,
) -> Result<(), ConfigurationError> {
    // Note that this puts the mptable at the last 1k of Linux's 640k base RAM
    mptable::setup_mptable(guest_mem, resource_allocator, num_cpus)
        .map_err(ConfigurationError::MpTableSetup)?;

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
) -> Result<(), ConfigurationError> {
    const XEN_HVM_START_MAGIC_VALUE: u32 = 0x336e_c578;
    let first_addr_past_32bits = GuestAddress(FIRST_ADDR_PAST_32BITS);
    let end_32bit_gap_start = GuestAddress(MMIO_MEM_START);
    let himem_start = GuestAddress(layout::HIMEM_START);

    // Vector to hold modules (currently either empty or holding initrd).
    let mut modules: Vec<hvm_modlist_entry> = Vec::new();
    if let Some(initrd_config) = initrd {
        // The initrd has been written to guest memory already, here we just need to
        // create the module structure that describes it.
        modules.push(hvm_modlist_entry {
            paddr: initrd_config.address.raw_value(),
            size: initrd_config.size as u64,
            ..Default::default()
        });
    }

    // Vector to hold the memory maps which needs to be written to guest memory
    // at MEMMAP_START after all of the mappings are recorded.
    let mut memmap: Vec<hvm_memmap_table_entry> = Vec::new();

    // Create the memory map entries.
    memmap.push(hvm_memmap_table_entry {
        addr: 0,
        size: SYSTEM_MEM_START,
        type_: MEMMAP_TYPE_RAM,
        ..Default::default()
    });
    memmap.push(hvm_memmap_table_entry {
        addr: SYSTEM_MEM_START,
        size: SYSTEM_MEM_SIZE,
        type_: E820_RESERVED,
        ..Default::default()
    });
    let last_addr = guest_mem.last_addr();
    if last_addr < end_32bit_gap_start {
        memmap.push(hvm_memmap_table_entry {
            addr: himem_start.raw_value(),
            size: last_addr.unchecked_offset_from(himem_start) + 1,
            type_: MEMMAP_TYPE_RAM,
            ..Default::default()
        });
    } else {
        memmap.push(hvm_memmap_table_entry {
            addr: himem_start.raw_value(),
            size: end_32bit_gap_start.unchecked_offset_from(himem_start),
            type_: MEMMAP_TYPE_RAM,
            ..Default::default()
        });

        if last_addr > first_addr_past_32bits {
            memmap.push(hvm_memmap_table_entry {
                addr: first_addr_past_32bits.raw_value(),
                size: last_addr.unchecked_offset_from(first_addr_past_32bits) + 1,
                type_: MEMMAP_TYPE_RAM,
                ..Default::default()
            });
        }
    }

    // Construct the hvm_start_info structure and serialize it into
    // boot_params.  This will be stored at PVH_INFO_START address, and %rbx
    // will be initialized to contain PVH_INFO_START prior to starting the
    // guest, as required by the PVH ABI.
    #[allow(clippy::cast_possible_truncation)] // the vec lenghts are single digit integers
    let mut start_info = hvm_start_info {
        magic: XEN_HVM_START_MAGIC_VALUE,
        version: 1,
        cmdline_paddr: cmdline_addr.raw_value(),
        memmap_paddr: layout::MEMMAP_START,
        memmap_entries: memmap.len() as u32,
        nr_modules: modules.len() as u32,
        ..Default::default()
    };
    if !modules.is_empty() {
        start_info.modlist_paddr = layout::MODLIST_START;
    }
    let mut boot_params =
        BootParams::new::<hvm_start_info>(&start_info, GuestAddress(layout::PVH_INFO_START));

    // Copy the vector with the memmap table to the MEMMAP_START address
    // which is already saved in the memmap_paddr field of hvm_start_info struct.
    boot_params.set_sections::<hvm_memmap_table_entry>(&memmap, GuestAddress(layout::MEMMAP_START));

    // Copy the vector with the modules list to the MODLIST_START address.
    // Note that we only set the modlist_paddr address if there is a nonzero
    // number of modules, but serializing an empty list is harmless.
    boot_params.set_modules::<hvm_modlist_entry>(&modules, GuestAddress(layout::MODLIST_START));

    // Write the hvm_start_info struct to guest memory.
    PvhBootConfigurator::write_bootparams(&boot_params, guest_mem)
        .map_err(|_| ConfigurationError::StartInfoSetup)
}

fn configure_64bit_boot(
    guest_mem: &GuestMemoryMmap,
    cmdline_addr: GuestAddress,
    cmdline_size: usize,
    initrd: &Option<InitrdConfig>,
) -> Result<(), ConfigurationError> {
    const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
    const KERNEL_HDR_MAGIC: u32 = 0x5372_6448;
    const KERNEL_LOADER_OTHER: u8 = 0xff;
    const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x0100_0000; // Must be non-zero.
    let first_addr_past_32bits = GuestAddress(FIRST_ADDR_PAST_32BITS);
    let end_32bit_gap_start = GuestAddress(MMIO_MEM_START);

    let himem_start = GuestAddress(layout::HIMEM_START);

    // Set the location of RSDP in Boot Parameters to help the guest kernel find it faster.
    let mut params = boot_params {
        acpi_rsdp_addr: layout::RSDP_ADDR,
        ..Default::default()
    };

    params.hdr.type_of_loader = KERNEL_LOADER_OTHER;
    params.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC;
    params.hdr.header = KERNEL_HDR_MAGIC;
    params.hdr.cmd_line_ptr = u32::try_from(cmdline_addr.raw_value()).unwrap();
    params.hdr.cmdline_size = u32::try_from(cmdline_size).unwrap();
    params.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;
    if let Some(initrd_config) = initrd {
        params.hdr.ramdisk_image = u32::try_from(initrd_config.address.raw_value()).unwrap();
        params.hdr.ramdisk_size = u32::try_from(initrd_config.size).unwrap();
    }

    // We mark first [0x0, SYSTEM_MEM_START) region as usable RAM and the subsequent
    // [SYSTEM_MEM_START, (SYSTEM_MEM_START + SYSTEM_MEM_SIZE)) as reserved (note
    // SYSTEM_MEM_SIZE + SYSTEM_MEM_SIZE == HIMEM_START).
    add_e820_entry(&mut params, 0, layout::SYSTEM_MEM_START, E820_RAM)?;
    add_e820_entry(
        &mut params,
        layout::SYSTEM_MEM_START,
        layout::SYSTEM_MEM_SIZE,
        E820_RESERVED,
    )?;

    let last_addr = guest_mem.last_addr();
    if last_addr < end_32bit_gap_start {
        add_e820_entry(
            &mut params,
            himem_start.raw_value(),
            // it's safe to use unchecked_offset_from because
            // mem_end > himem_start
            last_addr.unchecked_offset_from(himem_start) + 1,
            E820_RAM,
        )?;
    } else {
        add_e820_entry(
            &mut params,
            himem_start.raw_value(),
            // it's safe to use unchecked_offset_from because
            // end_32bit_gap_start > himem_start
            end_32bit_gap_start.unchecked_offset_from(himem_start),
            E820_RAM,
        )?;

        if last_addr > first_addr_past_32bits {
            add_e820_entry(
                &mut params,
                first_addr_past_32bits.raw_value(),
                // it's safe to use unchecked_offset_from because
                // mem_end > first_addr_past_32bits
                last_addr.unchecked_offset_from(first_addr_past_32bits) + 1,
                E820_RAM,
            )?;
        }
    }

    LinuxBootConfigurator::write_bootparams(
        &BootParams::new(&params, GuestAddress(layout::ZERO_PAGE_START)),
        guest_mem,
    )
    .map_err(|_| ConfigurationError::ZeroPageSetup)
}

/// Add an e820 region to the e820 map.
/// Returns Ok(()) if successful, or an error if there is no space left in the map.
fn add_e820_entry(
    params: &mut boot_params,
    addr: u64,
    size: u64,
    mem_type: u32,
) -> Result<(), ConfigurationError> {
    if params.e820_entries as usize >= params.e820_table.len() {
        return Err(ConfigurationError::E820Configuration);
    }

    params.e820_table[params.e820_entries as usize].addr = addr;
    params.e820_table[params.e820_entries as usize].size = size;
    params.e820_table[params.e820_entries as usize].type_ = mem_type;
    params.e820_entries += 1;

    Ok(())
}

#[cfg(test)]
mod tests {
    use linux_loader::loader::bootparam::boot_e820_entry;

    use super::*;
    use crate::test_utils::{arch_mem, single_region_mem};

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
        let gm = single_region_mem(0x10000);
        let mut resource_allocator = ResourceAllocator::new().unwrap();
        let config_err = configure_system(
            &gm,
            &mut resource_allocator,
            GuestAddress(0),
            0,
            &None,
            1,
            BootProtocol::LinuxBoot,
        );
        assert_eq!(
            config_err.unwrap_err(),
            super::ConfigurationError::MpTableSetup(mptable::MptableError::NotEnoughMemory)
        );

        // Now assigning some memory that falls before the 32bit memory hole.
        let mem_size = 128 << 20;
        let gm = arch_mem(mem_size);
        let mut resource_allocator = ResourceAllocator::new().unwrap();
        configure_system(
            &gm,
            &mut resource_allocator,
            GuestAddress(0),
            0,
            &None,
            no_vcpus,
            BootProtocol::LinuxBoot,
        )
        .unwrap();
        configure_system(
            &gm,
            &mut resource_allocator,
            GuestAddress(0),
            0,
            &None,
            no_vcpus,
            BootProtocol::PvhBoot,
        )
        .unwrap();

        // Now assigning some memory that is equal to the start of the 32bit memory hole.
        let mem_size = 3328 << 20;
        let gm = arch_mem(mem_size);
        let mut resource_allocator = ResourceAllocator::new().unwrap();
        configure_system(
            &gm,
            &mut resource_allocator,
            GuestAddress(0),
            0,
            &None,
            no_vcpus,
            BootProtocol::LinuxBoot,
        )
        .unwrap();
        configure_system(
            &gm,
            &mut resource_allocator,
            GuestAddress(0),
            0,
            &None,
            no_vcpus,
            BootProtocol::PvhBoot,
        )
        .unwrap();

        // Now assigning some memory that falls after the 32bit memory hole.
        let mem_size = 3330 << 20;
        let gm = arch_mem(mem_size);
        let mut resource_allocator = ResourceAllocator::new().unwrap();
        configure_system(
            &gm,
            &mut resource_allocator,
            GuestAddress(0),
            0,
            &None,
            no_vcpus,
            BootProtocol::LinuxBoot,
        )
        .unwrap();
        configure_system(
            &gm,
            &mut resource_allocator,
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
        let e820_map = [(boot_e820_entry {
            addr: 0x1,
            size: 4,
            type_: 1,
        }); 128];

        let expected_params = boot_params {
            e820_table: e820_map,
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
            format!("{:?}", params.e820_table[0]),
            format!("{:?}", expected_params.e820_table[0])
        );
        assert_eq!(params.e820_entries, expected_params.e820_entries);

        // Exercise the scenario where the field storing the length of the e820 entry table is
        // is bigger than the allocated memory.
        params.e820_entries = u8::try_from(params.e820_table.len()).unwrap() + 1;
        assert!(
            add_e820_entry(
                &mut params,
                e820_map[0].addr,
                e820_map[0].size,
                e820_map[0].type_
            )
            .is_err()
        );
    }
}
