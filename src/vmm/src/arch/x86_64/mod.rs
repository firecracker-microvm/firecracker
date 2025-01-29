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
/// Architecture specific KVM-related code
pub mod kvm;
/// Layout for the x86_64 system.
pub mod layout;
mod mptable;
/// Logic for configuring x86_64 model specific registers (MSRs).
pub mod msr;
/// Logic for configuring x86_64 registers.
pub mod regs;
/// Architecture specific vCPU code
pub mod vcpu;
/// Architecture specific VM state code
pub mod vm;
/// Logic for configuring XSTATE features.
pub mod xstate;

#[allow(missing_docs)]
pub mod generated;

use std::fs::File;

use layout::CMDLINE_START;
use linux_loader::configurator::linux::LinuxBootConfigurator;
use linux_loader::configurator::pvh::PvhBootConfigurator;
use linux_loader::configurator::{BootConfigurator, BootParams};
use linux_loader::loader::bootparam::boot_params;
use linux_loader::loader::elf::Elf as Loader;
use linux_loader::loader::elf::start_info::{
    hvm_memmap_table_entry, hvm_modlist_entry, hvm_start_info,
};
use linux_loader::loader::{Cmdline, KernelLoader, PvhBootCapability, load_cmdline};
use log::debug;

use super::EntryPoint;
use crate::acpi::create_acpi_tables;
use crate::arch::{BootProtocol, SYSTEM_MEM_SIZE, SYSTEM_MEM_START};
use crate::cpu_config::templates::{CustomCpuTemplate, GuestConfigError};
use crate::cpu_config::x86_64::CpuConfiguration;
use crate::initrd::InitrdConfig;
use crate::utils::{align_down, mib_to_bytes, u64_to_usize, usize_to_u64};
use crate::vmm_config::machine_config::MachineConfig;
use crate::vstate::memory::{
    Address, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion,
};
use crate::vstate::vcpu::KvmVcpuConfigureError;
use crate::{Vcpu, VcpuConfig, Vmm};

// Value taken from https://elixir.bootlin.com/linux/v5.10.68/source/arch/x86/include/uapi/asm/e820.h#L31
// Usable normal RAM
const E820_RAM: u32 = 1;

// Reserved area that should be avoided during memory allocations
const E820_RESERVED: u32 = 2;
const MEMMAP_TYPE_RAM: u32 = 1;

/// Errors thrown while configuring x86_64 system.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ConfigurationError {
    /// Invalid e820 setup params.
    E820Configuration,
    /// Error writing MP table to memory: {0}
    MpTableSetup(#[from] mptable::MptableError),
    /// Error writing the zero page of guest memory.
    ZeroPageSetup,
    /// Error writing module entry to guest memory.
    ModlistSetup,
    /// Error writing memory map table to guest memory.
    MemmapTableSetup,
    /// Error writing hvm_start_info to guest memory.
    StartInfoSetup,
    /// Cannot copy kernel file fd
    KernelFile,
    /// Cannot load kernel due to invalid memory configuration or invalid kernel image: {0}
    KernelLoader(linux_loader::loader::Error),
    /// Cannot load command line string: {0}
    LoadCommandline(linux_loader::loader::Error),
    /// Failed to create guest config: {0}
    CreateGuestConfig(#[from] GuestConfigError),
    /// Error configuring the vcpu for boot: {0}
    VcpuConfigure(#[from] KvmVcpuConfigureError),
    /// Error configuring ACPI: {0}
    Acpi(#[from] crate::acpi::AcpiError),
}

/// First address that cannot be addressed using 32 bit anymore.
pub const FIRST_ADDR_PAST_32BITS: u64 = 1 << 32;

/// Size of MMIO gap at top of 32-bit address space.
pub const MEM_32BIT_GAP_SIZE: u64 = mib_to_bytes(768) as u64;
/// The start of the memory area reserved for MMIO devices.
pub const MMIO_MEM_START: u64 = FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE;
/// The size of the memory area reserved for MMIO devices.
pub const MMIO_MEM_SIZE: u64 = MEM_32BIT_GAP_SIZE;

/// Returns a Vec of the valid memory addresses.
/// These should be used to configure the GuestMemoryMmap structure for the platform.
/// For x86_64 all addresses are valid from the start of the kernel except a
/// carve out at the end of 32bit address space.
pub fn arch_memory_regions(offset: usize, size: usize) -> Vec<(GuestAddress, usize)> {
    // If we get here with size == 0 something has seriously gone wrong. Firecracker should never
    // try to allocate guest memory of size 0
    assert!(size > 0, "Attempt to allocate guest memory of length 0");
    assert!(
        offset.checked_add(size).is_some(),
        "Attempt to allocate guest memory such that the address space would wrap around"
    );

    // It's safe to cast MMIO_MEM_START to usize because it fits in a u32 variable
    // (It points to an address in the 32 bit space).
    match (size + offset).checked_sub(u64_to_usize(MMIO_MEM_START)) {
        // case1: guest memory fits before the gap
        None | Some(0) => vec![(GuestAddress(offset as u64), size)],
        // case2: starts before the gap, but doesn't completely fit
        Some(remaining) if (offset as u64) < MMIO_MEM_START => vec![
            (
                GuestAddress(offset as u64),
                u64_to_usize(MMIO_MEM_START) - offset,
            ),
            (GuestAddress(FIRST_ADDR_PAST_32BITS), remaining),
        ],
        // case3: guest memory start after the gap
        Some(_) => vec![(
            GuestAddress(FIRST_ADDR_PAST_32BITS.max(offset as u64)),
            size,
        )],
    }
}

/// Returns the memory address where the kernel could be loaded.
pub fn get_kernel_start() -> u64 {
    layout::HIMEM_START
}

/// Returns the memory address where the initrd could be loaded.
pub fn initrd_load_addr(guest_mem: &GuestMemoryMmap, initrd_size: usize) -> Option<u64> {
    let first_region = guest_mem.find_region(GuestAddress::new(0))?;
    let lowmem_size = u64_to_usize(first_region.len());

    if lowmem_size < initrd_size {
        return None;
    }

    Some(align_down(
        usize_to_u64(lowmem_size - initrd_size),
        usize_to_u64(super::GUEST_PAGE_SIZE),
    ))
}

/// Configures the system for booting Linux.
pub fn configure_system_for_boot(
    vmm: &mut Vmm,
    vcpus: &mut [Vcpu],
    machine_config: &MachineConfig,
    cpu_template: &CustomCpuTemplate,
    entry_point: EntryPoint,
    initrd: &Option<InitrdConfig>,
    boot_cmdline: Cmdline,
) -> Result<(), ConfigurationError> {
    // Construct the base CpuConfiguration to apply CPU template onto.
    let cpu_config =
        CpuConfiguration::new(vmm.kvm.supported_cpuid.clone(), cpu_template, &vcpus[0])?;
    // Apply CPU template to the base CpuConfiguration.
    let cpu_config = CpuConfiguration::apply_template(cpu_config, cpu_template)?;

    let vcpu_config = VcpuConfig {
        vcpu_count: machine_config.vcpu_count,
        smt: machine_config.smt,
        cpu_config,
    };

    // Configure vCPUs with normalizing and setting the generated CPU configuration.
    for vcpu in vcpus.iter_mut() {
        vcpu.kvm_vcpu
            .configure(vmm.vm.guest_memory(), entry_point, &vcpu_config)?;
    }

    // Write the kernel command line to guest memory. This is x86_64 specific, since on
    // aarch64 the command line will be specified through the FDT.
    let cmdline_size = boot_cmdline
        .as_cstring()
        .map(|cmdline_cstring| cmdline_cstring.as_bytes_with_nul().len())
        .expect("Cannot create cstring from cmdline string");

    load_cmdline(
        vmm.vm.guest_memory(),
        GuestAddress(crate::arch::x86_64::layout::CMDLINE_START),
        &boot_cmdline,
    )
    .map_err(ConfigurationError::LoadCommandline)?;

    // Note that this puts the mptable at the last 1k of Linux's 640k base RAM
    mptable::setup_mptable(
        vmm.vm.guest_memory(),
        &mut vmm.resource_allocator,
        vcpu_config.vcpu_count,
    )
    .map_err(ConfigurationError::MpTableSetup)?;

    match entry_point.protocol {
        BootProtocol::PvhBoot => {
            configure_pvh(vmm.vm.guest_memory(), GuestAddress(CMDLINE_START), initrd)?;
        }
        BootProtocol::LinuxBoot => {
            configure_64bit_boot(
                vmm.vm.guest_memory(),
                GuestAddress(CMDLINE_START),
                cmdline_size,
                initrd,
            )?;
        }
    }

    // Create ACPI tables and write them in guest memory
    // For the time being we only support ACPI in x86_64
    create_acpi_tables(
        vmm.vm.guest_memory(),
        &mut vmm.resource_allocator,
        &vmm.mmio_device_manager,
        &vmm.acpi_device_manager,
        vcpus,
    )?;
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
    #[allow(clippy::cast_possible_truncation)] // the vec lengths are single digit integers
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

/// Load linux kernel into guest memory.
pub fn load_kernel(
    kernel: &File,
    guest_memory: &GuestMemoryMmap,
) -> Result<EntryPoint, ConfigurationError> {
    // Need to clone the File because reading from it
    // mutates it.
    let mut kernel_file = kernel
        .try_clone()
        .map_err(|_| ConfigurationError::KernelFile)?;

    let entry_addr = Loader::load(
        guest_memory,
        None,
        &mut kernel_file,
        Some(GuestAddress(get_kernel_start())),
    )
    .map_err(ConfigurationError::KernelLoader)?;

    let mut entry_point_addr: GuestAddress = entry_addr.kernel_load;
    let mut boot_prot: BootProtocol = BootProtocol::LinuxBoot;
    if let PvhBootCapability::PvhEntryPresent(pvh_entry_addr) = entry_addr.pvh_boot_cap {
        // Use the PVH kernel entry point to boot the guest
        entry_point_addr = pvh_entry_addr;
        boot_prot = BootProtocol::PvhBoot;
    }

    debug!("Kernel loaded using {boot_prot}");

    Ok(EntryPoint {
        entry_addr: entry_point_addr,
        protocol: boot_prot,
    })
}

#[cfg(kani)]
mod verification {
    use crate::arch::x86_64::FIRST_ADDR_PAST_32BITS;
    use crate::arch::{MMIO_MEM_START, arch_memory_regions};

    #[kani::proof]
    #[kani::unwind(3)]
    fn verify_arch_memory_regions() {
        let offset: u64 = kani::any::<u64>();
        let len: u64 = kani::any::<u64>();

        kani::assume(len > 0);
        kani::assume(offset.checked_add(len).is_some());

        let regions = arch_memory_regions(offset as usize, len as usize);

        // There's only one MMIO gap, so we can get either 1 or 2 regions
        assert!(regions.len() <= 2);
        assert!(regions.len() >= 1);

        // The total length of all regions is what we requested
        assert_eq!(
            regions.iter().map(|&(_, len)| len).sum::<usize>(),
            len as usize
        );

        // No region overlaps the MMIO gap
        assert!(
            regions
                .iter()
                .all(|&(start, len)| start.0 >= FIRST_ADDR_PAST_32BITS
                    || start.0 + len as u64 <= MMIO_MEM_START)
        );

        // All regions start after our specified offset
        assert!(regions.iter().all(|&(start, _)| start.0 >= offset as u64));

        // All regions have non-zero length
        assert!(regions.iter().all(|&(_, len)| len > 0));

        // If there's two regions, they perfectly snuggle up to the MMIO gap
        if regions.len() == 2 {
            kani::cover!();

            assert_eq!(regions[0].0.0 + regions[0].1 as u64, MMIO_MEM_START);
            assert_eq!(regions[1].0.0, FIRST_ADDR_PAST_32BITS);
        }
    }
}

#[cfg(test)]
mod tests {
    use linux_loader::loader::bootparam::boot_e820_entry;

    use super::*;
    use crate::device_manager::resources::ResourceAllocator;
    use crate::test_utils::{arch_mem, single_region_mem};

    #[test]
    fn regions_lt_4gb() {
        let regions = arch_memory_regions(0, 1usize << 29);
        assert_eq!(1, regions.len());
        assert_eq!(GuestAddress(0), regions[0].0);
        assert_eq!(1usize << 29, regions[0].1);

        let regions = arch_memory_regions(1 << 28, 1 << 29);
        assert_eq!(1, regions.len());
        assert_eq!(regions[0], (GuestAddress(1 << 28), 1 << 29));
    }

    #[test]
    fn regions_gt_4gb() {
        const MEMORY_SIZE: usize = (1 << 32) + 0x8000;

        let regions = arch_memory_regions(0, MEMORY_SIZE);
        assert_eq!(2, regions.len());
        assert_eq!(GuestAddress(0), regions[0].0);
        assert_eq!(GuestAddress(1u64 << 32), regions[1].0);

        let regions = arch_memory_regions(1 << 31, MEMORY_SIZE);
        assert_eq!(2, regions.len());
        assert_eq!(
            regions[0],
            (
                GuestAddress(1 << 31),
                u64_to_usize(MMIO_MEM_START) - (1 << 31)
            )
        );
        assert_eq!(
            regions[1],
            (
                GuestAddress(FIRST_ADDR_PAST_32BITS),
                MEMORY_SIZE - regions[0].1
            )
        )
    }

    #[test]
    fn test_system_configuration() {
        let no_vcpus = 4;
        let gm = single_region_mem(0x10000);
        let mut resource_allocator = ResourceAllocator::new().unwrap();
        let err = mptable::setup_mptable(&gm, &mut resource_allocator, 1);
        assert!(matches!(
            err.unwrap_err(),
            mptable::MptableError::NotEnoughMemory
        ));

        // Now assigning some memory that falls before the 32bit memory hole.
        let mem_size = mib_to_bytes(128);
        let gm = arch_mem(mem_size);
        let mut resource_allocator = ResourceAllocator::new().unwrap();
        mptable::setup_mptable(&gm, &mut resource_allocator, no_vcpus).unwrap();
        configure_64bit_boot(&gm, GuestAddress(0), 0, &None).unwrap();
        configure_pvh(&gm, GuestAddress(0), &None).unwrap();

        // Now assigning some memory that is equal to the start of the 32bit memory hole.
        let mem_size = mib_to_bytes(3328);
        let gm = arch_mem(mem_size);
        let mut resource_allocator = ResourceAllocator::new().unwrap();
        mptable::setup_mptable(&gm, &mut resource_allocator, no_vcpus).unwrap();
        configure_64bit_boot(&gm, GuestAddress(0), 0, &None).unwrap();
        configure_pvh(&gm, GuestAddress(0), &None).unwrap();

        // Now assigning some memory that falls after the 32bit memory hole.
        let mem_size = mib_to_bytes(3330);
        let gm = arch_mem(mem_size);
        let mut resource_allocator = ResourceAllocator::new().unwrap();
        mptable::setup_mptable(&gm, &mut resource_allocator, no_vcpus).unwrap();
        configure_64bit_boot(&gm, GuestAddress(0), 0, &None).unwrap();
        configure_pvh(&gm, GuestAddress(0), &None).unwrap();
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
