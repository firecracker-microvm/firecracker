// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod cache_info;
mod fdt;
/// Module for the global interrupt controller configuration.
pub mod gic;
/// Architecture specific KVM-related code
pub mod kvm;
/// Layout for this aarch64 system.
pub mod layout;
/// Logic for configuring aarch64 registers.
pub mod regs;
/// Architecture specific vCPU code
pub mod vcpu;
/// Architecture specific VM state code
pub mod vm;

use std::cmp::min;
use std::fmt::Debug;
use std::fs::File;

use linux_loader::loader::pe::PE as Loader;
use linux_loader::loader::{Cmdline, KernelLoader};
use vm_memory::GuestMemoryError;

use crate::arch::{BootProtocol, EntryPoint, arch_memory_regions_with_gap};
use crate::cpu_config::aarch64::{CpuConfiguration, CpuConfigurationError};
use crate::cpu_config::templates::CustomCpuTemplate;
use crate::initrd::InitrdConfig;
use crate::utils::{align_up, u64_to_usize, usize_to_u64};
use crate::vmm_config::machine_config::MachineConfig;
use crate::vstate::memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};
use crate::vstate::vcpu::KvmVcpuError;
use crate::{DeviceManager, Kvm, Vcpu, VcpuConfig, Vm, logger};

/// Errors thrown while configuring aarch64 system.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ConfigurationError {
    /// Failed to create a Flattened Device Tree for this aarch64 microVM: {0}
    SetupFDT(#[from] fdt::FdtError),
    /// Failed to write to guest memory.
    MemoryError(#[from] GuestMemoryError),
    /// Cannot copy kernel file fd
    KernelFile,
    /// Cannot load kernel due to invalid memory configuration or invalid kernel image: {0}
    KernelLoader(#[from] linux_loader::loader::Error),
    /// Error creating vcpu configuration: {0}
    VcpuConfig(#[from] CpuConfigurationError),
    /// Error configuring the vcpu: {0}
    VcpuConfigure(#[from] KvmVcpuError),
}

/// Returns a Vec of the valid memory addresses for aarch64.
/// See [`layout`](layout) module for a drawing of the specific memory model for this platform.
pub fn arch_memory_regions(size: usize) -> Vec<(GuestAddress, usize)> {
    assert!(size > 0, "Attempt to allocate guest memory of length 0");

    let dram_size = min(size, layout::DRAM_MEM_MAX_SIZE);

    if dram_size != size {
        logger::warn!(
            "Requested memory size {} exceeds architectural maximum (1022GiB). Size has been \
             truncated to {}",
            size,
            dram_size
        );
    }

    let mut regions = vec![];
    if let Some((offset, remaining)) = arch_memory_regions_with_gap(
        &mut regions,
        u64_to_usize(layout::DRAM_MEM_START),
        dram_size,
        u64_to_usize(layout::MMIO64_MEM_START),
        u64_to_usize(layout::MMIO64_MEM_SIZE),
    ) {
        regions.push((GuestAddress(offset as u64), remaining));
    }

    regions
}

/// Configures the system for booting Linux.
#[allow(clippy::too_many_arguments)]
pub fn configure_system_for_boot(
    kvm: &Kvm,
    vm: &Vm,
    device_manager: &mut DeviceManager,
    vcpus: &mut [Vcpu],
    machine_config: &MachineConfig,
    cpu_template: &CustomCpuTemplate,
    entry_point: EntryPoint,
    initrd: &Option<InitrdConfig>,
    boot_cmdline: Cmdline,
) -> Result<(), ConfigurationError> {
    // Construct the base CpuConfiguration to apply CPU template onto.
    let cpu_config = CpuConfiguration::new(cpu_template, vcpus)?;

    // Apply CPU template to the base CpuConfiguration.
    let cpu_config = CpuConfiguration::apply_template(cpu_config, cpu_template);

    let vcpu_config = VcpuConfig {
        vcpu_count: machine_config.vcpu_count,
        smt: machine_config.smt,
        cpu_config,
    };

    let optional_capabilities = kvm.optional_capabilities();
    // Configure vCPUs with normalizing and setting the generated CPU configuration.
    for vcpu in vcpus.iter_mut() {
        vcpu.kvm_vcpu.configure(
            vm.guest_memory(),
            entry_point,
            &vcpu_config,
            &optional_capabilities,
        )?;
    }
    let vcpu_mpidr = vcpus
        .iter_mut()
        .map(|cpu| cpu.kvm_vcpu.get_mpidr())
        .collect::<Result<Vec<_>, _>>()
        .map_err(KvmVcpuError::ConfigureRegisters)?;
    let cmdline = boot_cmdline
        .as_cstring()
        .expect("Cannot create cstring from cmdline string");

    let fdt = fdt::create_fdt(
        vm.guest_memory(),
        vcpu_mpidr,
        cmdline,
        device_manager,
        vm.get_irqchip(),
        initrd,
    )?;

    let fdt_address = GuestAddress(get_fdt_addr(vm.guest_memory()));
    vm.guest_memory().write_slice(fdt.as_slice(), fdt_address)?;

    Ok(())
}

/// Returns the memory address where the kernel could be loaded.
pub fn get_kernel_start() -> u64 {
    layout::SYSTEM_MEM_START + layout::SYSTEM_MEM_SIZE
}

/// Returns the memory address where the initrd could be loaded.
pub fn initrd_load_addr(guest_mem: &GuestMemoryMmap, initrd_size: usize) -> Option<u64> {
    let rounded_size = align_up(
        usize_to_u64(initrd_size),
        usize_to_u64(super::GUEST_PAGE_SIZE),
    );
    match GuestAddress(get_fdt_addr(guest_mem)).checked_sub(rounded_size) {
        Some(offset) => {
            if guest_mem.address_in_range(offset) {
                Some(offset.raw_value())
            } else {
                None
            }
        }
        None => None,
    }
}

// Auxiliary function to get the address where the device tree blob is loaded.
fn get_fdt_addr(mem: &GuestMemoryMmap) -> u64 {
    // If the memory allocated is smaller than the size allocated for the FDT,
    // we return the start of the DRAM so that
    // we allow the code to try and load the FDT.

    if let Some(addr) = mem.last_addr().checked_sub(layout::FDT_MAX_SIZE as u64 - 1)
        && mem.address_in_range(addr)
    {
        return addr.raw_value();
    }

    layout::DRAM_MEM_START
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
        Some(GuestAddress(get_kernel_start())),
        &mut kernel_file,
        None,
    )?;

    Ok(EntryPoint {
        entry_addr: entry_addr.kernel_load,
        protocol: BootProtocol::LinuxBoot,
    })
}

#[cfg(kani)]
mod verification {
    use crate::arch::aarch64::layout::{
        DRAM_MEM_MAX_SIZE, DRAM_MEM_START, FIRST_ADDR_PAST_64BITS_MMIO, MMIO64_MEM_START,
    };
    use crate::arch::arch_memory_regions;

    #[kani::proof]
    #[kani::unwind(3)]
    fn verify_arch_memory_regions() {
        let len: usize = kani::any::<usize>();
        kani::assume(len > 0);

        let regions = arch_memory_regions(len);

        for region in &regions {
            println!(
                "region: [{:x}:{:x})",
                region.0.0,
                region.0.0 + region.1 as u64
            );
        }

        // On Arm we have one MMIO gap that might fall within addressable ranges,
        // so we can get either 1 or 2 regions.
        assert!(regions.len() >= 1);
        assert!(regions.len() <= 2);

        // The total length of all regions cannot exceed DRAM_MEM_MAX_SIZE
        let actual_len = regions.iter().map(|&(_, len)| len).sum::<usize>();
        assert!(actual_len <= DRAM_MEM_MAX_SIZE);
        // The total length is smaller or equal to the length we asked
        assert!(actual_len <= len);
        // If it's smaller, it's because we asked more than the the maximum possible.
        if (actual_len) < len {
            assert!(len > DRAM_MEM_MAX_SIZE);
        }

        // No region overlaps the 64-bit MMIO gap
        assert!(
            regions
                .iter()
                .all(|&(start, len)| start.0 >= FIRST_ADDR_PAST_64BITS_MMIO
                    || start.0 + len as u64 <= MMIO64_MEM_START)
        );

        // All regions start after our DRAM_MEM_START
        assert!(regions.iter().all(|&(start, _)| start.0 >= DRAM_MEM_START));

        // All regions have non-zero length
        assert!(regions.iter().all(|&(_, len)| len > 0));

        // If there's two regions, they perfectly snuggle up the 64bit MMIO gap
        if regions.len() == 2 {
            kani::cover!();

            // The very first address should be DRAM_MEM_START
            assert_eq!(regions[0].0.0, DRAM_MEM_START);
            // The first region ends at the beginning of the 64 bits gap.
            assert_eq!(regions[0].0.0 + regions[0].1 as u64, MMIO64_MEM_START);
            // The second region starts exactly after the 64 bits gap.
            assert_eq!(regions[1].0.0, FIRST_ADDR_PAST_64BITS_MMIO);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::aarch64::layout::{
        DRAM_MEM_MAX_SIZE, DRAM_MEM_START, FDT_MAX_SIZE, FIRST_ADDR_PAST_64BITS_MMIO,
        MMIO64_MEM_START,
    };
    use crate::test_utils::arch_mem;

    #[test]
    fn test_regions_lt_1024gb() {
        let regions = arch_memory_regions(1usize << 29);
        assert_eq!(1, regions.len());
        assert_eq!(GuestAddress(DRAM_MEM_START), regions[0].0);
        assert_eq!(1usize << 29, regions[0].1);
    }

    #[test]
    fn test_regions_gt_1024gb() {
        let regions = arch_memory_regions(1usize << 41);
        assert_eq!(2, regions.len());
        assert_eq!(GuestAddress(DRAM_MEM_START), regions[0].0);
        assert_eq!(MMIO64_MEM_START - DRAM_MEM_START, regions[0].1 as u64);
        assert_eq!(GuestAddress(FIRST_ADDR_PAST_64BITS_MMIO), regions[1].0);
        assert_eq!(
            DRAM_MEM_MAX_SIZE as u64 - MMIO64_MEM_START + DRAM_MEM_START,
            regions[1].1 as u64
        );
    }

    #[test]
    fn test_get_fdt_addr() {
        let mem = arch_mem(FDT_MAX_SIZE - 0x1000);
        assert_eq!(get_fdt_addr(&mem), DRAM_MEM_START);

        let mem = arch_mem(FDT_MAX_SIZE);
        assert_eq!(get_fdt_addr(&mem), DRAM_MEM_START);

        let mem = arch_mem(FDT_MAX_SIZE + 0x1000);
        assert_eq!(get_fdt_addr(&mem), 0x1000 + DRAM_MEM_START);
    }
}
