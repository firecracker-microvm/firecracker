// Copyright © 2025 Computing Systems Laboratory (CSLab), ECE, NTUA. All rights reserved.
//
// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Module for the global interrupt controller configuration.
pub mod aia;
mod fdt;
/// Architecture specific KVM-related code.
pub mod kvm;
/// Layout for this riscv64 system.
pub mod layout;
/// Logic for configuring riscv64 registers.
pub mod regs;
/// Architecture specific vCPU code.
pub mod vcpu;
/// Architecture specific VM state code.
pub mod vm;

use std::cmp::min;
use std::fs::File;

use linux_loader::loader::pe::PE as Loader;
use linux_loader::loader::{Cmdline, KernelLoader};
use vm_memory::GuestMemoryError;

use crate::arch::{BootProtocol, EntryPoint};
use crate::cpu_config::riscv64::CpuConfiguration;
use crate::cpu_config::riscv64::custom_cpu_template::CustomCpuTemplate;
use crate::initrd::InitrdConfig;
use crate::vmm_config::machine_config::MachineConfig;
use crate::vstate::memory::{Bytes, GuestAddress, GuestMemoryMmap};
use crate::vstate::vcpu::KvmVcpuError;
use crate::{Vcpu, VcpuConfig, Vmm, logger};

/// Errors thrown while configuring riscv64 system.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ConfigurationError {
    /// Failed to create a Flattened Device Tree for this riscv64 microVM: {0}
    SetupFDT(#[from] fdt::FdtError),
    /// Failed to write to guest memory.
    MemoryError(GuestMemoryError),
    /// Cannot copy kernel file fd
    KernelFile,
    /// Cannot load kernel due to invalid memory configuration or invalid kernel image: {0}
    KernelLoader(#[from] linux_loader::loader::Error),
    /// Error configuring the vcpu: {0}
    VcpuConfigure(#[from] KvmVcpuError),
}

/// The start of the memory area reserved for MMIO devices.
pub const MMIO_MEM_START: u64 = layout::MAPPED_IO_START;
/// The size of the memory area reserved for MMIO devices.
pub const MMIO_MEM_SIZE: u64 = layout::DRAM_MEM_START - layout::MAPPED_IO_START; //>> 1GB

/// Returns a Vec of the valid memory addresses for riscv64.
/// See [`layout`](layout) module for a drawing of the specific memory model for this platform.
///
/// The `offset` parameter specified the offset from [`layout::DRAM_MEM_START`].
pub fn arch_memory_regions(offset: usize, size: usize) -> Vec<(GuestAddress, usize)> {
    assert!(size > 0, "Attempt to allocate guest memory of length 0");
    assert!(
        offset.checked_add(size).is_some(),
        "Attempt to allocate guest memory such that the address space would wrap around"
    );
    assert!(
        offset < layout::DRAM_MEM_MAX_SIZE,
        "offset outside allowed DRAM range"
    );

    let dram_size = min(size, layout::DRAM_MEM_MAX_SIZE - offset);

    if dram_size != size {
        logger::warn!(
            "Requested offset/memory size {}/{} exceeds architectural maximum (1022GiB). Size has \
             been truncated to {}",
            offset,
            size,
            dram_size
        );
    }

    vec![(
        GuestAddress(layout::DRAM_MEM_START + offset as u64),
        dram_size,
    )]
}

/// Configures the system for booting Linux.
pub fn configure_system_for_boot(
    vmm: &mut Vmm,
    vcpus: &mut [Vcpu],
    machine_config: &MachineConfig,
    cpu_template: &CustomCpuTemplate,
    entry_point: EntryPoint,
    _initrd: &Option<InitrdConfig>,
    boot_cmdline: Cmdline,
) -> Result<(), ConfigurationError> {
    let cpu_config = { CpuConfiguration };

    // Apply CPU template to the base CpuConfiguration.
    let cpu_config = CpuConfiguration::apply_template(cpu_config, cpu_template);

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
    let cmdline = boot_cmdline
        .as_cstring()
        .expect("Cannot create cstring from cmdline string");

    let guest_mem = &vmm.vm.guest_memory();
    // TODO: get timer frequency appropriately.
    let fdt = fdt::create_fdt(
        vcpus,
        guest_mem,
        cmdline,
        0x989680u32,
        vmm.mmio_device_manager.get_device_info(),
        vmm.vm.get_irqchip(),
    )?;
    let fdt_address = GuestAddress(get_fdt_addr());
    guest_mem
        .write_slice(fdt.as_slice(), fdt_address)
        .map_err(ConfigurationError::MemoryError)?;

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
        Some(GuestAddress(get_kernel_start())),
        &mut kernel_file,
        None,
    )?;

    Ok(EntryPoint {
        entry_addr: entry_addr.kernel_load,
        protocol: BootProtocol::LinuxBoot,
    })
}

/// Returns the memory address where the kernel could be loaded.
pub fn get_kernel_start() -> u64 {
    layout::SYSTEM_MEM_START + layout::SYSTEM_MEM_SIZE
}

/// Returns the memory address where the initrd could be loaded. Unimplemented for now.
pub fn initrd_load_addr(_guest_mem: &GuestMemoryMmap, _initrd_size: usize) -> Option<u64> {
    unimplemented!()
}

/// Auxiliary function to get the address where the device tree blob is loaded.
fn get_fdt_addr() -> u64 {
    layout::DRAM_MEM_START
}
