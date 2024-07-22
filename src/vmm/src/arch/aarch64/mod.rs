// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod cache_info;
mod fdt;
/// Module for the global interrupt controller configuration.
pub mod gic;
/// Layout for this aarch64 system.
pub mod layout;
/// Logic for configuring aarch64 registers.
pub mod regs;
/// Helper methods for VcpuFd.
pub mod vcpu;

use std::cmp::min;
use std::collections::HashMap;
use std::ffi::CString;
use std::fmt::Debug;

pub use self::fdt::DeviceInfoForFDT;
use self::gic::GICDevice;
use crate::arch::DeviceType;
use crate::devices::acpi::vmgenid::VmGenId;
use crate::vstate::memory::{Address, GuestAddress, GuestMemory, GuestMemoryMmap};

/// Errors thrown while configuring aarch64 system.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ConfigurationError {
    /// Failed to create a Flattened Device Tree for this aarch64 microVM.
    SetupFDT(#[from] fdt::FdtError),
    /// Failed to compute the initrd address.
    InitrdAddress,
}

/// The start of the memory area reserved for MMIO devices.
pub const MMIO_MEM_START: u64 = layout::MAPPED_IO_START;
/// The size of the memory area reserved for MMIO devices.
pub const MMIO_MEM_SIZE: u64 = layout::DRAM_MEM_START - layout::MAPPED_IO_START; //>> 1GB

/// Returns a Vec of the valid memory addresses for aarch64.
/// See [`layout`](layout) module for a drawing of the specific memory model for this platform.
pub fn arch_memory_regions(size: usize) -> Vec<(GuestAddress, usize)> {
    let dram_size = min(size, layout::DRAM_MEM_MAX_SIZE);
    vec![(GuestAddress(layout::DRAM_MEM_START), dram_size)]
}

/// Configures the system and should be called once per vm before starting vcpu threads.
/// For aarch64, we only setup the FDT.
///
/// # Arguments
///
/// * `guest_mem` - The memory to be used by the guest.
/// * `cmdline_cstring` - The kernel commandline.
/// * `vcpu_mpidr` - Array of MPIDR register values per vcpu.
/// * `device_info` - A hashmap containing the attached devices for building FDT device nodes.
/// * `gic_device` - The GIC device.
/// * `initrd` - Information about an optional initrd.
pub fn configure_system<T: DeviceInfoForFDT + Clone + Debug, S: std::hash::BuildHasher>(
    guest_mem: &GuestMemoryMmap,
    cmdline_cstring: CString,
    vcpu_mpidr: Vec<u64>,
    device_info: &HashMap<(DeviceType, String), T, S>,
    gic_device: &GICDevice,
    vmgenid: &Option<VmGenId>,
    initrd: &Option<super::InitrdConfig>,
) -> Result<(), ConfigurationError> {
    fdt::create_fdt(
        guest_mem,
        vcpu_mpidr,
        cmdline_cstring,
        device_info,
        gic_device,
        vmgenid,
        initrd,
    )?;
    Ok(())
}

/// Returns the memory address where the kernel could be loaded.
pub fn get_kernel_start() -> u64 {
    layout::SYSTEM_MEM_START + layout::SYSTEM_MEM_SIZE
}

/// Returns the memory address where the initrd could be loaded.
pub fn initrd_load_addr(
    guest_mem: &GuestMemoryMmap,
    initrd_size: usize,
) -> Result<u64, ConfigurationError> {
    let round_to_pagesize = |size| (size + (super::PAGE_SIZE - 1)) & !(super::PAGE_SIZE - 1);
    match GuestAddress(get_fdt_addr(guest_mem)).checked_sub(round_to_pagesize(initrd_size) as u64) {
        Some(offset) => {
            if guest_mem.address_in_range(offset) {
                Ok(offset.raw_value())
            } else {
                Err(ConfigurationError::InitrdAddress)
            }
        }
        None => Err(ConfigurationError::InitrdAddress),
    }
}

// Auxiliary function to get the address where the device tree blob is loaded.
fn get_fdt_addr(mem: &GuestMemoryMmap) -> u64 {
    // If the memory allocated is smaller than the size allocated for the FDT,
    // we return the start of the DRAM so that
    // we allow the code to try and load the FDT.

    if let Some(addr) = mem.last_addr().checked_sub(layout::FDT_MAX_SIZE as u64 - 1) {
        if mem.address_in_range(addr) {
            return addr.raw_value();
        }
    }

    layout::DRAM_MEM_START
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utilities::test_utils::arch_mem;

    #[test]
    fn test_regions_lt_1024gb() {
        let regions = arch_memory_regions(1usize << 29);
        assert_eq!(1, regions.len());
        assert_eq!(GuestAddress(super::layout::DRAM_MEM_START), regions[0].0);
        assert_eq!(1usize << 29, regions[0].1);
    }

    #[test]
    fn test_regions_gt_1024gb() {
        let regions = arch_memory_regions(1usize << 41);
        assert_eq!(1, regions.len());
        assert_eq!(GuestAddress(super::layout::DRAM_MEM_START), regions[0].0);
        assert_eq!(super::layout::DRAM_MEM_MAX_SIZE, regions[0].1);
    }

    #[test]
    fn test_get_fdt_addr() {
        let mem = arch_mem(layout::FDT_MAX_SIZE - 0x1000);
        assert_eq!(get_fdt_addr(&mem), layout::DRAM_MEM_START);

        let mem = arch_mem(layout::FDT_MAX_SIZE);
        assert_eq!(get_fdt_addr(&mem), layout::DRAM_MEM_START);

        let mem = arch_mem(layout::FDT_MAX_SIZE + 0x1000);
        assert_eq!(get_fdt_addr(&mem), 0x1000 + layout::DRAM_MEM_START);
    }
}
