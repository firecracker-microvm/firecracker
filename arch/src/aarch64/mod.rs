// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod fdt;
pub mod gic;
pub mod layout;
pub mod regs;

use std::cmp::min;
use std::ffi::CStr;

use memory_model::{GuestAddress, GuestMemory};

#[derive(Debug)]
pub enum Error {
    SetupFDT(fdt::Error),
}

impl From<Error> for super::Error {
    fn from(e: Error) -> super::Error {
        super::Error::Aarch64Setup(e)
    }
}

/// Returns a Vec of the valid memory addresses for aarch64.
/// See [`layout`](layout) module for a drawing of the specific memory model for this platform.
pub fn arch_memory_regions(size: usize) -> Vec<(GuestAddress, usize)> {
    let dram_size = min(size, layout::DRAM_MEM_END);
    vec![(GuestAddress(layout::DRAM_MEM_START), dram_size)]
}

/// Configures the system and should be called once per vm before starting vcpu threads.
/// For aarch64, we only setup the FDT.
///
/// # Arguments
///
/// * `guest_mem` - The memory to be used by the guest.
/// * `cmdline_cstring` - The kernel commandline.
/// * `num_cpus` - Number of virtual CPUs of the system.
pub fn configure_system(
    guest_mem: &GuestMemory,
    cmdline_cstring: &CStr,
    num_cpus: u8,
) -> super::Result<()> {
    fdt::create_fdt(guest_mem, u32::from(num_cpus), cmdline_cstring).map_err(Error::SetupFDT)?;
    Ok(())
}

/// Stub function that needs to be implemented when aarch64 functionality is added.
pub fn get_reserved_mem_addr() -> usize {
    0
}

/// Returns the memory address where the kernel could be loaded.
pub fn get_kernel_start() -> usize {
    layout::DRAM_MEM_START
}

// Auxiliary function to get the address where the device tree blob is loaded.
fn get_fdt_addr(mem: &GuestMemory) -> usize {
    // If the memory allocated is smaller than the size allocated for the FDT,
    // we return the start of the DRAM so that
    // we allow the code to try and load the FDT.

    if let Some(offset) = mem.end_addr().checked_sub(layout::FDT_MAX_SIZE) {
        if mem.address_in_range(offset) {
            return offset.offset();
        }
    }
    layout::DRAM_MEM_START
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(super::layout::DRAM_MEM_END, regions[0].1);
    }

    #[test]
    fn test_get_fdt_addr() {
        let regions = arch_memory_regions(layout::FDT_MAX_SIZE - 0x1000);
        let mem = GuestMemory::new(&regions).expect("Cannot initialize memory");
        assert_eq!(get_fdt_addr(&mem), layout::DRAM_MEM_START);

        let regions = arch_memory_regions(layout::FDT_MAX_SIZE);
        let mem = GuestMemory::new(&regions).expect("Cannot initialize memory");
        assert_eq!(get_fdt_addr(&mem), layout::DRAM_MEM_START);

        let regions = arch_memory_regions(layout::FDT_MAX_SIZE + 0x1000);
        let mem = GuestMemory::new(&regions).expect("Cannot initialize memory");
        assert_eq!(get_fdt_addr(&mem), 0x1000 + layout::DRAM_MEM_START);
    }
}
