// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

extern crate byteorder;
extern crate kvm;
extern crate kvm_sys;
extern crate libc;
extern crate memory_model;
extern crate sys_util;

#[allow(dead_code)]
#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
mod bootparam;
// Bindgen didn't implement copy for boot_params because edid_info contains an array with len > 32.
impl Copy for bootparam::edid_info {}
impl Clone for bootparam::edid_info {
    fn clone(&self) -> Self {
        *self
    }
}
impl Copy for bootparam::boot_params {}
impl Clone for bootparam::boot_params {
    fn clone(&self) -> Self {
        *self
    }
}
// boot_params is just a series of ints, it is safe to initialize it.
unsafe impl memory_model::DataInit for bootparam::boot_params {}

#[allow(dead_code)]
#[allow(non_upper_case_globals)]
mod msr_index;

#[allow(dead_code)]
#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
mod mpspec;
// These mpspec types are only data, reading them from data is a safe initialization.
unsafe impl memory_model::DataInit for mpspec::mpc_bus {}
unsafe impl memory_model::DataInit for mpspec::mpc_cpu {}
unsafe impl memory_model::DataInit for mpspec::mpc_intsrc {}
unsafe impl memory_model::DataInit for mpspec::mpc_ioapic {}
unsafe impl memory_model::DataInit for mpspec::mpc_table {}
unsafe impl memory_model::DataInit for mpspec::mpc_lintsrc {}
unsafe impl memory_model::DataInit for mpspec::mpf_intel {}

pub mod cpuid;
mod gdt;
pub mod interrupts;
pub mod layout;
mod mptable;
pub mod regs;

use std::mem;
use std::result;

use bootparam::boot_params;
use bootparam::E820_RAM;
use memory_model::{GuestAddress, GuestMemory};

pub use interrupts::Error as IntError;
pub use mptable::Error as MpTableError;
pub use regs::Error as RegError;

#[derive(Debug)]
pub enum Error {
    /// Error writing MP table to memory.
    MpTableSetup(MpTableError),
    /// Error writing the zero page of guest memory.
    ZeroPageSetup,
    /// The zero page extends past the end of guest_mem.
    ZeroPagePastRamEnd,
    /// Invalid e820 setup params.
    E820Configuration,
}
pub type Result<T> = result::Result<T, Error>;

const MEM_32BIT_GAP_SIZE: usize = (768 << 20);
const FIRST_ADDR_PAST_32BITS: usize = (1 << 32);

/// Returns a Vec of the valid memory addresses.
/// These should be used to configure the GuestMemory structure for the platfrom.
/// For x86_64 all addresses are valid from the start of the kenel except a
/// carve out at the end of 32bit address space.
pub fn arch_memory_regions(size: usize) -> Vec<(GuestAddress, usize)> {
    let memory_gap_start = GuestAddress(FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE);
    let memory_gap_end = GuestAddress(FIRST_ADDR_PAST_32BITS);
    let requested_memory_size = GuestAddress(size);
    let mut regions = Vec::new();

    // case1: guest memory fits before the gap
    if requested_memory_size <= memory_gap_start {
        regions.push((GuestAddress(0), size));
    // case2: guest memory extends beyond the gap
    } else {
        // push memory before the gap
        regions.push((GuestAddress(0), memory_gap_start.offset()));
        regions.push((
            memory_gap_end,
            requested_memory_size.offset_from(memory_gap_start),
        ));
    }

    regions
}

pub fn get_32bit_gap_start() -> usize {
    FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE
}

/// Configures the system and should be called once per vm before starting vcpu threads.
///
/// # Arguments
///
/// * `guest_mem` - The memory to be used by the guest.
/// * `cmdline_addr` - Address in `guest_mem` where the kernel command line was loaded.
/// * `cmdline_size` - Size of the kernel command line in bytes including the null terminator.
/// * `num_cpus` - Number of virtual CPUs the guest will have.
pub fn configure_system(
    guest_mem: &GuestMemory,
    cmdline_addr: GuestAddress,
    cmdline_size: usize,
    num_cpus: u8,
) -> Result<()> {
    const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
    const KERNEL_HDR_MAGIC: u32 = 0x53726448;
    const KERNEL_LOADER_OTHER: u8 = 0xff;
    const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x1000000; // Must be non-zero.
    let first_addr_past_32bits = GuestAddress(FIRST_ADDR_PAST_32BITS);
    let end_32bit_gap_start = GuestAddress(FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE);
    let himem_start = GuestAddress(layout::HIMEM_START);

    // Note that this puts the mptable at the last 1k of Linux's 640k base RAM
    mptable::setup_mptable(guest_mem, num_cpus).map_err(Error::MpTableSetup)?;

    let mut params: boot_params = Default::default();

    params.hdr.type_of_loader = KERNEL_LOADER_OTHER;
    params.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC;
    params.hdr.header = KERNEL_HDR_MAGIC;
    params.hdr.cmd_line_ptr = cmdline_addr.offset() as u32;
    params.hdr.cmdline_size = cmdline_size as u32;
    params.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;

    add_e820_entry(&mut params, 0, layout::EBDA_START, E820_RAM)?;

    let mem_end = guest_mem.end_addr();
    if mem_end < end_32bit_gap_start {
        add_e820_entry(
            &mut params,
            himem_start.offset() as u64,
            mem_end.offset_from(himem_start) as u64,
            E820_RAM,
        )?;
    } else {
        add_e820_entry(
            &mut params,
            himem_start.offset() as u64,
            end_32bit_gap_start.offset_from(himem_start) as u64,
            E820_RAM,
        )?;
        if mem_end > first_addr_past_32bits {
            add_e820_entry(
                &mut params,
                first_addr_past_32bits.offset() as u64,
                mem_end.offset_from(first_addr_past_32bits) as u64,
                E820_RAM,
            )?;
        }
    }

    let zero_page_addr = GuestAddress(layout::ZERO_PAGE_START);
    guest_mem
        .checked_offset(zero_page_addr, mem::size_of::<boot_params>())
        .ok_or(Error::ZeroPagePastRamEnd)?;
    guest_mem
        .write_obj_at_addr(params, zero_page_addr)
        .map_err(|_| Error::ZeroPageSetup)?;

    Ok(())
}

/// Add an e820 region to the e820 map.
/// Returns Ok(()) if successful, or an error if there is no space left in the map.
fn add_e820_entry(params: &mut boot_params, addr: u64, size: u64, mem_type: u32) -> Result<()> {
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
        assert_eq!(GuestAddress(1usize << 32), regions[1].0);
    }
}
