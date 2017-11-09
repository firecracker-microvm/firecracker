// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

extern crate byteorder;
extern crate data_model;
extern crate kvm;
extern crate kvm_sys;
extern crate libc;
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
unsafe impl data_model::DataInit for bootparam::boot_params {}

#[allow(dead_code)]
#[allow(non_upper_case_globals)]
mod msr_index;

#[allow(dead_code)]
#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
mod mpspec;
// These mpspec types are only data, reading them from data is a safe initialization.
unsafe impl data_model::DataInit for mpspec::mpc_bus {}
unsafe impl data_model::DataInit for mpspec::mpc_cpu {}
unsafe impl data_model::DataInit for mpspec::mpc_intsrc {}
unsafe impl data_model::DataInit for mpspec::mpc_ioapic {}
unsafe impl data_model::DataInit for mpspec::mpc_table {}
unsafe impl data_model::DataInit for mpspec::mpc_lintsrc {}
unsafe impl data_model::DataInit for mpspec::mpf_intel {}

mod cpuid;
mod gdt;
mod interrupts;
mod mptable;
mod regs;

use std::mem;
use std::result;

use bootparam::boot_params;
use bootparam::E820_RAM;
use sys_util::{GuestAddress, GuestMemory};

pub use regs::Error as RegError;
pub use interrupts::Error as IntError;
pub use mptable::Error as MpTableError;

#[derive(Debug)]
pub enum Error {
    /// Error configuring the VCPU.
    CpuSetup(cpuid::Error),
    /// The kernel extends past the end of RAM
    KernelOffsetPastEnd,
    /// Error configuring the VCPU registers.
    RegisterConfiguration(RegError),
    /// Error configuring the VCPU floating point registers.
    FpuRegisterConfiguration(RegError),
    /// Error configuring the VCPU segment registers.
    SegmentRegisterConfiguration(RegError),
    /// Error configuring the VCPU local interrupt.
    LocalIntConfiguration(IntError),
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

const BOOT_STACK_POINTER: usize = 0x8000;
const MEM_32BIT_GAP_SIZE: usize = (768 << 20);
const FIRST_ADDR_PAST_32BITS: usize = (1 << 32);
const KERNEL_64BIT_ENTRY_OFFSET: usize = 0x200;
const ZERO_PAGE_OFFSET: usize = 0x7000;

/// Returns a Vec of the valid memory addresses.
/// These should be used to configure the GuestMemory structure for the platfrom.
/// For x86_64 all addresses are valid from the start of the kenel except a
/// carve out at the end of 32bit address space.
pub fn arch_memory_regions(size: usize) -> Vec<(GuestAddress, usize)> {
    let mem_end = GuestAddress(size);
    let first_addr_past_32bits = GuestAddress(FIRST_ADDR_PAST_32BITS);
    let end_32bit_gap_start = GuestAddress(FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE);

    let mut regions = Vec::new();
    if mem_end < end_32bit_gap_start {
        regions.push((GuestAddress(0), size));
    } else {
        regions.push((GuestAddress(0), end_32bit_gap_start.offset()));
        if mem_end > first_addr_past_32bits {
            regions.push((first_addr_past_32bits, mem_end.offset_from(first_addr_past_32bits)));
        }
    }

    regions
}

/// Configures the vcpu and should be called once per vcpu from the vcpu's thread.
///
/// # Arguments
///
/// * `guest_mem` - The memory to be used by the guest.
/// * `kernel_load_offset` - Offset from `guest_mem` at which the kernel starts.
/// * `kvm` - The /dev/kvm object that created vcpu.
/// * `vcpu` - The VCPU object to configure.
/// * `cpu_id` - The id of the given `vcpu`.
/// * `num_cpus` - Number of virtual CPUs the guest will have.
pub fn configure_vcpu(guest_mem: &GuestMemory,
                      kernel_load_addr: GuestAddress,
                      kvm: &kvm::Kvm,
                      vcpu: &kvm::Vcpu,
                      cpu_id: u64,
                      num_cpus: u64)
                      -> Result<()> {
    cpuid::setup_cpuid(kvm, vcpu, cpu_id, num_cpus).map_err(Error::CpuSetup)?;
    regs::setup_msrs(vcpu).map_err(Error::RegisterConfiguration)?;
    let kernel_end = guest_mem.checked_offset(kernel_load_addr, KERNEL_64BIT_ENTRY_OFFSET)
        .ok_or(Error::KernelOffsetPastEnd)?;
    regs::setup_regs(vcpu,
                     (kernel_end).offset() as u64,
                     BOOT_STACK_POINTER as u64,
                     ZERO_PAGE_OFFSET as u64).map_err(Error::RegisterConfiguration)?;
    regs::setup_fpu(vcpu).map_err(Error::FpuRegisterConfiguration)?;
    regs::setup_sregs(guest_mem, vcpu).map_err(Error::SegmentRegisterConfiguration)?;
    interrupts::set_lint(vcpu).map_err(Error::LocalIntConfiguration)?;
    Ok(())
}

/// Configures the system and should be called once per vm before starting vcpu threads.
///
/// # Arguments
///
/// * `guest_mem` - The memory to be used by the guest.
/// * `kernel_addr` - Address in `guest_mem` where the kernel was loaded.
/// * `cmdline_addr` - Address in `guest_mem` where the kernel command line was loaded.
/// * `cmdline_size` - Size of the kernel command line in bytes including the null terminator.
/// * `num_cpus` - Number of virtual CPUs the guest will have.
pub fn configure_system(guest_mem: &GuestMemory,
                        kernel_addr: GuestAddress,
                        cmdline_addr: GuestAddress,
                        cmdline_size: usize,
                        num_cpus: u8)
                        -> Result<()> {
    const EBDA_START: u64 = 0x0009fc00;
    const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
    const KERNEL_HDR_MAGIC: u32 = 0x53726448;
    const KERNEL_LOADER_OTHER: u8 = 0xff;
    const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x1000000; // Must be non-zero.
    let first_addr_past_32bits = GuestAddress(FIRST_ADDR_PAST_32BITS);
    let end_32bit_gap_start = GuestAddress(FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE);

    // Note that this puts the mptable at 0x0 in guest physical memory.
    mptable::setup_mptable(guest_mem, num_cpus).map_err(Error::MpTableSetup)?;

    let mut params: boot_params = Default::default();

    params.hdr.type_of_loader = KERNEL_LOADER_OTHER;
    params.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC;
    params.hdr.header = KERNEL_HDR_MAGIC;
    params.hdr.cmd_line_ptr = cmdline_addr.offset() as u32;
    params.hdr.cmdline_size = cmdline_size as u32;
    params.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;

    add_e820_entry(&mut params, 0, EBDA_START, E820_RAM)?;

    let mem_end = guest_mem.end_addr();
    if mem_end < end_32bit_gap_start {
        add_e820_entry(&mut params,
                       kernel_addr.offset() as u64,
                       mem_end.offset_from(kernel_addr) as u64,
                       E820_RAM)?;
    } else {
        add_e820_entry(&mut params,
                       kernel_addr.offset() as u64,
                       end_32bit_gap_start.offset_from(kernel_addr) as u64,
                       E820_RAM)?;
        if mem_end > first_addr_past_32bits {
            add_e820_entry(&mut params,
                           first_addr_past_32bits.offset() as u64,
                           mem_end.offset_from(first_addr_past_32bits) as u64,
                           E820_RAM)?;
        }
    }

    let zero_page_addr = GuestAddress(ZERO_PAGE_OFFSET);
    guest_mem.checked_offset(zero_page_addr, mem::size_of::<boot_params>())
        .ok_or(Error::ZeroPagePastRamEnd)?;
    guest_mem.write_obj_at_addr(params, zero_page_addr)
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
