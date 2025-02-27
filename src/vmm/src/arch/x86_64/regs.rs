// Copyright © 2020, Oracle and/or its affiliates.
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::mem;

use kvm_bindings::{kvm_fpu, kvm_regs, kvm_sregs};
use kvm_ioctls::VcpuFd;

use super::super::{BootProtocol, EntryPoint};
use super::gdt::{gdt_entry, kvm_segment_from_gdt};
use crate::vstate::memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

// Initial pagetables.
const PML4_START: u64 = 0x9000;
const PDPTE_START: u64 = 0xa000;
const PDE_START: u64 = 0xb000;

/// Errors thrown while setting up x86_64 registers.
#[derive(Debug, thiserror::Error, displaydoc::Display, PartialEq, Eq)]
pub enum RegsError {
    /// Failed to get SREGs for this CPU: {0}
    GetStatusRegisters(kvm_ioctls::Error),
    /// Failed to set base registers for this CPU: {0}
    SetBaseRegisters(kvm_ioctls::Error),
    /// Failed to configure the FPU: {0}
    SetFPURegisters(kvm_ioctls::Error),
    /// Failed to set SREGs for this CPU: {0}
    SetStatusRegisters(kvm_ioctls::Error),
    /// Writing the GDT to RAM failed.
    WriteGDT,
    /// Writing the IDT to RAM failed
    WriteIDT,
    /// WritePDPTEAddress
    WritePDPTEAddress,
    /// WritePDEAddress
    WritePDEAddress,
    /// WritePML4Address
    WritePML4Address,
}

/// Error type for [`setup_fpu`].
#[derive(Debug, derive_more::From, PartialEq, Eq, thiserror::Error)]
#[error("Failed to setup FPU: {0}")]
pub struct SetupFpuError(vmm_sys_util::errno::Error);

/// Configure Floating-Point Unit (FPU) registers for a given CPU.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
///
/// # Errors
///
/// When [`kvm_ioctls::ioctls::vcpu::VcpuFd::set_fpu`] errors.
pub fn setup_fpu(vcpu: &VcpuFd) -> Result<(), SetupFpuError> {
    let fpu: kvm_fpu = kvm_fpu {
        fcw: 0x37f,
        mxcsr: 0x1f80,
        ..Default::default()
    };

    vcpu.set_fpu(&fpu).map_err(SetupFpuError)
}

/// Error type of [`setup_regs`].
#[derive(Debug, derive_more::From, PartialEq, Eq, thiserror::Error)]
#[error("Failed to setup registers: {0}")]
pub struct SetupRegistersError(vmm_sys_util::errno::Error);

/// Configure base registers for a given CPU.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
/// * `boot_ip` - Starting instruction pointer.
///
/// # Errors
///
/// When [`kvm_ioctls::ioctls::vcpu::VcpuFd::set_regs`] errors.
pub fn setup_regs(vcpu: &VcpuFd, entry_point: EntryPoint) -> Result<(), SetupRegistersError> {
    let regs: kvm_regs = match entry_point.protocol {
        BootProtocol::PvhBoot => kvm_regs {
            // Configure regs as required by PVH boot protocol.
            rflags: 0x0000_0000_0000_0002u64,
            rbx: super::layout::PVH_INFO_START,
            rip: entry_point.entry_addr.raw_value(),
            ..Default::default()
        },
        BootProtocol::LinuxBoot => kvm_regs {
            // Configure regs as required by Linux 64-bit boot protocol.
            rflags: 0x0000_0000_0000_0002u64,
            rip: entry_point.entry_addr.raw_value(),
            // Frame pointer. It gets a snapshot of the stack pointer (rsp) so that when adjustments
            // are made to rsp (i.e. reserving space for local variables or pushing
            // values on to the stack), local variables and function parameters are
            // still accessible from a constant offset from rbp.
            rsp: super::layout::BOOT_STACK_POINTER,
            // Starting stack pointer.
            rbp: super::layout::BOOT_STACK_POINTER,
            // Must point to zero page address per Linux ABI. This is x86_64 specific.
            rsi: super::layout::ZERO_PAGE_START,
            ..Default::default()
        },
    };

    vcpu.set_regs(&regs).map_err(SetupRegistersError)
}

/// Error type for [`setup_sregs`].
#[derive(Debug, thiserror::Error, displaydoc::Display, PartialEq, Eq)]
pub enum SetupSpecialRegistersError {
    /// Failed to get special registers: {0}
    GetSpecialRegisters(vmm_sys_util::errno::Error),
    /// Failed to configure segments and special registers: {0}
    ConfigureSegmentsAndSpecialRegisters(RegsError),
    /// Failed to setup page tables: {0}
    SetupPageTables(RegsError),
    /// Failed to set special registers: {0}
    SetSpecialRegisters(vmm_sys_util::errno::Error),
}

/// Configures the special registers and system page tables for a given CPU.
///
/// # Arguments
///
/// * `mem` - The memory that will be passed to the guest.
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
/// * `boot_prot` - The boot protocol being used.
///
/// # Errors
///
/// When:
/// - [`kvm_ioctls::ioctls::vcpu::VcpuFd::get_sregs`] errors.
/// - [`configure_segments_and_sregs`] errors.
/// - [`setup_page_tables`] errors
/// - [`kvm_ioctls::ioctls::vcpu::VcpuFd::set_sregs`] errors.
pub fn setup_sregs(
    mem: &GuestMemoryMmap,
    vcpu: &VcpuFd,
    boot_prot: BootProtocol,
) -> Result<(), SetupSpecialRegistersError> {
    let mut sregs: kvm_sregs = vcpu
        .get_sregs()
        .map_err(SetupSpecialRegistersError::GetSpecialRegisters)?;

    configure_segments_and_sregs(mem, &mut sregs, boot_prot)
        .map_err(SetupSpecialRegistersError::ConfigureSegmentsAndSpecialRegisters)?;
    if let BootProtocol::LinuxBoot = boot_prot {
        setup_page_tables(mem, &mut sregs).map_err(SetupSpecialRegistersError::SetupPageTables)?;
        // TODO(dgreid) - Can this be done once per system instead?
    }

    vcpu.set_sregs(&sregs)
        .map_err(SetupSpecialRegistersError::SetSpecialRegisters)
}

const BOOT_GDT_OFFSET: u64 = 0x500;
const BOOT_IDT_OFFSET: u64 = 0x520;

const BOOT_GDT_MAX: usize = 4;

const EFER_LMA: u64 = 0x400;
const EFER_LME: u64 = 0x100;

const X86_CR0_PE: u64 = 0x1;
const X86_CR0_ET: u64 = 0x10;
const X86_CR0_PG: u64 = 0x8000_0000;
const X86_CR4_PAE: u64 = 0x20;

fn write_gdt_table(table: &[u64], guest_mem: &GuestMemoryMmap) -> Result<(), RegsError> {
    let boot_gdt_addr = GuestAddress(BOOT_GDT_OFFSET);
    for (index, entry) in table.iter().enumerate() {
        let addr = guest_mem
            .checked_offset(boot_gdt_addr, index * mem::size_of::<u64>())
            .ok_or(RegsError::WriteGDT)?;
        guest_mem
            .write_obj(*entry, addr)
            .map_err(|_| RegsError::WriteGDT)?;
    }
    Ok(())
}

fn write_idt_value(val: u64, guest_mem: &GuestMemoryMmap) -> Result<(), RegsError> {
    let boot_idt_addr = GuestAddress(BOOT_IDT_OFFSET);
    guest_mem
        .write_obj(val, boot_idt_addr)
        .map_err(|_| RegsError::WriteIDT)
}

fn configure_segments_and_sregs(
    mem: &GuestMemoryMmap,
    sregs: &mut kvm_sregs,
    boot_prot: BootProtocol,
) -> Result<(), RegsError> {
    let gdt_table: [u64; BOOT_GDT_MAX] = match boot_prot {
        BootProtocol::PvhBoot => {
            // Configure GDT entries as specified by PVH boot protocol
            [
                gdt_entry(0, 0, 0),                // NULL
                gdt_entry(0xc09b, 0, 0xffff_ffff), // CODE
                gdt_entry(0xc093, 0, 0xffff_ffff), // DATA
                gdt_entry(0x008b, 0, 0x67),        // TSS
            ]
        }
        BootProtocol::LinuxBoot => {
            // Configure GDT entries as specified by Linux 64bit boot protocol
            [
                gdt_entry(0, 0, 0),            // NULL
                gdt_entry(0xa09b, 0, 0xfffff), // CODE
                gdt_entry(0xc093, 0, 0xfffff), // DATA
                gdt_entry(0x808b, 0, 0xfffff), // TSS
            ]
        }
    };

    let code_seg = kvm_segment_from_gdt(gdt_table[1], 1);
    let data_seg = kvm_segment_from_gdt(gdt_table[2], 2);
    let tss_seg = kvm_segment_from_gdt(gdt_table[3], 3);

    // Write segments
    write_gdt_table(&gdt_table[..], mem)?;
    sregs.gdt.base = BOOT_GDT_OFFSET;
    sregs.gdt.limit = u16::try_from(mem::size_of_val(&gdt_table)).unwrap() - 1;

    write_idt_value(0, mem)?;
    sregs.idt.base = BOOT_IDT_OFFSET;
    sregs.idt.limit = u16::try_from(mem::size_of::<u64>()).unwrap() - 1;

    sregs.cs = code_seg;
    sregs.ds = data_seg;
    sregs.es = data_seg;
    sregs.fs = data_seg;
    sregs.gs = data_seg;
    sregs.ss = data_seg;
    sregs.tr = tss_seg;

    match boot_prot {
        BootProtocol::PvhBoot => {
            sregs.cr0 = X86_CR0_PE | X86_CR0_ET;
            sregs.cr4 = 0;
        }
        BootProtocol::LinuxBoot => {
            // 64-bit protected mode
            sregs.cr0 |= X86_CR0_PE;
            sregs.efer |= EFER_LME | EFER_LMA;
        }
    }

    Ok(())
}

fn setup_page_tables(mem: &GuestMemoryMmap, sregs: &mut kvm_sregs) -> Result<(), RegsError> {
    // Puts PML4 right after zero page but aligned to 4k.
    let boot_pml4_addr = GuestAddress(PML4_START);
    let boot_pdpte_addr = GuestAddress(PDPTE_START);
    let boot_pde_addr = GuestAddress(PDE_START);

    // Entry covering VA [0..512GB)
    mem.write_obj(boot_pdpte_addr.raw_value() | 0x03, boot_pml4_addr)
        .map_err(|_| RegsError::WritePML4Address)?;

    // Entry covering VA [0..1GB)
    mem.write_obj(boot_pde_addr.raw_value() | 0x03, boot_pdpte_addr)
        .map_err(|_| RegsError::WritePDPTEAddress)?;
    // 512 2MB entries together covering VA [0..1GB). Note we are assuming
    // CPU supports 2MB pages (/proc/cpuinfo has 'pse'). All modern CPUs do.
    for i in 0..512 {
        mem.write_obj((i << 21) + 0x83u64, boot_pde_addr.unchecked_add(i * 8))
            .map_err(|_| RegsError::WritePDEAddress)?;
    }

    sregs.cr3 = boot_pml4_addr.raw_value();
    sregs.cr4 |= X86_CR4_PAE;
    sregs.cr0 |= X86_CR0_PG;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::cast_possible_truncation)]

    use kvm_ioctls::Kvm;

    use super::*;
    use crate::test_utils::single_region_mem;
    use crate::vstate::memory::{Bytes, GuestAddress, GuestMemoryMmap};

    fn read_u64(gm: &GuestMemoryMmap, offset: u64) -> u64 {
        let read_addr = GuestAddress(offset);
        gm.read_obj(read_addr).unwrap()
    }

    fn validate_segments_and_sregs(
        gm: &GuestMemoryMmap,
        sregs: &kvm_sregs,
        boot_prot: BootProtocol,
    ) {
        if let BootProtocol::LinuxBoot = boot_prot {
            assert_eq!(0xaf_9b00_0000_ffff, read_u64(gm, BOOT_GDT_OFFSET + 8));
            assert_eq!(0xcf_9300_0000_ffff, read_u64(gm, BOOT_GDT_OFFSET + 16));
            assert_eq!(0x8f_8b00_0000_ffff, read_u64(gm, BOOT_GDT_OFFSET + 24));

            assert_eq!(0xffff_ffff, sregs.tr.limit);

            assert!(sregs.cr0 & X86_CR0_PE != 0);
            assert!(sregs.efer & EFER_LME != 0 && sregs.efer & EFER_LMA != 0);
        } else {
            // Validate values that are specific to PVH boot protocol
            assert_eq!(0xcf_9b00_0000_ffff, read_u64(gm, BOOT_GDT_OFFSET + 8));
            assert_eq!(0xcf_9300_0000_ffff, read_u64(gm, BOOT_GDT_OFFSET + 16));
            assert_eq!(0x00_8b00_0000_0067, read_u64(gm, BOOT_GDT_OFFSET + 24));

            assert_eq!(0x67, sregs.tr.limit);
            assert_eq!(0, sregs.tr.g);

            assert!(sregs.cr0 & X86_CR0_PE != 0 && sregs.cr0 & X86_CR0_ET != 0);
            assert_eq!(0, sregs.cr4);
        }

        // Common settings for both PVH and Linux boot protocol
        assert_eq!(0x0, read_u64(gm, BOOT_GDT_OFFSET));
        assert_eq!(0x0, read_u64(gm, BOOT_IDT_OFFSET));

        assert_eq!(0, sregs.cs.base);
        assert_eq!(0xffff_ffff, sregs.ds.limit);
        assert_eq!(0x10, sregs.es.selector);
        assert_eq!(1, sregs.fs.present);
        assert_eq!(1, sregs.gs.g);
        assert_eq!(0, sregs.ss.avl);
        assert_eq!(0, sregs.tr.base);
        assert_eq!(0, sregs.tr.avl);
    }

    fn validate_page_tables(gm: &GuestMemoryMmap, sregs: &kvm_sregs) {
        assert_eq!(0xa003, read_u64(gm, PML4_START));
        assert_eq!(0xb003, read_u64(gm, PDPTE_START));
        for i in 0..512 {
            assert_eq!((i << 21) + 0x83u64, read_u64(gm, PDE_START + (i * 8)));
        }

        assert_eq!(PML4_START, sregs.cr3);
        assert!(sregs.cr4 & X86_CR4_PAE != 0);
        assert!(sregs.cr0 & X86_CR0_PG != 0);
    }

    #[test]
    fn test_setup_fpu() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        setup_fpu(&vcpu).unwrap();

        let expected_fpu: kvm_fpu = kvm_fpu {
            fcw: 0x37f,
            mxcsr: 0x1f80,
            ..Default::default()
        };
        let actual_fpu: kvm_fpu = vcpu.get_fpu().unwrap();
        // TODO: auto-generate kvm related structures with PartialEq on.
        assert_eq!(expected_fpu.fcw, actual_fpu.fcw);
        // Setting the mxcsr register from kvm_fpu inside setup_fpu does not influence anything.
        // See 'kvm_arch_vcpu_ioctl_set_fpu' from arch/x86/kvm/x86.c.
        // The mxcsr will stay 0 and the assert below fails. Decide whether or not we should
        // remove it at all.
        // assert!(expected_fpu.mxcsr == actual_fpu.mxcsr);
    }

    #[test]
    fn test_setup_regs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        let expected_regs: kvm_regs = kvm_regs {
            rflags: 0x0000_0000_0000_0002u64,
            rip: 1,
            rsp: super::super::layout::BOOT_STACK_POINTER,
            rbp: super::super::layout::BOOT_STACK_POINTER,
            rsi: super::super::layout::ZERO_PAGE_START,
            ..Default::default()
        };

        let entry_point: EntryPoint = EntryPoint {
            entry_addr: GuestAddress(expected_regs.rip),
            protocol: BootProtocol::LinuxBoot,
        };

        setup_regs(&vcpu, entry_point).unwrap();

        let actual_regs: kvm_regs = vcpu.get_regs().unwrap();
        assert_eq!(actual_regs, expected_regs);
    }

    #[test]
    fn test_setup_sregs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let gm = single_region_mem(0x10000);

        [BootProtocol::LinuxBoot, BootProtocol::PvhBoot]
            .iter()
            .for_each(|boot_prot| {
                vcpu.set_sregs(&Default::default()).unwrap();
                setup_sregs(&gm, &vcpu, *boot_prot).unwrap();

                let mut sregs: kvm_sregs = vcpu.get_sregs().unwrap();
                // for AMD KVM_GET_SREGS returns g = 0 for each kvm_segment.
                // We set it to 1, otherwise the test will fail.
                sregs.gs.g = 1;

                validate_segments_and_sregs(&gm, &sregs, *boot_prot);
                if let BootProtocol::LinuxBoot = *boot_prot {
                    validate_page_tables(&gm, &sregs);
                }
            });
    }

    #[test]
    fn test_write_gdt_table() {
        // Not enough memory for the gdt table to be written.
        let gm = single_region_mem(BOOT_GDT_OFFSET as usize);
        let gdt_table: [u64; BOOT_GDT_MAX] = [
            gdt_entry(0, 0, 0),            // NULL
            gdt_entry(0xa09b, 0, 0xfffff), // CODE
            gdt_entry(0xc093, 0, 0xfffff), // DATA
            gdt_entry(0x808b, 0, 0xfffff), // TSS
        ];
        write_gdt_table(&gdt_table, &gm).unwrap_err();

        // We allocate exactly the amount needed to write four u64 to `BOOT_GDT_OFFSET`.
        let gm =
            single_region_mem(BOOT_GDT_OFFSET as usize + (mem::size_of::<u64>() * BOOT_GDT_MAX));

        let gdt_table: [u64; BOOT_GDT_MAX] = [
            gdt_entry(0, 0, 0),            // NULL
            gdt_entry(0xa09b, 0, 0xfffff), // CODE
            gdt_entry(0xc093, 0, 0xfffff), // DATA
            gdt_entry(0x808b, 0, 0xfffff), // TSS
        ];
        write_gdt_table(&gdt_table, &gm).unwrap();
    }

    #[test]
    fn test_write_idt_table() {
        // Not enough memory for the a u64 value to fit.
        let gm = single_region_mem(BOOT_IDT_OFFSET as usize);
        let val = 0x100;
        write_idt_value(val, &gm).unwrap_err();

        let gm = single_region_mem(BOOT_IDT_OFFSET as usize + mem::size_of::<u64>());
        // We have allocated exactly the amount neded to write an u64 to `BOOT_IDT_OFFSET`.
        write_idt_value(val, &gm).unwrap();
    }

    #[test]
    fn test_configure_segments_and_sregs() {
        let mut sregs: kvm_sregs = Default::default();
        let gm = single_region_mem(0x10000);
        configure_segments_and_sregs(&gm, &mut sregs, BootProtocol::LinuxBoot).unwrap();

        validate_segments_and_sregs(&gm, &sregs, BootProtocol::LinuxBoot);

        configure_segments_and_sregs(&gm, &mut sregs, BootProtocol::PvhBoot).unwrap();

        validate_segments_and_sregs(&gm, &sregs, BootProtocol::PvhBoot);
    }

    #[test]
    fn test_setup_page_tables() {
        let mut sregs: kvm_sregs = Default::default();
        let gm = single_region_mem(PML4_START as usize);
        setup_page_tables(&gm, &mut sregs).unwrap_err();

        let gm = single_region_mem(PDPTE_START as usize);
        setup_page_tables(&gm, &mut sregs).unwrap_err();

        let gm = single_region_mem(PDE_START as usize);
        setup_page_tables(&gm, &mut sregs).unwrap_err();

        let gm = single_region_mem(0x10000);
        setup_page_tables(&gm, &mut sregs).unwrap();

        validate_page_tables(&gm, &sregs);
    }
}
