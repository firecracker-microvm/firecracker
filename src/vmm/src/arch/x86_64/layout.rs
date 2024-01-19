// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

/// Magic addresses externally used to lay out x86_64 VMs.

/// Initial stack for the boot CPU.
pub const BOOT_STACK_POINTER: u64 = 0x8ff0;

/// Kernel command line start address.
pub const CMDLINE_START: u64 = 0x20000;
/// Kernel command line maximum size.
pub const CMDLINE_MAX_SIZE: usize = 2048;

/// Start of the high memory.
pub const HIMEM_START: u64 = 0x0010_0000; // 1 MB.

// Typically, on x86 systems 24 IRQs are used (0-23).
/// First usable IRQ ID for virtio device interrupts on x86_64.
pub const IRQ_BASE: u32 = 5;
/// Last usable IRQ ID for virtio device interrupts on x86_64.
pub const IRQ_MAX: u32 = 23;

/// Address for the TSS setup.
pub const KVM_TSS_ADDRESS: u64 = 0xfffb_d000;

/// The 'zero page', a.k.a linux kernel bootparams.
pub const ZERO_PAGE_START: u64 = 0x7000;

/// APIC address
pub const APIC_ADDR: u32 = 0xfee0_0000;

/// IOAPIC address
pub const IOAPIC_ADDR: u32 = 0xfec0_0000;

/// Start of memory region we will use for ACPI data. We are putting them
/// where EBDA region would normally be, i.e. 0x9fc00.
pub const ACPI_MEM_START: u64 = 0x9fc00;

/// Size of memory region for ACPI data.
///
/// For the time being we allocate 3 pages, which is enough for our current needs and future proof.
/// The value is chosen based on the following calculations:
///
/// FADT size: 276 bytes
/// XSDT size: 52 bytes (header: 36 bytes, plus pointers of FADT and MADT)
/// MADT size: 2104 bytes (header: 44 bytes, IO-APIC: 12 bytes, LocalAPIC: 8 * #vCPUS)
/// DSDT size: 1907 bytes (header: 36 bytes, legacy devices: 345, GED: 161, VMGenID: 87,
///                        VirtIO devices: 71 bytes per device)
///
/// If we assume a maximum of 18 VirtIO devices and a maximum of 256 vCPUs (which is more
/// than what we actually support, but it is the max supported from ACPI), the above calculations
/// yield a bit more than 1 page (4096).
///         
/// VMGenID allocates one page of memory for the generation ID. So we reserve 3 pages of memory
/// to be on the safe side.
///
/// We are storing the ACPI data where EBDA would normally live, in range [0x9fc00, 0xa2c00).
pub const ACPI_MEM_SIZE: u64 = 3 * 4096;

/// Location of RSDP pointer in x86 machines
pub const RSDP_ADDR: u64 = 0x000e_0000;
