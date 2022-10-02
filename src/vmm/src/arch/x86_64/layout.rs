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

/// Address of the hvm_start_info struct used in PVH boot
pub const PVH_INFO_START: u64 = 0x6000;

/// The 'zero page', a.k.a linux kernel bootparams.
pub const ZERO_PAGE_START: u64 = 0x7000;

/// APIC address
pub const APIC_ADDR: u32 = 0xfee0_0000;

/// IOAPIC address
pub const IOAPIC_ADDR: u32 = 0xfec0_0000;

/// Location of RSDP pointer in x86 machines
pub const RSDP_ADDR: u64 = 0x000e_0000;

/// Start of memory region we will use for system data (MPTable, ACPI, etc). We are putting its
/// start address where EBDA normally starts, i.e. in the last 1 KiB of the first 640KiB of memory
pub const SYSTEM_MEM_START: u64 = 0x9fc00;

/// Size of memory region for system data.
///
/// We reserve the memory between the start of the EBDA up until the location of RSDP pointer,
/// [0x9fc00, 0xe0000) for system data. This is 257 KiB of memory we is enough for our needs and
/// future proof.
///
/// For ACPI we currently need:
///
/// FADT size: 276 bytes
/// XSDT size: 52 bytes (header: 36 bytes, plus pointers of FADT and MADT)
/// MADT size: 2104 bytes (header: 44 bytes, IO-APIC: 12 bytes, LocalAPIC: 8 * #vCPUS)
/// DSDT size: 1907 bytes (header: 36 bytes, legacy devices: 345, GED: 161, VMGenID: 87, VirtIO
///   devices: 71 bytes per device)
///
/// The above assumes a maximum of 256 vCPUs, because that's what ACPI allows, but currently
/// we have a hard limit of up to 32 vCPUs.
///
/// Moreover, for MPTable we need up to 5304 bytes (284 + 20 * #vCPUS) assuming again
/// a maximum number of 256 vCPUs.
///
/// 257KiB is more than we need, however we reserve this space for potential future use of
/// ACPI features (new tables and/or devices).
pub const SYSTEM_MEM_SIZE: u64 = RSDP_ADDR - SYSTEM_MEM_START;
