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

/// Where BIOS/VGA magic would live on a real PC.
pub const EBDA_START: u64 = 0x000a_0000;

// Put it at the beginning of the EBDA region
/// Address of the RSDP ACPI structure
pub const RSDP_ADDR: u64 = EBDA_START;

/// The EBDA region ends at 0x000f_ffff (HIMEM_START), which makes it
/// 384KiB long
pub const EBDA_SIZE: u64 = HIMEM_START - EBDA_START;

/// Start of the high memory.
pub const HIMEM_START: u64 = 0x0010_0000; // 1 MB.

// Typically, on x86 systems 24 IRQs are used (0-23).
// IRQs from 0 to 4 are used by Port IO devices
// IRQs from 5 to 23 are used by MMIO and ACPI devices
/// First usable IRQ ID for non-legacy device interrupts on x86_64.
pub const IRQ_BASE: u32 = 5;
/// Last usable IRQ ID for non-legacy device interrupts on x86_64.
pub const IRQ_MAX: u32 = 23;

/// Address for the TSS setup.
pub const KVM_TSS_ADDRESS: u64 = 0xfffb_d000;

/// The 'zero page', a.k.a linux kernel bootparams.
pub const ZERO_PAGE_START: u64 = 0x7000;
