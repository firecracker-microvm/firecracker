// Copyright © 2024, Institute of Software, CAS. All rights reserved.
// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

//
// Memory layout of riscv64 guest:
//
// RAM end    +---------------------------------------------------------------+
// (dynamic,  |                                                               |
// including  |                                                               |
// hotplug    ~                   ~                       ~                   ~
// memory)    |                                                               |
//            |                            DRAM                               |
//            ~                   ~                       ~                   ~
//            |                                                               |
//            |                                                               |
// 0x80000000 +---------------------------------------------------------------+
//            |                             ...                               |
// 0x08100000 +---------------------------------------------------------------+
//            |                                                               |
//            |                           VIRTIO (0x1000)                     |
//            |                                                               |
// 0x08002000 +---------------------------------------------------------------+
//            |                             RTC (0x1000)                      |
// 0x08001000 +---------------------------------------------------------------|
//            |                            UART (0x100)                       |
// 0x08000000 +---------------------------------------------------------------+
//            |                                                               |
//  (64M)     |                           IMSICs                              |
//            |                                                               |
// 0x04000000 +---------------------------------------------------------------+
//            |                                                               |
//  (64M)     |                           APLICs                              |
//            |                                                               |
// 0 GB       +---------------------------------------------------------------+
//

/// Start of RAM.
pub const DRAM_MEM_START: u64 = 0x8000_0000; // 2 GB.

pub const SYSTEM_MEM_START: u64 = 0;

/// Kernel start with a 2MiB shift.
pub const KERNEL_OFFSET: u64 = 0x20_0000;

pub const INITRD_ALIGN: u64 = 8;
pub const FDT_ALIGN: u64 = 0x40_0000;

/// 0x0800_2000 ~ 0x0810_0000 is reserved for VIRTIO devices.
pub const VIRTIO_START: u64 = 0x0800_2000;
pub const VIRTIO_SIZE: u64 = 0x1000;

/// 0x0800_1000 ~ 0x0800_2000 is reserved for RTC devices.
pub const RTC_START: u64 = 0x0800_1000;
pub const RTC_SIZE: u64 = 0x1000;

/// 0x0800_0000 ~ 0x0800_1000 is reserved for UART devices.
pub const UART_START: u64 = 0x0800_0000;
pub const UART_SIZE: u64 = 0x0100;

/// AIA related devices
/// See https://elixir.bootlin.com/linux/v6.10/source/arch/riscv/include/uapi/asm/kvm.h
/// 0x0400_0000 ~ 0x0800_0000 (64 MiB) resides IMSICs
pub const IMSIC_START: u64 = 0x0400_0000;
pub const IMSIC_SIZE: u64 = 0x0400_0000;

/// 0x0 ~ 0x0400_0000 (64 MiB) resides APLICs
pub const APLIC_START: u64 = 0;
pub const APLIC_SIZE: u64 = 0x0400_0000;

/// Kernel command line maximum size on RISC-V.
/// See https://elixir.bootlin.com/linux/v6.10/source/arch/riscv/include/uapi/asm/setup.h
pub const CMDLINE_MAX_SIZE: usize = 1024;

pub const FDT_MAX_SIZE: usize = 0x1_0000;

/// First usable interrupt on riscv64.
pub const IRQ_BASE: u32 = 1;
