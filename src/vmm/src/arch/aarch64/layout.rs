// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//      ==== Address map in use in ARM development systems today ====
//
//              - 32-bit -              - 36-bit -          - 40-bit -
// 1024GB   +                   +                       +-------------------+     <- 40-bit
//          |                                           | DRAM              |
//          ~                   ~                       ~                   ~
//          |                                           |                   |
//          |                                           |                   |
//          |                                           |                   |
//          |                                           |                   |
// 544GB    +                   +                       +-------------------+
//          |                                           | Hole or DRAM      |
//          |                                           |                   |
// 512GB    +                   +                       +-------------------+
//          |                                           |       Mapped      |
//          |                                           |       I/O         |
//          ~                   ~                       ~                   ~
//          |                                           |                   |
// 256GB    +                   +                       +-------------------+
//          |                                           |       Reserved    |
//          ~                   ~                       ~                   ~
//          |                                           |                   |
// 64GB     +                   +-----------------------+-------------------+   <- 36-bit
//          |                   |                   DRAM                    |
//          ~                   ~                   ~                       ~
//          |                   |                                           |
//          |                   |                                           |
// 34GB     +                   +-----------------------+-------------------+
//          |                   |                  Hole or DRAM             |
// 32GB     +                   +-----------------------+-------------------+
//          |                   |                   Mapped I/O              |
//          ~                   ~                       ~                   ~
//          |                   |                                           |
// 16GB     +                   +-----------------------+-------------------+
//          |                   |                   Reserved                |
//          ~                   ~                       ~                   ~
// 4GB      +-------------------+-----------------------+-------------------+   <- 32-bit
//          |           2GB of DRAM                                         |
//          |                                                               |
// 2GB      +-------------------+-----------------------+-------------------+
//          |                           Mapped I/O                          |
// 1GB      +-------------------+-----------------------+-------------------+
//          |                          ROM & RAM & I/O                      |
// 0GB      +-------------------+-----------------------+-------------------+   0
//              - 32-bit -              - 36-bit -              - 40-bit -
//
// Taken from (http://infocenter.arm.com/help/topic/com.arm.doc.den0001c/DEN0001C_principles_of_arm_memory_maps.pdf).

use crate::device_manager::mmio::MMIO_LEN;

/// Start of RAM on 64 bit ARM.
pub const DRAM_MEM_START: u64 = 0x8000_0000; // 2 GB.
/// The maximum RAM size.
pub const DRAM_MEM_MAX_SIZE: usize = 0x00FF_8000_0000; // 1024 - 2 = 1022G.

/// Start of RAM on 64 bit ARM.
pub const SYSTEM_MEM_START: u64 = DRAM_MEM_START;

/// This is used by ACPI device manager for acpi tables or devices like vmgenid
/// In reality, 2MBs is an overkill, but immediately after this we write the kernel
/// image, which needs to be 2MB aligned.
pub const SYSTEM_MEM_SIZE: u64 = 0x20_0000;

/// Kernel command line maximum size.
/// As per `arch/arm64/include/uapi/asm/setup.h`.
pub const CMDLINE_MAX_SIZE: usize = 2048;

/// Maximum size of the device tree blob as specified in https://www.kernel.org/doc/Documentation/arm64/booting.txt.
pub const FDT_MAX_SIZE: usize = 0x20_0000;

// As per virt/kvm/arm/vgic/vgic-kvm-device.c we need
// the number of interrupts our GIC will support to be:
// * bigger than 32
// * less than 1023 and
// * a multiple of 32.
// The first 32 SPIs are reserved, but KVM already shifts the gsi we
// pass, so we go from 0 to 95 for legacy gsis ("irq") and the remaining
// we use for MSI.
/// Offset of first SPI in the GIC
pub const SPI_START: u32 = 32;
/// Last possible SPI in the GIC (128 total SPIs)
pub const SPI_END: u32 = 127;
/// First usable GSI id on aarch64 (corresponds to SPI #32).
pub const GSI_LEGACY_START: u32 = 0;
/// There are 128 SPIs available, but the first 32 are reserved
pub const GSI_LEGACY_NUM: u32 = SPI_END - SPI_START + 1;
/// Last available GSI
pub const GSI_LEGACY_END: u32 = GSI_LEGACY_START + GSI_LEGACY_NUM - 1;
/// First GSI used by MSI after legacy GSI
pub const GSI_MSI_START: u32 = GSI_LEGACY_END + 1;
/// The highest available GSI in KVM (KVM_MAX_IRQ_ROUTES=4096)
pub const GSI_MSI_END: u32 = 4095;
/// Number of GSI available for MSI.
pub const GSI_MSI_NUM: u32 = GSI_MSI_END - GSI_MSI_START + 1;

/// The start of the memory area reserved for MMIO 32-bit accesses.
/// Below this address will reside the GIC, above this address will reside the MMIO devices.
pub const MMIO32_MEM_START: u64 = 1 << 30; // 1GiB
/// The size of the memory area reserved for MMIO 32-bit accesses (1GiB).
pub const MMIO32_MEM_SIZE: u64 = DRAM_MEM_START - MMIO32_MEM_START;

// The rest of the MMIO address space (256 MiB) we dedicate to PCIe for memory-mapped access to
// configuration.
/// Size of MMIO region for PCIe configuration accesses.
pub const PCI_MMCONFIG_SIZE: u64 = 256 << 20;
/// Start of MMIO region for PCIe configuration accesses.
pub const PCI_MMCONFIG_START: u64 = DRAM_MEM_START - PCI_MMCONFIG_SIZE;
/// MMIO space per PCIe segment
pub const PCI_MMIO_CONFIG_SIZE_PER_SEGMENT: u64 = 4096 * 256;

// We reserve 768 MiB for devices at the beginning of the MMIO region. This includes space both for
// pure MMIO and PCIe devices.

/// Memory region start for boot device.
pub const BOOT_DEVICE_MEM_START: u64 = MMIO32_MEM_START;
/// Memory region start for RTC device.
pub const RTC_MEM_START: u64 = BOOT_DEVICE_MEM_START + MMIO_LEN;
/// Memory region start for Serial device.
pub const SERIAL_MEM_START: u64 = RTC_MEM_START + MMIO_LEN;

/// Beginning of memory region for device MMIO 32-bit accesses
pub const MEM_32BIT_DEVICES_START: u64 = SERIAL_MEM_START + MMIO_LEN;
/// Size of memory region for device MMIO 32-bit accesses
pub const MEM_32BIT_DEVICES_SIZE: u64 = PCI_MMCONFIG_START - MEM_32BIT_DEVICES_START;

// 64-bits region for MMIO accesses
/// The start of the memory area reserved for MMIO 64-bit accesses.
pub const MMIO64_MEM_START: u64 = 256 << 30;
/// The size of the memory area reserved for MMIO 64-bit accesses.
pub const MMIO64_MEM_SIZE: u64 = 256 << 30;

// At the moment, all of this region goes to devices
/// Beginning of memory region for device MMIO 64-bit accesses
pub const MEM_64BIT_DEVICES_START: u64 = MMIO64_MEM_START;
/// Size of memory region for device MMIO 32-bit accesses
pub const MEM_64BIT_DEVICES_SIZE: u64 = MMIO64_MEM_SIZE;
/// First address past the 64-bit MMIO gap
pub const FIRST_ADDR_PAST_64BITS_MMIO: u64 = MMIO64_MEM_START + MMIO64_MEM_SIZE;
/// Size of the memory past 64-bit MMIO gap
pub const PAST_64BITS_MMIO_SIZE: u64 = 512 << 30;
