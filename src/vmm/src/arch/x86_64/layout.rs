// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Magic addresses externally used to lay out x86_64 VMs.

use crate::device_manager::mmio::MMIO_LEN;
use crate::utils::mib_to_bytes;

/// Initial stack for the boot CPU.
pub const BOOT_STACK_POINTER: u64 = 0x8ff0;

/// Kernel command line start address.
pub const CMDLINE_START: u64 = 0x20000;
/// Kernel command line maximum size.
pub const CMDLINE_MAX_SIZE: usize = 2048;

/// Start of the high memory.
pub const HIMEM_START: u64 = 0x0010_0000; // 1 MB.

// Typically, on x86 systems 24 IRQs are used for legacy devices (0-23).
// However, the first 5 are reserved.
// We allocate the remaining GSIs to MSIs.
/// First usable GSI for legacy interrupts (IRQ) on x86_64.
pub const GSI_LEGACY_START: u32 = 5;
/// Last usable GSI for legacy interrupts (IRQ) on x86_64.
pub const GSI_LEGACY_END: u32 = 23;
/// Number of legacy GSI (IRQ) available on x86_64.
pub const GSI_LEGACY_NUM: u32 = GSI_LEGACY_END - GSI_LEGACY_START + 1;
/// First GSI used by MSI after legacy GSI.
pub const GSI_MSI_START: u32 = GSI_LEGACY_END + 1;
/// The highest available GSI in KVM (KVM_MAX_IRQ_ROUTES=4096).
pub const GSI_MSI_END: u32 = 4095;
/// Number of GSI available for MSI.
pub const GSI_MSI_NUM: u32 = GSI_MSI_END - GSI_MSI_START + 1;

/// Address for the TSS setup.
pub const KVM_TSS_ADDRESS: u64 = 0xfffb_d000;

/// Address of the hvm_start_info struct used in PVH boot
pub const PVH_INFO_START: u64 = 0x6000;

/// Starting address of array of modules of hvm_modlist_entry type.
/// Used to enable initrd support using the PVH boot ABI.
pub const MODLIST_START: u64 = 0x6040;

/// Address of memory map table used in PVH boot. Can overlap
/// with the zero page address since they are mutually exclusive.
pub const MEMMAP_START: u64 = 0x7000;

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

/// First address that cannot be addressed using 32 bit anymore.
pub const FIRST_ADDR_PAST_32BITS: u64 = 1 << 32;

/// The size of the memory area reserved for MMIO 32-bit accesses.
pub const MMIO32_MEM_SIZE: u64 = mib_to_bytes(1024) as u64;
/// The start of the memory area reserved for MMIO 32-bit accesses.
pub const MMIO32_MEM_START: u64 = FIRST_ADDR_PAST_32BITS - MMIO32_MEM_SIZE;

// We dedicate the last 256 MiB of the 32-bit MMIO address space PCIe for memory-mapped access to
// configuration.
/// Size of MMIO region for PCIe configuration accesses.
pub const PCI_MMCONFIG_SIZE: u64 = 256 << 20;
/// Start of MMIO region for PCIe configuration accesses.
pub const PCI_MMCONFIG_START: u64 = IOAPIC_ADDR as u64 - PCI_MMCONFIG_SIZE;
/// MMIO space per PCIe segment
pub const PCI_MMIO_CONFIG_SIZE_PER_SEGMENT: u64 = 4096 * 256;

// We reserve 768 MiB for devices at the beginning of the MMIO region. This includes space both for
// pure MMIO and PCIe devices.

/// Memory region start for boot device.
pub const BOOT_DEVICE_MEM_START: u64 = MMIO32_MEM_START;

/// Beginning of memory region for device MMIO 32-bit accesses
pub const MEM_32BIT_DEVICES_START: u64 = BOOT_DEVICE_MEM_START + MMIO_LEN;
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
