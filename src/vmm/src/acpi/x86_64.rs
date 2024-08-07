// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::mem::size_of;

use acpi_tables::fadt::{
    IAPC_BOOT_ARG_FLAGS_MSI_NOT_PRESENT, IAPC_BOOT_ARG_FLAGS_PCI_ASPM,
    IAPC_BOOT_ARG_FLAGS_VGA_NOT_PRESENT,
};
use acpi_tables::madt::{IoAPIC, LocalAPIC};
use acpi_tables::Fadt;
use vm_memory::GuestAddress;
use zerocopy::AsBytes;

use crate::arch::x86_64::layout;
use crate::device_manager::legacy::PortIODeviceManager;
use crate::vmm_config::machine_config::MAX_SUPPORTED_VCPUS;

#[inline(always)]
pub(crate) fn setup_interrupt_controllers(nr_vcpus: u8) -> Vec<u8> {
    let mut ic = Vec::with_capacity(
        size_of::<IoAPIC>() + (MAX_SUPPORTED_VCPUS as usize) * size_of::<LocalAPIC>(),
    );

    ic.extend_from_slice(IoAPIC::new(0, layout::IOAPIC_ADDR).as_bytes());
    for i in 0..MAX_SUPPORTED_VCPUS {
        if i < nr_vcpus {
            ic.extend_from_slice(LocalAPIC::new(i, false).as_bytes());
        } else {
            ic.extend_from_slice(LocalAPIC::new(i, true).as_bytes())
        }
    }
    ic
}

#[inline(always)]
pub(crate) fn setup_arch_fadt(fadt: &mut Fadt) {
    // Let the guest kernel know that there is not VGA hardware present
    // neither do we support ASPM, or MSI type of interrupts.
    // More info here:
    // https://uefi.org/specs/ACPI/6.5/05_ACPI_Software_Programming_Model.html?highlight=0a06#ia-pc-boot-architecture-flags
    fadt.setup_iapc_flags(
        1 << IAPC_BOOT_ARG_FLAGS_VGA_NOT_PRESENT
            | 1 << IAPC_BOOT_ARG_FLAGS_PCI_ASPM
            | 1 << IAPC_BOOT_ARG_FLAGS_MSI_NOT_PRESENT,
    );
}

#[inline(always)]
pub(crate) fn setup_arch_dsdt(dsdt_data: &mut Vec<u8>) {
    PortIODeviceManager::append_aml_bytes(dsdt_data)
}

pub(crate) const fn apic_addr() -> u32 {
    layout::APIC_ADDR
}

pub(crate) const fn rsdp_addr() -> GuestAddress {
    GuestAddress(layout::RSDP_ADDR)
}
