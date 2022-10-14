// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::mem::size_of;

use vm_memory::ByteValued;

use crate::fadt::Fadt;

// Disable VGA probing
const IAPC_BOOT_ARG_FLAGS_VGA_NOT_PRESENT: u8 = 2;
// Do not enable MSI
const IAPC_BOOT_ARG_FLAGS_MSI_NOT_PRESENT: u8 = 3;
// Do not enable ASPM control
const IAPC_BOOT_ARG_FLAGS_PCI_ASPM: u8 = 4;

/// x86-specific FADT initialization
#[inline(always)]
pub(crate) fn fadt_platform_init(fadt: &mut Fadt) {
    // Disable probing for VGA, enabling MSI and PCI ASPM Controls,
    // maybe we can speed-up a bit booting
    fadt._iapc_boot_arch = 1 << IAPC_BOOT_ARG_FLAGS_VGA_NOT_PRESENT
        | 1 << IAPC_BOOT_ARG_FLAGS_MSI_NOT_PRESENT
        | 1 << IAPC_BOOT_ARG_FLAGS_PCI_ASPM;
}

const MADT_CPU_ENABLE_FLAG: usize = 0;

/// Processor Local APIC structure
#[repr(packed)]
#[derive(Copy, Clone, Default)]
pub struct LocalAPIC {
    _type: u8,
    _length: u8,
    _processor_uid: u8,
    _apic_id: u8,
    _flags: u32,
}

unsafe impl ByteValued for LocalAPIC {}

impl LocalAPIC {
    pub fn new(cpu_id: u8) -> Self {
        Self {
            _type: 0,
            _length: 8,
            _processor_uid: cpu_id,
            _apic_id: cpu_id,
            _flags: 1 << MADT_CPU_ENABLE_FLAG,
        }
    }
}

impl From<LocalAPIC> for Vec<u8> {
    fn from(lapic: LocalAPIC) -> Self {
        lapic.as_slice().to_owned()
    }
}

/// I/O APIC Structure
#[repr(packed)]
#[derive(Copy, Clone, Default)]
struct IoAPIC {
    _type: u8,
    _length: u8,
    _ioapic_id: u8,
    _reserved: u8,
    _apic_address: u32,
    _gsi_base: u32,
}

unsafe impl ByteValued for IoAPIC {}

impl IoAPIC {
    pub fn new(_ioapic_id: u8) -> Self {
        IoAPIC {
            _type: 1,
            _length: 12,
            _ioapic_id,
            _reserved: 0,
            _apic_address: arch::IO_APIC_DEFAULT_PHYS_BASE,
            _gsi_base: 0,
        }
    }
}

/// Create the APIC data structures for x86_64 architectures
///
/// We create one Local APIC structure per CPU and one I/O APIC
pub(crate) fn create_apic_structures(num_cpus: usize) -> Vec<u8> {
    let mut interrupt_controllers =
        Vec::with_capacity(num_cpus * size_of::<LocalAPIC>() + size_of::<IoAPIC>());

    (0..num_cpus).for_each(|cpu_id| {
        interrupt_controllers.extend(LocalAPIC::new(cpu_id as u8).as_slice());
    });

    interrupt_controllers.extend(IoAPIC::new(0).as_slice());

    interrupt_controllers
}

/// Returns the 32-bit guest physical address where each processor can access its local interrupt
/// controller
pub(crate) fn local_interrupt_controller_address() -> u32 {
    arch::APIC_DEFAULT_PHYS_BASE
}
