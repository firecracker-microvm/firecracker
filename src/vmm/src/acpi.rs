// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use acpi::{aml, AcpiError, Aml, Dsdt, Fadt, Madt, Rsdp, Sdt, Xsdt};
use vm_memory::{GuestAddress, GuestMemoryMmap};

use crate::resource_manager::{AllocPolicy, ResourceManager};

#[derive(Debug, thiserror::Error)]
pub enum AcpiConfigError {
    #[error("Could not allocate vm-allocator resource: {0}")]
    VmAllocator(#[from] vm_allocator::Error),
    /// Failed to register and IRQ file descriptor.
    #[error("Could not register IRQ fd: {0}")]
    RegisterIrqFd(#[from] kvm_ioctls::Error),
    /// Error handling ACPI tables
    #[error("ACPI tables error: {0}")]
    AcpiTable(#[from] AcpiError),
}

type Result<T> = std::result::Result<T, AcpiConfigError>;

/// ACPI configuration for a VM
///
/// At the moment, this does not store any information but in the future
/// we might want to store state so that we can modify it at runtime
/// (for example memory / CPU hotplugging)
pub(crate) struct AcpiConfig {
    devices: Vec<u8>,
}

impl AcpiConfig {
    /// Create a new ACPI configuration object
    pub(crate) fn new() -> Self {
        Self { devices: vec![] }
    }

    // Allocate some guest memory and write a table to it
    fn write_acpi_table(
        &mut self,
        resource_manager: &mut ResourceManager,
        mem: &GuestMemoryMmap,
        table: &dyn Sdt,
    ) -> Result<u64> {
        let addr = resource_manager.allocate_acpi_addresses(
            table.len() as u64,
            64,
            AllocPolicy::FirstMatch,
        )?;

        table.write_to_guest(mem, GuestAddress(addr))?;

        Ok(addr)
    }

    // Build the DSDT data of the microVM
    fn create_dsdt_data(&self) -> Vec<u8> {
        let mut dsdt_data = aml::Scope::new(
            "\\".into(),
            vec![&aml::Name::new(
                "_S5_".into(),
                &aml::Package::new(vec![&5u8, &aml::ZERO, &aml::ZERO, &aml::ZERO]),
            )],
        )
        .to_aml_bytes();

        dsdt_data.extend(&self.devices);

        dsdt_data
    }

    /// Add devices in ACPI configuration
    pub(crate) fn add_device(&mut self, device: &dyn Aml) {
        device.append_aml_bytes(&mut self.devices);
    }

    /// Create the ACPI tables and write them to guest
    pub(crate) fn create_acpi_tables(
        &mut self,
        resource_manager: &mut ResourceManager,
        guest_mem: &GuestMemoryMmap,
        nr_vcpus: usize,
    ) -> Result<()> {
        // Make sure we allocate space for the RSDP pointer at the address the OS
        // expects to find it
        let rsdp_addr = resource_manager.allocate_acpi_addresses(
            std::mem::size_of::<Rsdp>() as u64,
            arch::PAGE_SIZE as u64,
            AllocPolicy::ExactMatch(arch::get_rsdp_addr()),
        )?;

        let dsdt = Dsdt::new(self.create_dsdt_data());
        let dsdt_addr = self.write_acpi_table(resource_manager, guest_mem, &dsdt)?;

        let fadt = Fadt::new(dsdt_addr);
        let fadt_addr = self.write_acpi_table(resource_manager, guest_mem, &fadt)?;

        let madt = Madt::new(nr_vcpus);
        let madt_addr = self.write_acpi_table(resource_manager, guest_mem, &madt)?;

        let xsdt = Xsdt::new(vec![fadt_addr, madt_addr]);
        let xsdt_addr = self.write_acpi_table(resource_manager, guest_mem, &xsdt)?;

        let rsdp = Rsdp::new(xsdt_addr);
        rsdp.write_to_guest(guest_mem, GuestAddress(rsdp_addr))?;

        Ok(())
    }
}
