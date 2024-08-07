// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use acpi_tables::fadt::{FADT_F_HW_REDUCED_ACPI, FADT_F_PWR_BUTTON, FADT_F_SLP_BUTTON};
use acpi_tables::{Aml, Dsdt, Fadt, Madt, Rsdp, Sdt, Xsdt};
use log::{debug, error};
use vm_allocator::AllocPolicy;

use crate::acpi::x86_64::{
    apic_addr, rsdp_addr, setup_arch_dsdt, setup_arch_fadt, setup_interrupt_controllers,
};
use crate::device_manager::acpi::ACPIDeviceManager;
use crate::device_manager::mmio::MMIODeviceManager;
use crate::device_manager::resources::ResourceAllocator;
use crate::vstate::memory::{GuestAddress, GuestMemoryMmap};
use crate::Vcpu;

mod x86_64;

// Our (Original Equipment Manufacturer" (OEM) name. OEM is how ACPI names the manufacturer of the
// hardware that is exposed to the OS, through ACPI tables. The OEM name is passed in every ACPI
// table, to let the OS know that we are the owner of the table.
const OEM_ID: [u8; 6] = *b"FIRECK";

// In reality the OEM revision is per table and it defines the revision of the OEM's implementation
// of the particular ACPI table. For our purpose, we can set it to a fixed value for all the tables
const OEM_REVISION: u32 = 0;

// This is needed for an entry in the FADT table. Populating this entry in FADT is a way to let the
// guest know that it runs within a Firecracker microVM.
const HYPERVISOR_VENDOR_ID: [u8; 8] = *b"FIRECKVM";

#[derive(Debug, thiserror::Error, displaydoc::Display)]
/// Error type for ACPI related operations
pub enum AcpiError {
    /// Could not allocate resources: {0}
    VmAllocator(#[from] vm_allocator::Error),
    /// ACPI tables error: {0}
    AcpiTables(#[from] acpi_tables::AcpiError),
}

/// Helper type that holds the guest memory in which we write the tables in and a resource
/// allocator for allocating space for the tables
struct AcpiTableWriter<'a> {
    mem: &'a GuestMemoryMmap,
    resource_allocator: &'a mut ResourceAllocator,
}

impl<'a> AcpiTableWriter<'a> {
    /// Write a table in guest memory
    ///
    /// This will allocate enough space inside guest memory and write the table in the allocated
    /// buffer. It returns the address in which it wrote the table.
    fn write_acpi_table<S>(&mut self, table: &mut S) -> Result<u64, AcpiError>
    where
        S: Sdt,
    {
        let addr = self.resource_allocator.allocate_system_memory(
            table.len().try_into().unwrap(),
            1,
            AllocPolicy::FirstMatch,
        )?;

        table
            .write_to_guest(self.mem, GuestAddress(addr))
            .inspect_err(|err| error!("acpi: Could not write table in guest memory: {err}"))?;

        debug!(
            "acpi: Wrote table ({} bytes) at address: {:#010x}",
            table.len(),
            addr
        );

        Ok(addr)
    }

    /// Build the DSDT table for the guest
    fn build_dsdt(
        &mut self,
        mmio_device_manager: &MMIODeviceManager,
        acpi_device_manager: &ACPIDeviceManager,
    ) -> Result<u64, AcpiError> {
        let mut dsdt_data = Vec::new();

        // Virtio-devices DSDT data
        dsdt_data.extend_from_slice(&mmio_device_manager.dsdt_data);

        // Add GED and VMGenID AML data.
        acpi_device_manager.append_aml_bytes(&mut dsdt_data);

        // Architecture specific DSDT data
        setup_arch_dsdt(&mut dsdt_data);

        let mut dsdt = Dsdt::new(OEM_ID, *b"FCVMDSDT", OEM_REVISION, dsdt_data);
        self.write_acpi_table(&mut dsdt)
    }

    /// Build the FADT table for the guest
    ///
    /// This includes a pointer with the location of the DSDT in guest memory
    fn build_fadt(&mut self, dsdt_addr: u64) -> Result<u64, AcpiError> {
        let mut fadt = Fadt::new(OEM_ID, *b"FCVMFADT", OEM_REVISION);
        fadt.set_hypervisor_vendor_id(HYPERVISOR_VENDOR_ID);
        fadt.set_x_dsdt(dsdt_addr);
        fadt.set_flags(
            1 << FADT_F_HW_REDUCED_ACPI | 1 << FADT_F_PWR_BUTTON | 1 << FADT_F_SLP_BUTTON,
        );
        setup_arch_fadt(&mut fadt);
        self.write_acpi_table(&mut fadt)
    }

    /// Build the MADT table for the guest
    ///
    /// This includes information about the interrupt controllers supported in the platform
    fn build_madt(&mut self, nr_vcpus: u8) -> Result<u64, AcpiError> {
        let mut madt = Madt::new(
            OEM_ID,
            *b"FCVMMADT",
            OEM_REVISION,
            apic_addr(),
            setup_interrupt_controllers(nr_vcpus),
        );
        self.write_acpi_table(&mut madt)
    }

    /// Build the XSDT table for the guest
    ///
    /// Currently, we pass to the guest just FADT and MADT tables.
    fn build_xsdt(&mut self, fadt_addr: u64, madt_addr: u64) -> Result<u64, AcpiError> {
        let mut xsdt = Xsdt::new(
            OEM_ID,
            *b"FCMVXSDT",
            OEM_REVISION,
            vec![fadt_addr, madt_addr],
        );
        self.write_acpi_table(&mut xsdt)
    }

    /// Build the RSDP pointer for the guest.
    ///
    /// This will build the RSDP pointer which points to the XSDT table and write it in guest
    /// memory. The address in which we write RSDP is pre-determined for every architecture.
    /// We will not allocate arbitrary memory for it
    fn build_rsdp(&mut self, xsdt_addr: u64) -> Result<(), AcpiError> {
        let mut rsdp = Rsdp::new(OEM_ID, xsdt_addr);
        rsdp.write_to_guest(self.mem, rsdp_addr())
            .inspect_err(|err| error!("acpi: Could not write RSDP in guest memory: {err}"))?;

        debug!(
            "acpi: Wrote RSDP ({} bytes) at address: {:#010x}",
            rsdp.len(),
            rsdp_addr().0
        );
        Ok(())
    }
}

/// Create ACPI tables for the guest
///
/// This will create the ACPI tables needed to describe to the guest OS the available hardware,
/// such as interrupt controllers, vCPUs and VirtIO devices.
pub(crate) fn create_acpi_tables(
    mem: &GuestMemoryMmap,
    resource_allocator: &mut ResourceAllocator,
    mmio_device_manager: &MMIODeviceManager,
    acpi_device_manager: &ACPIDeviceManager,
    vcpus: &[Vcpu],
) -> Result<(), AcpiError> {
    let mut writer = AcpiTableWriter {
        mem,
        resource_allocator,
    };

    let dsdt_addr = writer.build_dsdt(mmio_device_manager, acpi_device_manager)?;
    let fadt_addr = writer.build_fadt(dsdt_addr)?;
    let madt_addr = writer.build_madt(vcpus.len().try_into().unwrap())?;
    let xsdt_addr = writer.build_xsdt(fadt_addr, madt_addr)?;
    writer.build_rsdp(xsdt_addr)
}

#[cfg(test)]
pub mod tests {
    use acpi_tables::Sdt;
    use vm_memory::Bytes;

    use crate::acpi::{AcpiError, AcpiTableWriter};
    use crate::arch::x86_64::layout::{SYSTEM_MEM_SIZE, SYSTEM_MEM_START};
    use crate::builder::tests::default_vmm;
    use crate::utilities::test_utils::arch_mem;

    struct MockSdt(Vec<u8>);

    impl Sdt for MockSdt {
        fn len(&self) -> usize {
            self.0.len()
        }

        fn write_to_guest<M: vm_memory::GuestMemory>(
            &mut self,
            mem: &M,
            address: vm_memory::GuestAddress,
        ) -> acpi_tables::Result<()> {
            mem.write_slice(&self.0, address)?;
            Ok(())
        }
    }

    // Currently we are allocating up to SYSTEM_MEM_SIZE memory for ACPI tables. We are allocating
    // using the FirstMatch policy, with an 1 byte alignment. This test checks that we are able to
    // allocate up to this size, and get back the expected addresses.
    #[test]
    fn test_write_acpi_table_memory_allocation() {
        // A mocke Vmm object with 128MBs of memory
        let mut vmm = default_vmm();
        let mut writer = AcpiTableWriter {
            mem: &vmm.guest_memory,
            resource_allocator: &mut vmm.resource_allocator,
        };

        // This should succeed
        let mut sdt = MockSdt(vec![0; 4096]);
        let addr = writer.write_acpi_table(&mut sdt).unwrap();
        assert_eq!(addr, SYSTEM_MEM_START);

        // Let's try to write two 4K pages plus one byte
        let mut sdt = MockSdt(vec![0; usize::try_from(SYSTEM_MEM_SIZE + 1).unwrap()]);
        let err = writer.write_acpi_table(&mut sdt).unwrap_err();
        assert!(
            matches!(
                err,
                AcpiError::VmAllocator(vm_allocator::Error::ResourceNotAvailable)
            ),
            "{:?}",
            err
        );

        // We are allocating memory for tables with alignment of 1 byte. All of these should
        // succeed.
        let mut sdt = MockSdt(vec![0; 5]);
        let addr = writer.write_acpi_table(&mut sdt).unwrap();
        assert_eq!(addr, SYSTEM_MEM_START + 4096);
        let mut sdt = MockSdt(vec![0; 2]);
        let addr = writer.write_acpi_table(&mut sdt).unwrap();
        assert_eq!(addr, SYSTEM_MEM_START + 4101);
        let mut sdt = MockSdt(vec![0; 4]);
        let addr = writer.write_acpi_table(&mut sdt).unwrap();
        assert_eq!(addr, SYSTEM_MEM_START + 4103);
        let mut sdt = MockSdt(vec![0; 8]);
        let addr = writer.write_acpi_table(&mut sdt).unwrap();
        assert_eq!(addr, SYSTEM_MEM_START + 4107);
        let mut sdt = MockSdt(vec![0; 16]);
        let addr = writer.write_acpi_table(&mut sdt).unwrap();
        assert_eq!(addr, SYSTEM_MEM_START + 4115);
    }

    // If, for whatever weird reason, we end up with microVM that has less memory than the maximum
    // address we allocate for ACPI tables, we would be able to allocate the tables but we would
    // not be able to write them. This is practically impossible in our case. If we get such a
    // guest memory, we won't be able to load the guest kernel, but the function does
    // return an error on this case, so let's just check that in case any of these assumptions
    // change in the future.
    #[test]
    fn test_write_acpi_table_small_memory() {
        let mut vmm = default_vmm();
        vmm.guest_memory = arch_mem(
            (SYSTEM_MEM_START + SYSTEM_MEM_SIZE - 8192)
                .try_into()
                .unwrap(),
        );
        let mut writer = AcpiTableWriter {
            mem: &vmm.guest_memory,
            resource_allocator: &mut vmm.resource_allocator,
        };

        let mut sdt = MockSdt(vec![0; usize::try_from(SYSTEM_MEM_SIZE - 4096).unwrap()]);
        let err = writer.write_acpi_table(&mut sdt).unwrap_err();
        assert!(
            matches!(
                err,
                AcpiError::AcpiTables(acpi_tables::AcpiError::GuestMemory(
                    vm_memory::GuestMemoryError::PartialBuffer {
                        expected: 259072,  // SYSTEM_MEM_SIZE - 4096
                        completed: 254976  // SYSTEM_MEM_SIZE - 8192
                    },
                ))
            ),
            "{:?}",
            err
        );
    }
}
