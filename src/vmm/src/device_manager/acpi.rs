// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::rc::Rc;

use acpi_tables::{aml, Aml};
use kvm_ioctls::VmFd;
use vm_memory::GuestAddress;

use super::resources::ResourceAllocator;
use crate::devices::acpi::vmgenid::{VmGenId, VmGenIdError};
use crate::vstate::memory::GuestMemoryMmap;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ACPIDeviceManagerError {
    /// Failed to allocate requested resource: {0}
    Allocator(#[from] vm_allocator::Error),
    /// Error in VMGenID device: {0}
    VmGenID(#[from] VmGenIdError),
    /// Error registering interrupt: {0}
    InterruptRegister(#[from] kvm_ioctls::Error),
}

#[derive(Debug)]
pub struct ACPIDeviceManager {
    resource_allocator: Rc<ResourceAllocator>,
    /// VMGenID device
    pub vmgenid: Option<VmGenId>,
}

impl ACPIDeviceManager {
    /// Create a new ACPIDeviceManager object
    pub fn new(resource_allocator: Rc<ResourceAllocator>) -> Self {
        Self {
            resource_allocator,
            vmgenid: None,
        }
    }

    /// Create a new VMGenID device
    ///
    /// This will allocate resources (guest memory and one interrupt line) for the device,
    /// build the device and registers its interrupt line with KVM.
    pub fn attach_vmgenid(
        &mut self,
        mem: &GuestMemoryMmap,
        vm_fd: &VmFd,
    ) -> Result<(), ACPIDeviceManagerError> {
        let gsi = self.resource_allocator.allocate_gsi(1)?;
        let addr = self.resource_allocator.allocate_acpi_memory(
            4096,
            8,
            vm_allocator::AllocPolicy::FirstMatch,
        )?;
        self.build_vmgenid(gsi[0], GuestAddress(addr), mem, vm_fd)
    }

    /// Create a new VMGenID device using the provided guest address for the generation ID and GSI
    /// number for the interrupt line.
    ///
    /// This will create the device and register the interrupt line with KVM.
    pub fn build_vmgenid(
        &mut self,
        gsi: u32,
        guest_address: GuestAddress,
        mem: &GuestMemoryMmap,
        vm_fd: &VmFd,
    ) -> Result<(), ACPIDeviceManagerError> {
        let vmgenid = VmGenId::new(guest_address, gsi, mem)?;
        vm_fd.register_irqfd(&vmgenid.interrupt_evt, vmgenid.gsi)?;
        self.vmgenid = Some(vmgenid);
        Ok(())
    }

    /// If it exists, notify guest VMGenID device that we have resumed from a snapshot.
    pub fn notify_vmgenid(&mut self) -> Result<(), VmGenIdError> {
        if let Some(vmgenid) = &mut self.vmgenid {
            vmgenid.notify_guest()?;
        }
        Ok(())
    }
}

impl Aml for ACPIDeviceManager {
    fn append_aml_bytes(&self, v: &mut Vec<u8>) {
        // If we have a VMGenID device, create the AML for the device and GED interrupt handler
        self.vmgenid.as_ref().inspect(|vmgenid| {
            // AML for GED
            aml::Device::new(
                "_SB_.GED_".into(),
                vec![
                    &aml::Name::new("_HID".into(), &"ACPI0013"),
                    &aml::Name::new(
                        "_CRS".into(),
                        &aml::ResourceTemplate::new(vec![&aml::Interrupt::new(
                            true,
                            true,
                            false,
                            false,
                            vmgenid.gsi,
                        )]),
                    ),
                    &aml::Method::new(
                        "_EVT".into(),
                        1,
                        true,
                        vec![&aml::If::new(
                            // We know that the maximum IRQ number fits in a u8. We have up to 32
                            // IRQs in x86 and up to 128 in ARM (look into
                            // `vmm::crate::arch::layout::IRQ_MAX`)
                            #[allow(clippy::cast_possible_truncation)]
                            &aml::Equal::new(&aml::Arg(0), &(vmgenid.gsi as u8)),
                            vec![&aml::Notify::new(
                                &aml::Path::new("\\_SB_.VGEN"),
                                &0x80usize,
                            )],
                        )],
                    ),
                ],
            )
            .append_aml_bytes(v);
            // AML for VMGenID itself.
            vmgenid.append_aml_bytes(v);
        });
    }
}
