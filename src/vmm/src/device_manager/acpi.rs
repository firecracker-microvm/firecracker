// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use acpi_tables::{Aml, aml};
use kvm_ioctls::VmFd;

use crate::devices::acpi::vmgenid::VmGenId;

#[derive(Debug)]
pub struct ACPIDeviceManager {
    /// VMGenID device
    pub vmgenid: Option<VmGenId>,
}

impl ACPIDeviceManager {
    /// Create a new ACPIDeviceManager object
    pub fn new() -> Self {
        Self { vmgenid: None }
    }

    /// Attach a new VMGenID device to the microVM
    ///
    /// This will register the device's interrupt with KVM
    pub fn attach_vmgenid(
        &mut self,
        vmgenid: VmGenId,
        vm_fd: &VmFd,
    ) -> Result<(), kvm_ioctls::Error> {
        vm_fd.register_irqfd(&vmgenid.interrupt_evt, vmgenid.gsi)?;
        self.vmgenid = Some(vmgenid);
        Ok(())
    }

    /// If it exists, notify guest VMGenID device that we have resumed from a snapshot.
    pub fn notify_vmgenid(&mut self) -> Result<(), std::io::Error> {
        if let Some(vmgenid) = &mut self.vmgenid {
            vmgenid.notify_guest()?;
        }
        Ok(())
    }
}

impl Aml for ACPIDeviceManager {
    fn append_aml_bytes(&self, v: &mut Vec<u8>) -> Result<(), aml::AmlError> {
        // If we have a VMGenID device, create the AML for the device and GED interrupt handler
        match self.vmgenid.as_ref() {
            Some(vmgenid) => {
                // AML for GED
                aml::Device::new(
                    "_SB_.GED_".try_into()?,
                    vec![
                        &aml::Name::new("_HID".try_into()?, &"ACPI0013")?,
                        &aml::Name::new(
                            "_CRS".try_into()?,
                            &aml::ResourceTemplate::new(vec![&aml::Interrupt::new(
                                true,
                                true,
                                false,
                                false,
                                vmgenid.gsi,
                            )]),
                        )?,
                        &aml::Method::new(
                            "_EVT".try_into()?,
                            1,
                            true,
                            vec![&aml::If::new(
                                // We know that the maximum IRQ number fits in a u8. We have up to
                                // 32 IRQs in x86 and up to 128 in
                                // ARM (look into
                                // `vmm::crate::arch::layout::IRQ_MAX`)
                                #[allow(clippy::cast_possible_truncation)]
                                &aml::Equal::new(&aml::Arg(0), &(vmgenid.gsi as u8)),
                                vec![&aml::Notify::new(
                                    &aml::Path::new("\\_SB_.VGEN")?,
                                    &0x80usize,
                                )],
                            )],
                        ),
                    ],
                )
                .append_aml_bytes(v)?;
                // AML for VMGenID itself.
                vmgenid.append_aml_bytes(v)
            }
            None => Ok(()),
        }
    }
}
