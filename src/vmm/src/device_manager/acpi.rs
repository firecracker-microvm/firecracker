// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Mutex};

use acpi_tables::{aml, Aml};
use kvm_ioctls::VmFd;

use crate::devices::acpi::cpu_container::CpuContainer;
use crate::devices::acpi::vmgenid::VmGenId;

#[derive(Debug)]
pub struct ACPIDeviceManager {
    /// VMGenID device
    pub vmgenid: Option<VmGenId>,
    pub cpu_container: Option<Arc<Mutex<CpuContainer>>>,
}

impl ACPIDeviceManager {
    /// Create a new ACPIDeviceManager object
    pub fn new() -> Self {
        Self {
            vmgenid: None,
            cpu_container: None,
        }
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

    pub fn attach_cpu_container(
        &mut self,
        cpu_container: Arc<Mutex<CpuContainer>>,
        vm_fd: &VmFd,
    ) -> Result<(), kvm_ioctls::Error> {
        {
            let locked_container = cpu_container.lock().expect("Poisoned lock");
            vm_fd.register_irqfd(&locked_container.acpi_interrupt_evt, locked_container.gsi)?;
        }
        self.cpu_container = Some(cpu_container);
        Ok(())
    }

    pub fn notify_cpu_container(&mut self) -> Result<(), std::io::Error> {
        if let Some(container) = &mut self.cpu_container {
            container.lock().expect("Poisoned lock").notify_guest()?;
        }
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
    fn append_aml_bytes(&self, v: &mut Vec<u8>) {
        // Depending on what devices are available, generate AML for GED.
        match (self.cpu_container.as_ref(), self.vmgenid.as_ref()) {
            (Some(container), Some(vmgenid)) => {
                let locked_container = container.lock().expect("Poisoned lock");
                aml::Device::new(
                    "_SB_.GED_".into(),
                    vec![
                        &aml::Name::new("_HID".into(), &"ACPI0013"),
                        &aml::Name::new(
                            "_CRS".into(),
                            &aml::ResourceTemplate::new(vec![
                                &aml::Interrupt::new(
                                    true,
                                    true,
                                    false,
                                    false,
                                    locked_container.gsi,
                                ),
                                &aml::Interrupt::new(true, true, false, false, vmgenid.gsi),
                            ]),
                        ),
                        &aml::Method::new(
                            "_EVT".into(),
                            1,
                            true,
                            vec![
                                &aml::If::new(
                                    #[allow(clippy::cast_possible_truncation)]
                                    &aml::Equal::new(&aml::Arg(0), &(locked_container.gsi as u8)),
                                    vec![&aml::MethodCall::new(
                                        aml::Path::new("\\_SB_.CPUS.CSCN"),
                                        vec![],
                                    )],
                                ),
                                &aml::If::new(
                                    #[allow(clippy::cast_possible_truncation)]
                                    &aml::Equal::new(&aml::Arg(0), &(vmgenid.gsi as u8)),
                                    vec![&aml::Notify::new(
                                        &aml::Path::new("\\_SB_.VGEN"),
                                        &0x80usize,
                                    )],
                                ),
                            ],
                        ),
                    ],
                )
                .append_aml_bytes(v);
                locked_container.append_aml_bytes(v);
                vmgenid.append_aml_bytes(v);
            }
            (Some(container), None) => {
                let locked_container = container.lock().expect("Poisoned lock");
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
                                locked_container.gsi,
                            )]),
                        ),
                        &aml::Method::new(
                            "_EVT".into(),
                            1,
                            true,
                            vec![&aml::If::new(
                                #[allow(clippy::cast_possible_truncation)]
                                &aml::Equal::new(&aml::Arg(0), &(locked_container.gsi as u8)),
                                vec![&aml::MethodCall::new(
                                    aml::Path::new("\\_SB_.CPUS.CSCN"),
                                    vec![],
                                )],
                            )],
                        ),
                    ],
                )
                .append_aml_bytes(v);
                locked_container.append_aml_bytes(v);
            }
            (None, Some(vmgenid)) => {
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
                vmgenid.append_aml_bytes(v);
            }
            (None, None) => {
                aml::Device::new(
                    "_SB_.GED_".into(),
                    vec![
                        &aml::Name::new("_HID".into(), &"ACPI0013"),
                        &aml::Name::new("_CRS".into(), &aml::ResourceTemplate::new(vec![])),
                        &aml::Method::new("_EVT".into(), 1, true, vec![]),
                    ],
                )
                .append_aml_bytes(v);
            }
        }
    }
}
