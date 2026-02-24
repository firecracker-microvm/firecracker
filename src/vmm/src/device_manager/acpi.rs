// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_arch = "x86_64")]
use acpi_tables::{Aml, aml};

use crate::Vm;
use crate::devices::acpi::vmclock::{VmClock, VmClockError};
use crate::devices::acpi::vmgenid::{VmGenId, VmGenIdError};
use crate::vstate::memory::GuestMemoryMmap;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ACPIDeviceError {
    /// VMGenID: {0}
    VmGenId(#[from] VmGenIdError),
    /// VMClock: {0}
    VmClock(#[from] VmClockError),
    /// Could not register IRQ with KVM: {0}
    RegisterIrq(#[from] kvm_ioctls::Error),
}

// Although both VMGenID and VMClock devices are always present, they should be instantiated when
// they are attached to preserve the existing ordering of GSI allocation.
#[derive(Debug, Default)]
pub struct ACPIDeviceManager {
    /// VMGenID device
    vmgenid: Option<VmGenId>,
    /// VMclock device
    vmclock: Option<VmClock>,
}

impl ACPIDeviceManager {
    /// Create a new ACPIDeviceManager object
    pub fn new(vmgenid: VmGenId, vmclock: VmClock) -> Self {
        ACPIDeviceManager {
            vmgenid: Some(vmgenid),
            vmclock: Some(vmclock),
        }
    }

    pub fn attach_vmgenid(&mut self, vm: &Vm) -> Result<(), ACPIDeviceError> {
        self.vmgenid = Some(VmGenId::new(&mut vm.resource_allocator())?);
        Ok(())
    }

    pub fn attach_vmclock(&mut self, vm: &Vm) -> Result<(), ACPIDeviceError> {
        self.vmclock = Some(VmClock::new(&mut vm.resource_allocator())?);
        Ok(())
    }

    pub fn vmgenid(&self) -> &VmGenId {
        self.vmgenid.as_ref().expect("Missing VMGenID device")
    }

    pub fn vmclock(&self) -> &VmClock {
        self.vmclock.as_ref().expect("Missing VMClock device")
    }

    pub fn activate_vmgenid(&self, vm: &Vm) -> Result<(), ACPIDeviceError> {
        vm.register_irq(&self.vmgenid().interrupt_evt, self.vmgenid().gsi)?;
        self.vmgenid().activate(vm.guest_memory())?;
        Ok(())
    }

    pub fn activate_vmclock(&self, vm: &Vm) -> Result<(), ACPIDeviceError> {
        vm.register_irq(&self.vmclock().interrupt_evt, self.vmclock().gsi)?;
        self.vmclock().activate(vm.guest_memory())?;
        Ok(())
    }

    pub fn post_restore_vmgenid(&self) -> Result<(), ACPIDeviceError> {
        self.vmgenid().post_restore()?;
        Ok(())
    }

    pub fn post_restore_vmclock(&mut self, mem: &GuestMemoryMmap) -> Result<(), ACPIDeviceError> {
        self.vmclock
            .as_mut()
            .expect("Missing VMClock device")
            .post_restore(mem)?;
        Ok(())
    }
}

#[cfg(target_arch = "x86_64")]
impl Aml for ACPIDeviceManager {
    fn append_aml_bytes(&self, v: &mut Vec<u8>) -> Result<(), aml::AmlError> {
        // AML for [`VmGenId`] device.
        self.vmgenid().append_aml_bytes(v)?;
        // AML for [`VmClock`] device.
        self.vmclock().append_aml_bytes(v)?;

        // Create the AML for the GED interrupt handler
        aml::Device::new(
            "_SB_.GED_".try_into()?,
            vec![
                &aml::Name::new("_HID".try_into()?, &"ACPI0013")?,
                &aml::Name::new(
                    "_CRS".try_into()?,
                    &aml::ResourceTemplate::new(vec![
                        &aml::Interrupt::new(true, true, false, false, self.vmgenid().gsi),
                        &aml::Interrupt::new(true, true, false, false, self.vmclock().gsi),
                    ]),
                )?,
                // We know that the maximum IRQ number fits in a u8. We have up to
                // 32 IRQs in x86 and up to 128 in ARM (look into `vmm::crate::arch::layout::GSI_LEGACY_END`).
                // Both `vmgenid.gsi` and `vmclock.gsi` can safely be cast to `u8`
                // without truncation, so we let clippy know.
                &aml::Method::new(
                    "_EVT".try_into()?,
                    1,
                    true,
                    vec![
                        &aml::If::new(
                            #[allow(clippy::cast_possible_truncation)]
                            &aml::Equal::new(&aml::Arg(0), &(self.vmgenid().gsi as u8)),
                            vec![&aml::Notify::new(
                                &aml::Path::new("\\_SB_.VGEN")?,
                                &0x80usize,
                            )],
                        ),
                        &aml::If::new(
                            #[allow(clippy::cast_possible_truncation)]
                            &aml::Equal::new(&aml::Arg(0), &(self.vmclock().gsi as u8)),
                            vec![&aml::Notify::new(
                                &aml::Path::new("\\_SB_.VCLK")?,
                                &0x80usize,
                            )],
                        ),
                    ],
                ),
            ],
        )
        .append_aml_bytes(v)
    }
}
