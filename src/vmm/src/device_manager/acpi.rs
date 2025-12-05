// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_arch = "x86_64")]
use acpi_tables::{Aml, aml};
use vm_memory::GuestMemoryError;

use crate::Vm;
use crate::devices::acpi::vmclock::VmClock;
use crate::devices::acpi::vmgenid::VmGenId;
use crate::vstate::resources::ResourceAllocator;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ACPIDeviceError {
    /// Could not register GSI with KVM: {0}
    RegisterIrq(#[from] kvm_ioctls::Error),
    /// Could not write to guest memory: {0}
    WriteGuestMemory(#[from] GuestMemoryError),
}

#[derive(Debug)]
pub struct ACPIDeviceManager {
    /// VMGenID device
    pub vmgenid: VmGenId,
    /// VMclock device
    pub vmclock: VmClock,
}

impl ACPIDeviceManager {
    /// Create a new ACPIDeviceManager object
    pub fn new(resource_allocator: &mut ResourceAllocator) -> Self {
        ACPIDeviceManager {
            vmgenid: VmGenId::new(resource_allocator),
            vmclock: VmClock::new(resource_allocator),
        }
    }

    pub fn attach_vmgenid(&self, vm: &Vm) -> Result<(), ACPIDeviceError> {
        vm.register_irq(&self.vmgenid.interrupt_evt, self.vmgenid.gsi)?;
        self.vmgenid.activate(vm.guest_memory())?;
        Ok(())
    }

    pub fn attach_vmclock(&self, vm: &Vm) -> Result<(), ACPIDeviceError> {
        vm.register_irq(&self.vmclock.interrupt_evt, self.vmclock.gsi)?;
        self.vmclock.activate(vm.guest_memory())?;
        Ok(())
    }
}

#[cfg(target_arch = "x86_64")]
impl Aml for ACPIDeviceManager {
    fn append_aml_bytes(&self, v: &mut Vec<u8>) -> Result<(), aml::AmlError> {
        // AML for [`VmGenId`] device.
        self.vmgenid.append_aml_bytes(v)?;
        // AML for [`VmClock`] device.
        #[cfg(target_arch = "x86_64")]
        self.vmclock.append_aml_bytes(v)?;

        // Create the AML for the GED interrupt handler
        aml::Device::new(
            "_SB_.GED_".try_into()?,
            vec![
                &aml::Name::new("_HID".try_into()?, &"ACPI0013")?,
                &aml::Name::new(
                    "_CRS".try_into()?,
                    &aml::ResourceTemplate::new(vec![
                        &aml::Interrupt::new(true, true, false, false, self.vmgenid.gsi),
                        &aml::Interrupt::new(true, true, false, false, self.vmclock.gsi),
                    ]),
                )?,
                &aml::Method::new(
                    "_EVT".try_into()?,
                    1,
                    true,
                    vec![
                        &aml::If::new(
                            // We know that the maximum IRQ number fits in a u8. We have up to
                            // 32 IRQs in x86 and up to 128 in
                            // ARM (look into
                            // `vmm::crate::arch::layout::GSI_LEGACY_END`)
                            #[allow(clippy::cast_possible_truncation)]
                            &aml::Equal::new(&aml::Arg(0), &(self.vmgenid.gsi as u8)),
                            vec![&aml::Notify::new(
                                &aml::Path::new("\\_SB_.VGEN")?,
                                &0x80usize,
                            )],
                        ),
                        &aml::If::new(
                            // We know that the maximum IRQ number fits in a u8. We have up to
                            // 32 IRQs in x86 and up to 128 in
                            // ARM (look into
                            // `vmm::crate::arch::layout::GSI_LEGACY_END`)
                            #[allow(clippy::cast_possible_truncation)]
                            &aml::Equal::new(&aml::Arg(0), &(self.vmclock.gsi as u8)),
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
