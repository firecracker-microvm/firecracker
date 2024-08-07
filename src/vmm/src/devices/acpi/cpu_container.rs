// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2019 Intel Corporation

use acpi_tables::madt::LocalAPIC;
use acpi_tables::{aml, Aml};
use kvm_ioctls::VmFd;
use log::{debug, error};
use serde::{Deserialize, Serialize};
use utils::eventfd::EventFd;
use vm_memory::{GuestAddress, GuestMemoryError};
use vm_superio::Trigger;
use zerocopy::AsBytes;

use crate::device_manager::mmio::MMIO_LEN;
use crate::device_manager::resources::ResourceAllocator;
use crate::devices::legacy::EventFdTrigger;
use crate::vmm_config::machine_config::MAX_SUPPORTED_VCPUS;
use crate::Persist;

#[derive(Debug)]
pub struct CpuContainer {
    /// Interrupt line for performing MMIO operations
    pub mmio_interrupt_evt: EventFdTrigger,
    /// Interrupt line for notifying guest about changes
    pub acpi_interrupt_evt: EventFdTrigger,
    // GSI for the device
    pub gsi: u32,
    /// The address in guest memory where the device is stored
    pub mmio_address: GuestAddress,
    /// A list containing status of all possible CPUs. Used in AML methods.
    pub cpu_devices: Vec<CpuDevice>,
    /// The currently selected cpu in AML methods.
    pub selected_cpu: u8,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum CpuContainerError {
    /// Error with CpuContainer interrupt: {0}
    Interrupt(#[from] std::io::Error),
    /// Error accessing Cpu Container memory: {0}
    GuestMemory(#[from] GuestMemoryError),
    /// Failed to allocate requested resource: {0}
    Allocator(#[from] vm_allocator::Error),
    /// Failed to register file descriptor: {0}
    RegisterIrqFd(#[from] kvm_ioctls::Error),
}

pub const CPU_CONTAINER_ACPI_SIZE: usize = 0xC;

const CPU_ENABLE_BIT: u8 = 1 << 0;
const CPU_INSERTING_BIT: u8 = 1 << 1;

const CPU_SELECTION_OFFSET: u64 = 0;
const CPU_STATUS_OFFSET: u64 = 4;

impl CpuContainer {
    pub fn from_parts(
        mmio_address: GuestAddress,
        gsi: u32,
        selected_cpu: u8,
        cpu_devices: Vec<CpuDevice>,
    ) -> Result<Self, CpuContainerError> {
        let mmio_interrupt_evt = EventFdTrigger::new(EventFd::new(libc::EFD_NONBLOCK)?);
        let acpi_interrupt_evt = EventFdTrigger::new(EventFd::new(libc::EFD_NONBLOCK)?);

        Ok(Self {
            mmio_interrupt_evt,
            acpi_interrupt_evt,
            gsi,
            mmio_address,
            cpu_devices,
            selected_cpu,
        })
    }

    /// Create a new CPU Container device
    /// Allocate memory and a GSI for sending notifications and build the device
    pub fn new(
        resource_allocator: &mut ResourceAllocator,
        boot_count: u8,
    ) -> Result<Self, CpuContainerError> {
        let gsi = resource_allocator.allocate_gsi(1)?;
        let mmio_address = resource_allocator.allocate_mmio_memory(
            MMIO_LEN,
            MMIO_LEN,
            vm_allocator::AllocPolicy::FirstMatch,
        )?;

        let mut cpu_devices = Vec::new();
        for i in 0..MAX_SUPPORTED_VCPUS {
            cpu_devices.push(CpuDevice {
                cpu_id: i,
                active: i < boot_count,
                inserting: false,
            })
        }

        Self::from_parts(GuestAddress(mmio_address), gsi[0], 0, cpu_devices)
    }

    pub fn notify_guest(&mut self) -> Result<(), std::io::Error> {
        self.acpi_interrupt_evt
            .trigger()
            .inspect_err(|err| error!("hotplug: could not send guest notification: {err}"))?;
        debug!("hotplug: notifying guest about new vcpus available");
        Ok(())
    }

    pub fn bus_read(&mut self, offset: u64, data: &mut [u8]) {
        data.fill(0);
        match offset {
            CPU_SELECTION_OFFSET => {
                data[0] = self.selected_cpu;
            }
            CPU_STATUS_OFFSET => {
                if self.selected_cpu < MAX_SUPPORTED_VCPUS {
                    let cpu_device = &self.cpu_devices[self.selected_cpu as usize];
                    if cpu_device.active {
                        data[0] |= CPU_ENABLE_BIT;
                    }
                    if cpu_device.inserting {
                        data[0] |= CPU_INSERTING_BIT;
                    }
                } else {
                    error!("Out of range vCPU id: {}", self.selected_cpu)
                }
            }
            _ => error!("Unexpected CPU container offset"),
        }
    }

    pub fn bus_write(&mut self, offset: u64, data: &[u8]) {
        match offset {
            CPU_SELECTION_OFFSET => self.selected_cpu = data[0],
            CPU_STATUS_OFFSET => {
                if self.selected_cpu < MAX_SUPPORTED_VCPUS {
                    let cpu_device = &mut self.cpu_devices[self.selected_cpu as usize];
                    if data[0] & CPU_INSERTING_BIT != 0 {
                        cpu_device.inserting = false;
                    }
                    if data[0] & CPU_ENABLE_BIT != 0 {
                        cpu_device.active = true;
                    }
                } else {
                    error!("Out of range vCPU id: {}", self.selected_cpu)
                }
            }
            _ => error!("Unexpected CPU container offset"),
        }
    }
}

impl<'a> Persist<'a> for CpuContainer {
    type State = CpuContainerState;
    type ConstructorArgs = CpuContainerConstructorArgs<'a>;
    type Error = CpuContainerError;

    fn save(&self) -> Self::State {
        Self::State {
            mmio_address: self.mmio_address.0,
            gsi: self.gsi,
            cpu_devices: self.cpu_devices.clone(),
            selected_cpu: self.selected_cpu,
        }
    }

    fn restore(
        _constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> std::result::Result<Self, Self::Error> {
        Self::from_parts(
            GuestAddress(state.mmio_address),
            state.gsi,
            state.selected_cpu,
            state.cpu_devices.clone(),
        )
    }
}

impl Aml for CpuContainer {
    fn append_aml_bytes(&self, v: &mut Vec<u8>) {
        // CPU hotplug controller
        aml::Device::new(
            "_SB_.PRES".into(),
            vec![
                &aml::Name::new("_HID".into(), &aml::EisaName::new("PNP0A06")),
                &aml::Name::new("_UID".into(), &"CPU Hotplug Controller"),
                // Mutex to protect concurrent access as we write to choose CPU and then read
                // back status
                &aml::Mutex::new("CPLK".into(), 0),
                &aml::Name::new(
                    "_CRS".into(),
                    &aml::ResourceTemplate::new(vec![&aml::AddressSpace::new_memory(
                        aml::AddressSpaceCachable::NotCacheable,
                        true,
                        self.mmio_address.0,
                        self.mmio_address.0 + CPU_CONTAINER_ACPI_SIZE as u64 - 1,
                    )]),
                ),
                // OpRegion and Fields map MMIO range into individual field values
                #[allow(clippy::cast_possible_truncation)]
                &aml::OpRegion::new(
                    "PRST".into(),
                    aml::OpRegionSpace::SystemMemory,
                    self.mmio_address.0 as usize,
                    CPU_CONTAINER_ACPI_SIZE,
                ),
                &aml::Field::new(
                    "PRST".into(),
                    aml::FieldAccessType::Byte,
                    aml::FieldUpdateRule::WriteAsZeroes,
                    vec![
                        aml::FieldEntry::Reserved(32),
                        aml::FieldEntry::Named(*b"CPEN", 1),
                        aml::FieldEntry::Named(*b"CINS", 1),
                        aml::FieldEntry::Reserved(6),
                        aml::FieldEntry::Named(*b"CCMD", 8),
                    ],
                ),
                &aml::Field::new(
                    "PRST".into(),
                    aml::FieldAccessType::DWord,
                    aml::FieldUpdateRule::Preserve,
                    vec![
                        aml::FieldEntry::Named(*b"CSEL", 32),
                        aml::FieldEntry::Reserved(32),
                        aml::FieldEntry::Named(*b"CDAT", 32),
                    ],
                ),
            ],
        )
        .append_aml_bytes(v);
        // CPU devices
        let hid = aml::Name::new("_HID".into(), &"ACPI0010");
        let uid = aml::Name::new("_CID".into(), &aml::EisaName::new("PNP0A05"));
        // Bundle methods together under a common object
        let methods = CpuMethods {
            max_vcpus: MAX_SUPPORTED_VCPUS,
        };
        let mut cpu_data_inner: Vec<&dyn Aml> = vec![&hid, &uid, &methods];

        for cpu_device in self.cpu_devices.iter() {
            cpu_data_inner.push(cpu_device);
        }

        aml::Device::new("_SB_.CPUS".into(), cpu_data_inner).append_aml_bytes(v)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuContainerState {
    pub mmio_address: u64,
    pub gsi: u32,
    pub cpu_devices: Vec<CpuDevice>,
    pub selected_cpu: u8,
}

#[derive(Debug, Clone)]
pub struct CpuContainerConstructorArgs<'a> {
    pub vm: &'a VmFd,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct CpuDevice {
    /// The ID of this CPU, matches APICID
    cpu_id: u8,
    /// Whether this CPU is currently on or not
    pub active: bool,
    /// Whether this CPU is in the process of being inserted
    pub inserting: bool,
}

impl CpuDevice {
    fn generate_mat(&self) -> Vec<u8> {
        LocalAPIC::new(self.cpu_id, false).as_bytes().to_owned()
    }
}

impl Aml for CpuDevice {
    fn append_aml_bytes(&self, v: &mut Vec<u8>) {
        let mat_data = self.generate_mat();
        aml::Device::new(
            format!("C{:03X}", self.cpu_id).as_str().into(),
            vec![
                &aml::Name::new("_HID".into(), &"ACPI0007"),
                &aml::Name::new("_UID".into(), &self.cpu_id),
                // Currently, AArch64 cannot support following fields.
                // _STA return value:
                // Bit [0] – Set if the device is present.
                // Bit [1] – Set if the device is enabled and decoding its resources.
                // Bit [2] – Set if the device should be shown in the UI.
                // Bit [3] – Set if the device is functioning properly (cleared if device failed
                // its diagnostics). Bit [4] – Set if the battery is present.
                // Bits [31:5] – Reserved (must be cleared).
                #[cfg(target_arch = "x86_64")]
                &aml::Method::new(
                    "_STA".into(),
                    0,
                    false,
                    // Call into CSTA method which will interrogate device
                    vec![&aml::Return::new(&aml::MethodCall::new(
                        "CSTA".into(),
                        vec![&self.cpu_id],
                    ))],
                ),
                #[cfg(target_arch = "x86_64")]
                &aml::Name::new("_MAT".into(), &aml::Buffer::new(mat_data)),
            ],
        )
        .append_aml_bytes(v)
    }
}

struct CpuNotify {
    cpu_id: u8,
}

impl Aml for CpuNotify {
    fn append_aml_bytes(&self, v: &mut Vec<u8>) {
        let object = aml::Path::new(&format!("C{:03X}", self.cpu_id));
        aml::If::new(
            &aml::Equal::new(&aml::Arg(0), &self.cpu_id),
            vec![&aml::Notify::new(&object, &1u8)],
        )
        .append_aml_bytes(v)
    }
}

struct CpuMethods {
    max_vcpus: u8,
}

impl Aml for CpuMethods {
    fn append_aml_bytes(&self, v: &mut Vec<u8>) {
        // CPU status method
        aml::Method::new(
            "CSTA".into(),
            1,
            true,
            vec![
                // Take lock defined above
                &aml::Acquire::new("\\_SB_.PRES.CPLK".into(), 0xffff),
                // Write CPU number (in first argument) to I/O port via field
                &aml::Store::new(&aml::Path::new("\\_SB_.PRES.CSEL"), &aml::Arg(0)),
                &aml::Store::new(&aml::Local(0), &aml::ZERO),
                // Check if CPEN bit is set, if so make the local variable 0xf (see _STA for
                // details of meaning)
                &aml::If::new(
                    &aml::Equal::new(&aml::Path::new("\\_SB_.PRES.CPEN"), &aml::ONE),
                    vec![&aml::Store::new(&aml::Local(0), &0xfu8)],
                ),
                // Release lock
                &aml::Release::new("\\_SB_.PRES.CPLK".into()),
                // Return 0 or 0xf
                &aml::Return::new(&aml::Local(0)),
            ],
        )
        .append_aml_bytes(v);

        let mut cpu_notifies = Vec::new();
        for cpu_id in 0..self.max_vcpus {
            cpu_notifies.push(CpuNotify { cpu_id });
        }

        let mut cpu_notifies_refs: Vec<&dyn Aml> = Vec::new();
        for cpu_id in 0..self.max_vcpus {
            cpu_notifies_refs.push(&cpu_notifies[usize::from(cpu_id)]);
        }

        aml::Method::new("CTFY".into(), 2, true, cpu_notifies_refs).append_aml_bytes(v);

        aml::Method::new(
            "CSCN".into(),
            0,
            true,
            vec![
                // Take lock defined above
                &aml::Acquire::new("\\_SB_.PRES.CPLK".into(), 0xffff),
                &aml::Store::new(&aml::Local(0), &aml::ZERO),
                &aml::While::new(
                    &aml::LessThan::new(&aml::Local(0), &self.max_vcpus),
                    vec![
                        // Write CPU number (in first argument) to I/O port via field
                        &aml::Store::new(&aml::Path::new("\\_SB_.PRES.CSEL"), &aml::Local(0)),
                        // Check if CINS bit is set
                        &aml::If::new(
                            &aml::Equal::new(&aml::Path::new("\\_SB_.PRES.CINS"), &aml::ONE),
                            // Notify device if it is
                            vec![
                                &aml::Store::new(&aml::Path::new("\\_SB_.PRES.CPEN"), &aml::ONE),
                                &aml::MethodCall::new(
                                    "CTFY".into(),
                                    vec![&aml::Local(0), &aml::ONE],
                                ),
                                // Reset CINS bit
                                &aml::Store::new(&aml::Path::new("\\_SB_.PRES.CINS"), &aml::ONE),
                            ],
                        ),
                        &aml::Add::new(&aml::Local(0), &aml::Local(0), &aml::ONE),
                    ],
                ),
                // Release lock
                &aml::Release::new("\\_SB_.PRES.CPLK".into()),
            ],
        )
        .append_aml_bytes(v);
    }
}
