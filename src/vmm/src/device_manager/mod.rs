// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::fmt::Debug;
use std::sync::{Arc, Mutex};

use acpi::ACPIDeviceManager;
use event_manager::{MutEventSubscriber, SubscriberOps};
#[cfg(target_arch = "x86_64")]
use legacy::{LegacyDeviceError, PortIODeviceManager};
use linux_loader::loader::Cmdline;
use log::error;
use mmio::{MMIODeviceManager, MmioError};
use pci_mngr::{PciDevices, PciManagerError};
use persist::{ACPIDeviceManagerConstructorArgs, MMIODevManagerConstructorArgs};
use resources::ResourceAllocator;
use serde::{Deserialize, Serialize};
use utils::time::TimestampUs;
use vmm_sys_util::eventfd::EventFd;

use crate::devices::acpi::vmgenid::{VmGenId, VmGenIdError};
#[cfg(target_arch = "x86_64")]
use crate::devices::legacy::I8042Device;
#[cfg(target_arch = "aarch64")]
use crate::devices::legacy::RTCDevice;
use crate::devices::legacy::serial::SerialOut;
use crate::devices::legacy::{IER_RDA_BIT, IER_RDA_OFFSET, SerialDevice};
use crate::devices::pseudo::BootTimer;
use crate::devices::virtio::device::VirtioDevice;
use crate::devices::virtio::transport::mmio::{IrqTrigger, MmioTransport};
use crate::resources::VmResources;
use crate::snapshot::Persist;
use crate::vstate::memory::GuestMemoryMmap;
use crate::{EmulateSerialInitError, EventManager, Vm};

/// ACPI device manager.
pub mod acpi;
/// Legacy Device Manager.
pub mod legacy;
/// Memory Mapped I/O Manager.
pub mod mmio;
/// PCIe device manager
pub mod pci_mngr;
/// Device managers (de)serialization support.
pub mod persist;
/// Resource manager for devices.
pub mod resources;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
/// Error while creating a new [`DeviceManager`]
pub enum DeviceManagerCreateError {
    /// Error with EventFd: {0}
    EventFd(#[from] std::io::Error),
    #[cfg(target_arch = "x86_64")]
    /// Legacy device manager error: {0}
    PortIOError(#[from] LegacyDeviceError),
    /// Resource allocator error: {0}
    ResourceAllocator(#[from] vm_allocator::Error),
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
/// Error while attaching a VirtIO device
pub enum AttachMmioDeviceError {
    /// MMIO transport error: {0}
    MmioTransport(#[from] MmioError),
    /// Error inserting device in bus: {0}
    Bus(#[from] vm_device::BusError),
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
/// Error while attaching the VMGenID device
pub enum AttachVmgenidError {
    /// Error creating VMGenID device: {0}
    CreateVmGenID(#[from] VmGenIdError),
    /// Error while registering VMGenID with KVM: {0}
    AttachVmGenID(#[from] kvm_ioctls::Error),
}

#[cfg(target_arch = "aarch64")]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
/// Error while attaching the VMGenID device
pub enum AttachLegacyMmioDeviceError {
    /// Cmdline error
    Cmdline,
    /// Error creating serial device: {0}
    CreateSerial(#[from] std::io::Error),
    /// Error registering device: {0}
    RegisterMMIODevice(#[from] MmioError),
    /// Error inserting device in the Bus: {0}
    Bus(#[from] vm_device::BusError),
}

#[derive(Debug)]
/// A manager of all peripheral devices of Firecracker
pub struct DeviceManager {
    /// Allocator for system memory and interrupt numbers
    pub resource_allocator: Arc<ResourceAllocator>,
    /// MMIO devices
    pub mmio_devices: MMIODeviceManager,
    #[cfg(target_arch = "x86_64")]
    /// Legacy devices
    pub legacy_devices: PortIODeviceManager,
    /// ACPI devices
    pub acpi_devices: ACPIDeviceManager,
    /// PCIe devices
    pub pci_devices: PciDevices,
}

impl DeviceManager {
    // Adds `O_NONBLOCK` to the stdout flags.
    fn set_stdout_nonblocking() {
        // SAFETY: Call is safe since parameters are valid.
        let flags = unsafe { libc::fcntl(libc::STDOUT_FILENO, libc::F_GETFL, 0) };
        if flags < 0 {
            error!("Could not get Firecracker stdout flags.");
        }
        // SAFETY: Call is safe since parameters are valid.
        let rc =
            unsafe { libc::fcntl(libc::STDOUT_FILENO, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if rc < 0 {
            error!("Could not set Firecracker stdout to non-blocking.");
        }
    }

    /// Sets up the serial device.
    fn setup_serial_device(
        event_manager: &mut EventManager,
    ) -> Result<Arc<Mutex<SerialDevice>>, std::io::Error> {
        let serial = Arc::new(Mutex::new(SerialDevice::new(
            Some(std::io::stdin()),
            SerialOut::Stdout(std::io::stdout()),
        )?));
        event_manager.add_subscriber(serial.clone());
        Ok(serial)
    }

    #[cfg_attr(target_arch = "aarch64", allow(unused))]
    pub fn new(
        event_manager: &mut EventManager,
        vcpu_exit_evt: &EventFd,
        vm: &Vm,
    ) -> Result<Self, DeviceManagerCreateError> {
        let resource_allocator = Arc::new(ResourceAllocator::new()?);
        #[cfg(target_arch = "x86_64")]
        let legacy_devices = {
            Self::set_stdout_nonblocking();

            // Create serial device
            let serial = Self::setup_serial_device(event_manager)?;
            let reset_evt = vcpu_exit_evt
                .try_clone()
                .map_err(DeviceManagerCreateError::EventFd)?;
            // Create keyboard emulator for reset event
            let i8042 = Arc::new(Mutex::new(I8042Device::new(reset_evt)?));

            // create pio dev manager with legacy devices
            let mut legacy_devices = PortIODeviceManager::new(serial, i8042)?;
            legacy_devices.register_devices(&resource_allocator.pio_bus, vm)?;
            legacy_devices
        };

        Ok(DeviceManager {
            resource_allocator,
            mmio_devices: MMIODeviceManager::new(),
            #[cfg(target_arch = "x86_64")]
            legacy_devices,
            acpi_devices: ACPIDeviceManager::new(),
            pci_devices: PciDevices::new(),
        })
    }

    /// Attaches a VirtioDevice device to the device manager and event manager.
    pub(crate) fn attach_virtio_device<T: 'static + VirtioDevice + MutEventSubscriber + Debug>(
        &mut self,
        vm: &Vm,
        id: String,
        device: Arc<Mutex<T>>,
        cmdline: &mut Cmdline,
        is_vhost_user: bool,
    ) -> Result<(), AttachMmioDeviceError> {
        let interrupt = Arc::new(IrqTrigger::new());
        // The device mutex mustn't be locked here otherwise it will deadlock.
        let device =
            MmioTransport::new(vm.guest_memory().clone(), interrupt, device, is_vhost_user);
        self.mmio_devices.register_mmio_virtio_for_boot(
            vm,
            &self.resource_allocator,
            id,
            device,
            cmdline,
        )?;

        Ok(())
    }

    /// Attaches a [`BootTimer`] to the VM
    pub(crate) fn attach_boot_timer_device(
        &mut self,
        request_ts: TimestampUs,
    ) -> Result<(), AttachMmioDeviceError> {
        let boot_timer = Arc::new(Mutex::new(BootTimer::new(request_ts)));

        self.mmio_devices
            .register_mmio_boot_timer(&self.resource_allocator.mmio_bus, boot_timer)?;

        Ok(())
    }

    pub(crate) fn attach_vmgenid_device(
        &mut self,
        mem: &GuestMemoryMmap,
        vm: &Vm,
    ) -> Result<(), AttachVmgenidError> {
        let vmgenid = VmGenId::new(mem, &self.resource_allocator)?;
        self.acpi_devices.attach_vmgenid(vmgenid, vm)?;
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn attach_legacy_devices_aarch64(
        &mut self,
        vm: &Vm,
        event_manager: &mut EventManager,
        cmdline: &mut Cmdline,
    ) -> Result<(), AttachLegacyMmioDeviceError> {
        // Serial device setup.
        let cmdline_contains_console = cmdline
            .as_cstring()
            .map_err(|_| AttachLegacyMmioDeviceError::Cmdline)?
            .into_string()
            .map_err(|_| AttachLegacyMmioDeviceError::Cmdline)?
            .contains("console=");

        if cmdline_contains_console {
            // Make stdout non-blocking.
            Self::set_stdout_nonblocking();
            let serial = Self::setup_serial_device(event_manager)?;
            self.mmio_devices
                .register_mmio_serial(vm, &self.resource_allocator, serial, None)?;
            self.mmio_devices.add_mmio_serial_to_cmdline(cmdline)?;
        }

        let rtc = Arc::new(Mutex::new(RTCDevice::new()));
        self.mmio_devices
            .register_mmio_rtc(&self.resource_allocator, rtc, None)?;
        Ok(())
    }

    /// Enables PCIe support for Firecracker devices
    pub fn enable_pci(&mut self) -> Result<(), PciManagerError> {
        self.pci_devices
            .attach_pci_segment(&self.resource_allocator)
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
/// State of devices in the system
pub struct DevicesState {
    /// MMIO devices state
    pub mmio_state: persist::DeviceStates,
    /// ACPI devices state
    pub acpi_state: persist::ACPIDeviceManagerState,
    /// PCI devices state
    pub pci_state: pci_mngr::PciDevicesState,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum DevicePersistError {
    /// Error restoring MMIO devices: {0}
    MmioRestore(#[from] persist::DevicePersistError),
    /// Error restoring ACPI devices: {0}
    AcpiRestore(#[from] persist::ACPIDeviceManagerRestoreError),
    /// Error restoring PCI devices: {0}
    PciRestore(#[from] PciManagerError),
    /// Error notifying VMGenID device: {0}
    VmGenidUpdate(#[from] std::io::Error),
    /// Error resetting serial console: {0}
    SerialRestore(#[from] EmulateSerialInitError),
    /// Error inserting device in bus: {0}
    Bus(#[from] vm_device::BusError),
}

pub struct DeviceRestoreArgs<'a> {
    pub mem: &'a GuestMemoryMmap,
    pub vm: &'a Vm,
    pub event_manager: &'a mut EventManager,
    pub vm_resources: &'a mut VmResources,
    pub instance_id: &'a str,
    pub restored_from_file: bool,
}

impl std::fmt::Debug for DeviceRestoreArgs<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceRestoreArgs")
            .field("mem", &self.mem)
            .field("vm", &self.vm)
            .field("vm_resources", &self.vm_resources)
            .field("instance_id", &self.instance_id)
            .field("restored_from_file", &self.restored_from_file)
            .finish()
    }
}

impl DeviceManager {
    pub fn save(&self) -> DevicesState {
        DevicesState {
            mmio_state: self.mmio_devices.save(),
            acpi_state: self.acpi_devices.save(),
            pci_state: self.pci_devices.save(),
        }
    }

    /// Sets RDA bit in serial console
    pub fn emulate_serial_init(&self) -> Result<(), EmulateSerialInitError> {
        // When restoring from a previously saved state, there is no serial
        // driver initialization, therefore the RDA (Received Data Available)
        // interrupt is not enabled. Because of that, the driver won't get
        // notified of any bytes that we send to the guest. The clean solution
        // would be to save the whole serial device state when we do the vm
        // serialization. For now we set that bit manually

        #[cfg(target_arch = "aarch64")]
        {
            if let Some(device) = &self.mmio_devices.serial {
                let mut device_locked = device.inner.lock().expect("Poisoned lock");

                device_locked
                    .serial
                    .write(IER_RDA_OFFSET, IER_RDA_BIT)
                    .map_err(|_| EmulateSerialInitError(std::io::Error::last_os_error()))?;
            }
            Ok(())
        }

        #[cfg(target_arch = "x86_64")]
        {
            let mut serial = self
                .legacy_devices
                .stdio_serial
                .lock()
                .expect("Poisoned lock");

            serial
                .serial
                .write(IER_RDA_OFFSET, IER_RDA_BIT)
                .map_err(|_| EmulateSerialInitError(std::io::Error::last_os_error()))?;
            Ok(())
        }
    }

    pub fn restore(
        &mut self,
        state: &DevicesState,
        restore_args: DeviceRestoreArgs,
    ) -> Result<(), DevicePersistError> {
        // Restore MMIO devices
        let mmio_ctor_args = MMIODevManagerConstructorArgs {
            mem: restore_args.mem,
            vm: restore_args.vm,
            event_manager: restore_args.event_manager,
            resource_allocator: &self.resource_allocator,
            vm_resources: restore_args.vm_resources,
            instance_id: restore_args.instance_id,
            restored_from_file: restore_args.restored_from_file,
        };
        self.mmio_devices = MMIODeviceManager::restore(mmio_ctor_args, &state.mmio_state)?;

        // Restore serial.
        // We need to do that after we restore mmio devices, otherwise it won't succeed in Aarch64
        self.emulate_serial_init()?;

        // Restore ACPI devices
        let acpi_ctor_args = ACPIDeviceManagerConstructorArgs {
            mem: restore_args.mem,
            resource_allocator: &self.resource_allocator,
            vm: restore_args.vm,
        };
        self.acpi_devices = ACPIDeviceManager::restore(acpi_ctor_args, &state.acpi_state)?;
        self.acpi_devices.notify_vmgenid()?;

        // Restore PCI devices
        self.pci_devices
            .restore(&state.pci_state, &self.resource_allocator)?;

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    #[cfg(target_arch = "aarch64")]
    use crate::builder::tests::default_vmm;

    pub(crate) fn default_device_manager() -> DeviceManager {
        let mmio_devices = MMIODeviceManager::new();
        let acpi_devices = ACPIDeviceManager::new();
        let pci_devices = PciDevices::new();
        let resource_allocator = Arc::new(ResourceAllocator::new().unwrap());

        #[cfg(target_arch = "x86_64")]
        let legacy_devices = PortIODeviceManager::new(
            Arc::new(Mutex::new(
                SerialDevice::new(None, SerialOut::Sink(std::io::sink())).unwrap(),
            )),
            Arc::new(Mutex::new(
                I8042Device::new(EventFd::new(libc::EFD_NONBLOCK).unwrap()).unwrap(),
            )),
        )
        .unwrap();

        DeviceManager {
            resource_allocator,
            mmio_devices,
            #[cfg(target_arch = "x86_64")]
            legacy_devices,
            acpi_devices,
            pci_devices,
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_attach_legacy_serial() {
        let mut vmm = default_vmm();
        assert!(vmm.device_manager.mmio_devices.rtc.is_none());
        assert!(vmm.device_manager.mmio_devices.serial.is_none());

        let mut cmdline = Cmdline::new(4096).unwrap();
        let mut event_manager = EventManager::new().unwrap();
        vmm.device_manager
            .attach_legacy_devices_aarch64(&vmm.vm, &mut event_manager, &mut cmdline)
            .unwrap();
        assert!(vmm.device_manager.mmio_devices.rtc.is_some());
        assert!(vmm.device_manager.mmio_devices.serial.is_none());

        let mut vmm = default_vmm();
        cmdline.insert("console", "/dev/blah").unwrap();
        vmm.device_manager
            .attach_legacy_devices_aarch64(&vmm.vm, &mut event_manager, &mut cmdline)
            .unwrap();
        assert!(vmm.device_manager.mmio_devices.rtc.is_some());
        assert!(vmm.device_manager.mmio_devices.serial.is_some());

        assert!(
            cmdline
                .as_cstring()
                .unwrap()
                .into_string()
                .unwrap()
                .contains(&format!(
                    "earlycon=uart,mmio,0x{:08x}",
                    vmm.device_manager
                        .mmio_devices
                        .serial
                        .as_ref()
                        .unwrap()
                        .resources
                        .addr
                ))
        );
    }
}
