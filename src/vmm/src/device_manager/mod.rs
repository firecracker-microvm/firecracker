// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::convert::Infallible;
use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use acpi::ACPIDeviceManager;
use event_manager::{MutEventSubscriber, SubscriberOps};
#[cfg(target_arch = "x86_64")]
use legacy::{LegacyDeviceError, PortIODeviceManager};
use linux_loader::loader::Cmdline;
use log::{error, info};
use mmio::{MMIODeviceManager, MmioError};
use pci_mngr::{PciDevices, PciDevicesConstructorArgs, PciManagerError};
use persist::MMIODevManagerConstructorArgs;
use serde::{Deserialize, Serialize};
use utils::time::TimestampUs;
use vmm_sys_util::eventfd::EventFd;

use crate::device_manager::acpi::ACPIDeviceError;
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
use crate::utils::open_file_write_nonblock;
use crate::vstate::bus::BusError;
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
pub enum AttachDeviceError {
    /// MMIO transport error: {0}
    MmioTransport(#[from] MmioError),
    /// Error inserting device in bus: {0}
    Bus(#[from] BusError),
    /// Error while registering ACPI with KVM: {0}
    AttachAcpiDevice(#[from] ACPIDeviceError),
    #[cfg(target_arch = "aarch64")]
    /// Cmdline error
    Cmdline,
    #[cfg(target_arch = "aarch64")]
    /// Error creating serial device: {0}
    CreateSerial(#[from] std::io::Error),
    /// Error attach PCI device: {0}
    PciTransport(#[from] PciManagerError),
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
/// Error while searching for a VirtIO device
pub enum FindDeviceError {
    /// Device not found
    DeviceNotFound,
}

#[derive(Debug)]
/// A manager of all peripheral devices of Firecracker
pub struct DeviceManager {
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
        output: Option<&PathBuf>,
    ) -> Result<Arc<Mutex<SerialDevice>>, std::io::Error> {
        let (serial_in, serial_out) = match output {
            Some(path) => (None, open_file_write_nonblock(path).map(SerialOut::File)?),
            None => {
                Self::set_stdout_nonblocking();

                (Some(std::io::stdin()), SerialOut::Stdout(std::io::stdout()))
            }
        };

        let serial = Arc::new(Mutex::new(SerialDevice::new(serial_in, serial_out)?));
        event_manager.add_subscriber(serial.clone());
        Ok(serial)
    }

    #[cfg(target_arch = "x86_64")]
    fn create_legacy_devices(
        event_manager: &mut EventManager,
        vcpus_exit_evt: &EventFd,
        vm: &Vm,
        serial_output: Option<&PathBuf>,
    ) -> Result<PortIODeviceManager, DeviceManagerCreateError> {
        // Create serial device
        let serial = Self::setup_serial_device(event_manager, serial_output)?;
        let reset_evt = vcpus_exit_evt
            .try_clone()
            .map_err(DeviceManagerCreateError::EventFd)?;
        // Create keyboard emulator for reset event
        let i8042 = Arc::new(Mutex::new(I8042Device::new(reset_evt)?));

        // create pio dev manager with legacy devices
        let mut legacy_devices = PortIODeviceManager::new(serial, i8042)?;
        legacy_devices.register_devices(vm)?;
        Ok(legacy_devices)
    }

    #[cfg_attr(target_arch = "aarch64", allow(unused))]
    pub fn new(
        event_manager: &mut EventManager,
        vcpus_exit_evt: &EventFd,
        vm: &Vm,
        serial_output: Option<&PathBuf>,
    ) -> Result<Self, DeviceManagerCreateError> {
        #[cfg(target_arch = "x86_64")]
        let legacy_devices =
            Self::create_legacy_devices(event_manager, vcpus_exit_evt, vm, serial_output)?;

        Ok(DeviceManager {
            mmio_devices: MMIODeviceManager::new(),
            #[cfg(target_arch = "x86_64")]
            legacy_devices,
            acpi_devices: ACPIDeviceManager::new(&mut vm.resource_allocator()),
            pci_devices: PciDevices::new(),
        })
    }

    /// Attaches an MMIO VirtioDevice device to the device manager and event manager.
    pub(crate) fn attach_mmio_virtio_device<
        T: 'static + VirtioDevice + MutEventSubscriber + Debug,
    >(
        &mut self,
        vm: &Vm,
        id: String,
        device: Arc<Mutex<T>>,
        cmdline: &mut Cmdline,
        is_vhost_user: bool,
    ) -> Result<(), AttachDeviceError> {
        let interrupt = Arc::new(IrqTrigger::new());
        // The device mutex mustn't be locked here otherwise it will deadlock.
        let device =
            MmioTransport::new(vm.guest_memory().clone(), interrupt, device, is_vhost_user);
        self.mmio_devices
            .register_mmio_virtio_for_boot(vm, id, device, cmdline)?;

        Ok(())
    }

    /// Attaches a VirtioDevice device to the device manager and event manager.
    pub(crate) fn attach_virtio_device<T: 'static + VirtioDevice + MutEventSubscriber + Debug>(
        &mut self,
        vm: &Arc<Vm>,
        id: String,
        device: Arc<Mutex<T>>,
        cmdline: &mut Cmdline,
        is_vhost_user: bool,
    ) -> Result<(), AttachDeviceError> {
        if self.pci_devices.pci_segment.is_some() {
            self.pci_devices.attach_pci_virtio_device(vm, id, device)?;
        } else {
            self.attach_mmio_virtio_device(vm, id, device, cmdline, is_vhost_user)?;
        }

        Ok(())
    }

    /// Attaches a [`BootTimer`] to the VM
    pub(crate) fn attach_boot_timer_device(
        &mut self,
        vm: &Vm,
        request_ts: TimestampUs,
    ) -> Result<(), AttachDeviceError> {
        let boot_timer = Arc::new(Mutex::new(BootTimer::new(request_ts)));

        self.mmio_devices
            .register_mmio_boot_timer(&vm.common.mmio_bus, boot_timer)?;

        Ok(())
    }

    pub(crate) fn attach_vmgenid_device(&mut self, vm: &Vm) -> Result<(), AttachDeviceError> {
        self.acpi_devices.attach_vmgenid(vm)?;
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) fn attach_vmclock_device(&mut self, vm: &Vm) -> Result<(), AttachDeviceError> {
        self.acpi_devices.attach_vmclock(vm)?;
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn attach_legacy_devices_aarch64(
        &mut self,
        vm: &Vm,
        event_manager: &mut EventManager,
        cmdline: &mut Cmdline,
        serial_out_path: Option<&PathBuf>,
    ) -> Result<(), AttachDeviceError> {
        // Serial device setup.
        let cmdline_contains_console = cmdline
            .as_cstring()
            .map_err(|_| AttachDeviceError::Cmdline)?
            .into_string()
            .map_err(|_| AttachDeviceError::Cmdline)?
            .contains("console=");

        if cmdline_contains_console {
            let serial = Self::setup_serial_device(event_manager, serial_out_path)?;
            self.mmio_devices.register_mmio_serial(vm, serial, None)?;
            self.mmio_devices.add_mmio_serial_to_cmdline(cmdline)?;
        }

        let rtc = Arc::new(Mutex::new(RTCDevice::new()));
        self.mmio_devices.register_mmio_rtc(vm, rtc, None)?;
        Ok(())
    }

    /// Enables PCIe support for Firecracker devices
    pub fn enable_pci(&mut self, vm: &Arc<Vm>) -> Result<(), PciManagerError> {
        self.pci_devices.attach_pci_segment(vm)
    }

    /// Artificially kick VirtIO devices as if they had external events.
    pub fn kick_virtio_devices(&self) {
        info!("Artificially kick devices");
        // Go through MMIO VirtIO devices
        let _: Result<(), MmioError> = self.mmio_devices.for_each_virtio_device(|_, _, device| {
            let mmio_transport_locked = device.inner.lock().expect("Poisoned lock");
            mmio_transport_locked
                .device()
                .lock()
                .expect("Poisoned lock")
                .kick();
            Ok(())
        });
        // Go through PCI VirtIO devices
        for virtio_pci_device in self.pci_devices.virtio_devices.values() {
            virtio_pci_device
                .lock()
                .expect("Poisoned lock")
                .virtio_device()
                .lock()
                .expect("Poisoned lock")
                .kick();
        }
    }

    fn do_mark_virtio_queue_memory_dirty(
        device: Arc<Mutex<dyn VirtioDevice>>,
        mem: &GuestMemoryMmap,
    ) {
        // SAFETY:
        // This should never fail as we mark pages only if device has already been activated,
        // and the address validation was already performed on device activation.
        let mut locked_device = device.lock().expect("Poisoned lock");
        if locked_device.is_activated() {
            locked_device.mark_queue_memory_dirty(mem).unwrap()
        }
    }

    /// Mark queue memory dirty for activated VirtIO devices
    pub fn mark_virtio_queue_memory_dirty(&self, mem: &GuestMemoryMmap) {
        // Go through MMIO VirtIO devices
        let _: Result<(), Infallible> = self.mmio_devices.for_each_virtio_device(|_, _, device| {
            let mmio_transport_locked = device.inner.lock().expect("Poisoned locked");
            Self::do_mark_virtio_queue_memory_dirty(mmio_transport_locked.device(), mem);
            Ok(())
        });

        // Go through PCI VirtIO devices
        for device in self.pci_devices.virtio_devices.values() {
            let virtio_device = device.lock().expect("Poisoned lock").virtio_device();
            Self::do_mark_virtio_queue_memory_dirty(virtio_device, mem);
        }
    }

    /// Get a VirtIO device of type `virtio_type` with ID `device_id`
    pub fn get_virtio_device(
        &self,
        virtio_type: u32,
        device_id: &str,
    ) -> Option<Arc<Mutex<dyn VirtioDevice>>> {
        if self.pci_devices.pci_segment.is_some() {
            let pci_device = self.pci_devices.get_virtio_device(virtio_type, device_id)?;
            Some(
                pci_device
                    .lock()
                    .expect("Poisoned lock")
                    .virtio_device()
                    .clone(),
            )
        } else {
            let mmio_device = self
                .mmio_devices
                .get_virtio_device(virtio_type, device_id)?;
            Some(
                mmio_device
                    .inner
                    .lock()
                    .expect("Poisoned lock")
                    .device()
                    .clone(),
            )
        }
    }

    /// Run fn `f()` for the virtio device matching `virtio_type` and `id`.
    pub fn with_virtio_device<T, F, R>(&self, id: &str, f: F) -> Result<R, FindDeviceError>
    where
        T: VirtioDevice + 'static + Debug,
        F: FnOnce(&mut T) -> R,
    {
        if let Some(device) = self.get_virtio_device(T::const_device_type(), id) {
            let mut dev = device.lock().expect("Poisoned lock");
            Ok(f(dev
                .as_mut_any()
                .downcast_mut::<T>()
                .expect("Invalid device for a given device type")))
        } else {
            Err(FindDeviceError::DeviceNotFound)
        }
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
    AcpiRestore(#[from] ACPIDeviceError),
    /// Error restoring PCI devices: {0}
    PciRestore(#[from] PciManagerError),
    /// Error notifying VMGenID device: {0}
    VmGenidUpdate(#[from] std::io::Error),
    /// Error resetting serial console: {0}
    SerialRestore(#[from] EmulateSerialInitError),
    /// Error inserting device in bus: {0}
    Bus(#[from] BusError),
    /// Error creating DeviceManager: {0}
    DeviceManager(#[from] DeviceManagerCreateError),
}

pub struct DeviceRestoreArgs<'a> {
    pub mem: &'a GuestMemoryMmap,
    pub vm: &'a Arc<Vm>,
    pub event_manager: &'a mut EventManager,
    pub vcpus_exit_evt: &'a EventFd,
    pub vm_resources: &'a mut VmResources,
    pub instance_id: &'a str,
}

impl std::fmt::Debug for DeviceRestoreArgs<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceRestoreArgs")
            .field("mem", &self.mem)
            .field("vm", &self.vm)
            .field("vm_resources", &self.vm_resources)
            .field("instance_id", &self.instance_id)
            .finish()
    }
}

impl<'a> Persist<'a> for DeviceManager {
    type State = DevicesState;
    type ConstructorArgs = DeviceRestoreArgs<'a>;
    type Error = DevicePersistError;

    fn save(&self) -> Self::State {
        DevicesState {
            mmio_state: self.mmio_devices.save(),
            acpi_state: self.acpi_devices.save(),
            pci_state: self.pci_devices.save(),
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        // Setup legacy devices in case of x86
        #[cfg(target_arch = "x86_64")]
        let legacy_devices = Self::create_legacy_devices(
            constructor_args.event_manager,
            constructor_args.vcpus_exit_evt,
            constructor_args.vm,
            constructor_args.vm_resources.serial_out_path.as_ref(),
        )?;

        // Restore MMIO devices
        let mmio_ctor_args = MMIODevManagerConstructorArgs {
            mem: constructor_args.mem,
            vm: constructor_args.vm,
            event_manager: constructor_args.event_manager,
            vm_resources: constructor_args.vm_resources,
            instance_id: constructor_args.instance_id,
        };
        let mmio_devices = MMIODeviceManager::restore(mmio_ctor_args, &state.mmio_state)?;

        // Restore ACPI devices
        let mut acpi_devices = ACPIDeviceManager::restore(constructor_args.vm, &state.acpi_state)?;
        acpi_devices.vmgenid.notify_guest()?;
        #[cfg(target_arch = "x86_64")]
        acpi_devices
            .vmclock
            .post_load_update(constructor_args.vm.guest_memory());

        // Restore PCI devices
        let pci_ctor_args = PciDevicesConstructorArgs {
            vm: constructor_args.vm,
            mem: constructor_args.mem,
            vm_resources: constructor_args.vm_resources,
            instance_id: constructor_args.instance_id,
            event_manager: constructor_args.event_manager,
        };
        let pci_devices = PciDevices::restore(pci_ctor_args, &state.pci_state)?;

        let device_manager = DeviceManager {
            mmio_devices,
            #[cfg(target_arch = "x86_64")]
            legacy_devices,
            acpi_devices,
            pci_devices,
        };

        // Restore serial.
        // We need to do that after we restore mmio devices, otherwise it won't succeed in Aarch64
        device_manager.emulate_serial_init()?;

        Ok(device_manager)
    }
}

impl DeviceManager {
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
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    #[cfg(target_arch = "aarch64")]
    use crate::builder::tests::default_vmm;
    use crate::vstate::resources::ResourceAllocator;

    pub(crate) fn default_device_manager() -> DeviceManager {
        let mut resource_allocator = ResourceAllocator::new();
        let mmio_devices = MMIODeviceManager::new();
        let acpi_devices = ACPIDeviceManager::new(&mut resource_allocator);
        let pci_devices = PciDevices::new();

        #[cfg(target_arch = "x86_64")]
        let legacy_devices = PortIODeviceManager::new(
            Arc::new(Mutex::new(
                SerialDevice::new(None, SerialOut::Sink).unwrap(),
            )),
            Arc::new(Mutex::new(
                I8042Device::new(EventFd::new(libc::EFD_NONBLOCK).unwrap()).unwrap(),
            )),
        )
        .unwrap();

        DeviceManager {
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
            .attach_legacy_devices_aarch64(&vmm.vm, &mut event_manager, &mut cmdline, None)
            .unwrap();
        assert!(vmm.device_manager.mmio_devices.rtc.is_some());
        assert!(vmm.device_manager.mmio_devices.serial.is_none());

        let mut vmm = default_vmm();
        cmdline.insert("console", "/dev/blah").unwrap();
        vmm.device_manager
            .attach_legacy_devices_aarch64(&vmm.vm, &mut event_manager, &mut cmdline, None)
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
