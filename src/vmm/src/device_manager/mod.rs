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
use mmio::{MMIODeviceManager, MmioError};
use pci_mngr::{PciDevices, PciDevicesConstructorArgs, PciManagerError};
use persist::MMIODevManagerConstructorArgs;
use serde::{Deserialize, Serialize};
use utils::time::TimestampUs;
use vm_superio::serial;
use vmm_sys_util::eventfd::EventFd;

use crate::device_manager::acpi::ACPIDeviceError;
#[cfg(target_arch = "x86_64")]
use crate::devices::legacy::I8042Device;
#[cfg(target_arch = "aarch64")]
use crate::devices::legacy::RTCDevice;
use crate::devices::legacy::SerialDevice;
use crate::devices::legacy::serial::{SerialOut, SerialOutInner};
use crate::devices::pseudo::BootTimer;
use crate::devices::virtio::ActivateError;
use crate::devices::virtio::balloon::BalloonError;
use crate::devices::virtio::block::BlockError;
use crate::devices::virtio::block::device::Block;
use crate::devices::virtio::device::{VirtioDevice, VirtioDeviceId, VirtioDeviceType};
use crate::devices::virtio::mem::persist::VirtioMemPersistError;
use crate::devices::virtio::net::Net;
use crate::devices::virtio::net::persist::NetPersistError;
use crate::devices::virtio::pmem::device::Pmem;
use crate::devices::virtio::pmem::persist::PmemPersistError;
use crate::devices::virtio::rng::persist::EntropyPersistError;
use crate::devices::virtio::transport::mmio::{IrqTrigger, MmioTransport};
use crate::devices::virtio::vsock::{VsockError, VsockUnixBackendError};
use crate::logger::{error, info};
use crate::rate_limiter::TokenBucket;
use crate::resources::VmResources;
use crate::rpc_interface::VmmActionError;
use crate::snapshot::Persist;
use crate::utils::open_file_nonblock;
use crate::vmm_config::HotplugDeviceConfig;
use crate::vmm_config::drive::{BlockDeviceConfig, DriveError};
use crate::vmm_config::mmds::MmdsConfigError;
use crate::vmm_config::net::{NetBuilder, NetworkInterfaceConfig, NetworkInterfaceError};
use crate::vmm_config::pmem::{PmemConfig, PmemConfigError};
use crate::vstate::bus::BusError;
use crate::vstate::memory::GuestMemoryMmap;
use crate::{EventManager, Vm};

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
        state: Option<&serial::SerialState>,
        rate_limiter: Option<TokenBucket>,
    ) -> Result<Arc<Mutex<SerialDevice>>, std::io::Error> {
        let (serial_in, serial_out) = match output {
            Some(path) => (
                None,
                SerialOut::new(
                    SerialOutInner::File(open_file_nonblock(path)?),
                    rate_limiter,
                ),
            ),
            None => {
                Self::set_stdout_nonblocking();

                (
                    Some(std::io::stdin()),
                    SerialOut::new(SerialOutInner::Stdout(std::io::stdout()), rate_limiter),
                )
            }
        };

        let serial = Arc::new(Mutex::new(SerialDevice::new(serial_in, serial_out, state)?));
        event_manager.add_subscriber(serial.clone());
        Ok(serial)
    }

    fn serial_state(&self) -> Option<persist::SerialState> {
        #[cfg(target_arch = "aarch64")]
        {
            self.mmio_devices.serial.as_ref().map(|device| {
                let locked = device.inner.lock().expect("Poisoned lock");
                locked.serial.state().into()
            })
        }

        #[cfg(target_arch = "x86_64")]
        {
            Some(
                self.legacy_devices
                    .stdio_serial
                    .lock()
                    .expect("Poisoned lock")
                    .serial
                    .state()
                    .into(),
            )
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn create_legacy_devices(
        event_manager: &mut EventManager,
        vcpus_exit_evt: &EventFd,
        vm: &Vm,
        serial_output: Option<&PathBuf>,
        serial_state: Option<&serial::SerialState>,
        serial_rate_limiter: Option<TokenBucket>,
    ) -> Result<PortIODeviceManager, DeviceManagerCreateError> {
        // Create serial device
        let serial = Self::setup_serial_device(
            event_manager,
            serial_output,
            serial_state,
            serial_rate_limiter,
        )?;
        let reset_evt = vcpus_exit_evt
            .try_clone()
            .map_err(DeviceManagerCreateError::EventFd)?;
        // Create keyboard emulator for reset event
        let i8042 = Arc::new(Mutex::new(I8042Device::new(reset_evt)?));

        // create pio dev manager with legacy devices
        let mut legacy_devices = PortIODeviceManager {
            stdio_serial: serial,
            i8042,
        };
        legacy_devices.register_devices(vm)?;
        Ok(legacy_devices)
    }

    #[cfg_attr(target_arch = "aarch64", allow(unused))]
    pub fn new(
        event_manager: &mut EventManager,
        vcpus_exit_evt: &EventFd,
        vm: &Vm,
        serial_output: Option<&PathBuf>,
        serial_rate_limiter: Option<TokenBucket>,
    ) -> Result<Self, DeviceManagerCreateError> {
        #[cfg(target_arch = "x86_64")]
        let legacy_devices = Self::create_legacy_devices(
            event_manager,
            vcpus_exit_evt,
            vm,
            serial_output,
            None,
            serial_rate_limiter,
        )?;

        Ok(DeviceManager {
            mmio_devices: MMIODeviceManager::new(),
            #[cfg(target_arch = "x86_64")]
            legacy_devices,
            acpi_devices: ACPIDeviceManager::default(),
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
        event_manager: &mut EventManager,
        is_vhost_user: bool,
    ) -> Result<(), AttachDeviceError> {
        let interrupt = Arc::new(IrqTrigger::new());
        // The device mutex mustn't be locked here otherwise it will deadlock.
        let device =
            MmioTransport::new(vm.guest_memory().clone(), interrupt, device, is_vhost_user);
        self.mmio_devices
            .register_mmio_virtio_for_boot(vm, id, device, event_manager, cmdline)?;

        Ok(())
    }

    /// Attaches a VirtioDevice device to the device manager and event manager.
    pub(crate) fn attach_virtio_device<T: 'static + VirtioDevice + MutEventSubscriber + Debug>(
        &mut self,
        vm: &Arc<Vm>,
        id: String,
        device: Arc<Mutex<T>>,
        cmdline: &mut Cmdline,
        event_manager: &mut EventManager,
        is_vhost_user: bool,
    ) -> Result<(), AttachDeviceError> {
        if self.is_pci_enabled() {
            self.pci_devices
                .attach_pci_virtio_device(vm, id, device, event_manager)?;
        } else {
            self.attach_mmio_virtio_device(vm, id, device, cmdline, event_manager, is_vhost_user)?;
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
        self.acpi_devices.activate_vmgenid(vm)?;
        Ok(())
    }

    pub(crate) fn attach_vmclock_device(&mut self, vm: &Vm) -> Result<(), AttachDeviceError> {
        self.acpi_devices.attach_vmclock(vm)?;
        self.acpi_devices.activate_vmclock(vm)?;
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn attach_legacy_devices_aarch64(
        &mut self,
        vm: &Vm,
        event_manager: &mut EventManager,
        cmdline: &mut Cmdline,
        serial_out_path: Option<&PathBuf>,
        serial_rate_limiter: Option<TokenBucket>,
    ) -> Result<(), AttachDeviceError> {
        // Serial device setup.
        let cmdline_contains_console = cmdline
            .as_cstring()
            .map_err(|_| AttachDeviceError::Cmdline)?
            .into_string()
            .map_err(|_| AttachDeviceError::Cmdline)?
            .contains("console=");

        if cmdline_contains_console {
            let serial = Self::setup_serial_device(
                event_manager,
                serial_out_path,
                None,
                serial_rate_limiter,
            )?;
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
        let _: Result<(), MmioError> =
            self.mmio_devices
                .for_each_virtio_mmio_device(|_, _, device| {
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
        let _: Result<(), Infallible> =
            self.mmio_devices
                .for_each_virtio_mmio_device(|_, _, device| {
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
        device_type: VirtioDeviceType,
        device_id: &str,
    ) -> Option<Arc<Mutex<dyn VirtioDevice>>> {
        if self.is_pci_enabled() {
            let pci_device = self.pci_devices.get_virtio_device(device_type, device_id)?;
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
                .get_virtio_device(device_type, device_id)?;
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

    /// Run fn `f()` on all virtio devices
    pub fn for_each_virtio_device(&self, mut f: impl FnMut(VirtioDeviceType, &dyn VirtioDevice)) {
        if self.is_pci_enabled() {
            self.pci_devices.for_each_virtio_device(&mut f);
        } else {
            self.mmio_devices.for_each_virtio_device(&mut f);
        }
    }

    pub fn is_pci_enabled(&self) -> bool {
        self.pci_devices.pci_segment.is_some()
    }

    /// Attaches a device after VM start
    pub fn hotplug_device(
        &mut self,
        vm: Arc<Vm>,
        config: HotplugDeviceConfig,
        event_manager: &mut EventManager,
    ) -> Result<(), VmmActionError> {
        if !self.is_pci_enabled() {
            return Err(VmmActionError::PciNotEnabled);
        }

        let dev_type = config.device_type();
        let dev_id = config.device_id().to_string();

        if self
            .pci_devices
            .virtio_devices
            .contains_key(&(dev_type, dev_id.clone()))
        {
            return Err(VmmActionError::DeviceIdInUse);
        }

        let device = match config {
            HotplugDeviceConfig::Block(cfg) => Self::hotplug_make_block(cfg)?,
            HotplugDeviceConfig::Pmem(cfg) => Self::hotplug_make_pmem(vm.clone(), cfg)?,
            HotplugDeviceConfig::Net(cfg) => self.hotplug_make_net(cfg)?,
        };

        self.pci_devices
            .attach_pci_virtio_device(&vm, dev_id, device, event_manager)?;
        Ok(())
    }

    fn hotplug_make_block(
        config: BlockDeviceConfig,
    ) -> Result<Arc<Mutex<dyn VirtioDevice>>, VmmActionError> {
        if config.is_root_device {
            return Err(DriveError::RootBlockDeviceAlreadyAdded.into());
        }

        let block = Block::new(config).map_err(DriveError::CreateBlockDevice)?;
        Ok(Arc::new(Mutex::new(block)))
    }

    fn hotplug_make_pmem(
        vm: Arc<Vm>,
        config: PmemConfig,
    ) -> Result<Arc<Mutex<dyn VirtioDevice>>, VmmActionError> {
        if config.root_device {
            return Err(PmemConfigError::AddingSecondRootDevice.into());
        }

        let pmem = Pmem::new(vm.clone(), config).map_err(PmemConfigError::from)?;
        Ok(Arc::new(Mutex::new(pmem)))
    }

    fn hotplug_make_net(
        &self,
        config: NetworkInterfaceConfig,
    ) -> Result<Arc<Mutex<dyn VirtioDevice>>, VmmActionError> {
        if let Some(mac) = config.guest_mac {
            let mut mac_in_use = false;
            self.for_each_virtio_device(|_, device| {
                if let Some(net) = device.as_any().downcast_ref::<Net>()
                    && net.guest_mac() == Some(&mac)
                {
                    mac_in_use = true;
                }
            });
            if mac_in_use {
                return Err(NetworkInterfaceError::GuestMacAddressInUse(mac.to_string()).into());
            }
        }

        let net = NetBuilder::create_net(config)?;
        Ok(Arc::new(Mutex::new(net)))
    }

    /// Detaches a device after VM start
    pub fn hot_unplug_device(
        &mut self,
        _vm: Arc<Vm>,
        _device_id: VirtioDeviceId,
        _event_manager: &mut EventManager,
    ) -> Result<(), VmmActionError> {
        todo!()
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
    /// Serial device state
    pub serial_state: Option<persist::SerialState>,
}

/// Errors for (de)serialization of the devices.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum DevicePersistError {
    /// Balloon: {0}
    Balloon(#[from] BalloonError),
    /// Block: {0}
    Block(#[from] BlockError),
    /// MMIO Device manager: {0}
    MmioDeviceManager(#[from] mmio::MmioError),
    /// Mmio transport
    MmioTransport,
    /// PCI Device manager: {0}
    PciDeviceManager(#[from] PciManagerError),
    /// Bus error: {0}
    Bus(#[from] BusError),
    #[cfg(target_arch = "aarch64")]
    /// Legacy: {0}
    Legacy(#[from] std::io::Error),
    /// Net: {0}
    Net(#[from] NetPersistError),
    /// Vsock: {0}
    Vsock(#[from] VsockError),
    /// VsockUnixBackend: {0}
    VsockUnixBackend(#[from] VsockUnixBackendError),
    /// MmdsConfig: {0}
    MmdsConfig(#[from] MmdsConfigError),
    /// Entropy: {0}
    Entropy(#[from] EntropyPersistError),
    /// Pmem: {0}
    Pmem(#[from] PmemPersistError),
    /// virtio-mem: {0}
    VirtioMem(#[from] VirtioMemPersistError),
    /// Could not activate device: {0}
    DeviceActivation(#[from] ActivateError),
}

/// Errors for (de)serialization of the device manager.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum DeviceManagerPersistError {
    /// Error restoring MMIO devices: {0}
    MmioRestore(DevicePersistError),
    /// Error restoring ACPI devices: {0}
    AcpiRestore(#[from] ACPIDeviceError),
    /// Error restoring PCI devices: {0}
    PciRestore(DevicePersistError),
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
    type Error = DeviceManagerPersistError;

    fn save(&self) -> Self::State {
        DevicesState {
            mmio_state: self.mmio_devices.save(),
            acpi_state: self.acpi_devices.save(),
            pci_state: self.pci_devices.save(),
            serial_state: self.serial_state(),
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        // Setup legacy devices in case of x86
        #[cfg(target_arch = "x86_64")]
        let serial_state: Option<vm_superio::serial::SerialState> =
            state.serial_state.as_ref().map(Into::into);
        #[cfg(target_arch = "x86_64")]
        let legacy_devices = Self::create_legacy_devices(
            constructor_args.event_manager,
            constructor_args.vcpus_exit_evt,
            constructor_args.vm,
            constructor_args.vm_resources.serial_out_path.as_ref(),
            serial_state.as_ref(),
            constructor_args.vm_resources.serial_rate_limiter(),
        )?;

        // Restore MMIO devices
        let mmio_ctor_args = MMIODevManagerConstructorArgs {
            mem: constructor_args.mem,
            vm: constructor_args.vm,
            event_manager: constructor_args.event_manager,
            vm_resources: constructor_args.vm_resources,
            instance_id: constructor_args.instance_id,
            serial_state: state.serial_state.as_ref(),
        };
        let mmio_devices = MMIODeviceManager::restore(mmio_ctor_args, &state.mmio_state)
            .map_err(DeviceManagerPersistError::MmioRestore)?;

        // Restore ACPI devices
        let acpi_devices = ACPIDeviceManager::restore(constructor_args.vm, &state.acpi_state)?;

        // Restore PCI devices
        let pci_ctor_args = PciDevicesConstructorArgs {
            vm: constructor_args.vm,
            mem: constructor_args.mem,
            vm_resources: constructor_args.vm_resources,
            instance_id: constructor_args.instance_id,
            event_manager: constructor_args.event_manager,
        };
        let pci_devices = PciDevices::restore(pci_ctor_args, &state.pci_state)
            .map_err(DeviceManagerPersistError::PciRestore)?;

        Ok(DeviceManager {
            mmio_devices,
            #[cfg(target_arch = "x86_64")]
            legacy_devices,
            acpi_devices,
            pci_devices,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    #[cfg(target_arch = "aarch64")]
    use crate::builder::tests::default_vmm;
    use crate::devices::acpi::vmclock::VmClock;
    use crate::devices::acpi::vmgenid::VmGenId;
    use crate::vstate::resources::ResourceAllocator;

    pub(crate) fn default_device_manager() -> DeviceManager {
        let mut resource_allocator = ResourceAllocator::new();
        let mmio_devices = MMIODeviceManager::new();
        let acpi_devices = ACPIDeviceManager::new(
            VmGenId::new(&mut resource_allocator).unwrap(),
            VmClock::new(&mut resource_allocator).unwrap(),
        );
        let pci_devices = PciDevices::new();

        #[cfg(target_arch = "x86_64")]
        let legacy_devices = PortIODeviceManager {
            stdio_serial: Arc::new(Mutex::new(
                SerialDevice::new(None, SerialOut::new(SerialOutInner::Sink, None), None).unwrap(),
            )),
            i8042: Arc::new(Mutex::new(
                I8042Device::new(EventFd::new(libc::EFD_NONBLOCK).unwrap()).unwrap(),
            )),
        };

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
            .attach_legacy_devices_aarch64(&vmm.vm, &mut event_manager, &mut cmdline, None, None)
            .unwrap();
        assert!(vmm.device_manager.mmio_devices.rtc.is_some());
        assert!(vmm.device_manager.mmio_devices.serial.is_none());

        let mut vmm = default_vmm();
        cmdline.insert("console", "/dev/blah").unwrap();
        vmm.device_manager
            .attach_legacy_devices_aarch64(&vmm.vm, &mut event_manager, &mut cmdline, None, None)
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
