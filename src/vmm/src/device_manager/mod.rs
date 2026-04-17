// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use acpi::ACPIDeviceManager;
#[cfg(target_arch = "x86_64")]
use acpi_tables::Aml;
use event_manager::{MutEventSubscriber, SubscriberOps};
#[cfg(target_arch = "x86_64")]
use legacy::{LegacyDeviceError, PortIODeviceManager};
use linux_loader::loader::Cmdline;
use mmio::{MMIOPlatformDevices, MMIOVirtioDevices, MmioError};
use pci_mngr::{PciDevices, PciDevicesConstructorArgs, PciManagerError};
use persist::{
    MMIODevManagerConstructorArgs, MMIOPlatformDevicesConstructorArgs, MMIOPlatformDevicesState,
};
use serde::{Deserialize, Serialize};
use utils::time::TimestampUs;
use vm_superio::serial;
use vmm_sys_util::eventfd::EventFd;

use crate::EventManager;
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
use crate::devices::virtio::vsock::{VsockError, VsockUnixBackendError};
use crate::logger::{error, info};
use crate::rate_limiter::TokenBucket;
use crate::resources::{ResourcesError, VmResources};
use crate::rpc_interface::VmmActionError;
use crate::snapshot::Persist;
use crate::utils::open_file_nonblock;
use crate::vmm_config::HotplugDeviceConfig;
use crate::vmm_config::drive::{BlockDeviceConfig, DriveError};
use crate::vmm_config::mmds::MmdsConfigError;
use crate::vmm_config::net::{NetBuilder, NetworkInterfaceConfig, NetworkInterfaceError};
use crate::vmm_config::pmem::{PmemConfig, PmemConfigError};
use crate::vmm_config::vfio::VfioConfig;
use crate::vstate::bus::BusError;
use crate::vstate::memory::GuestMemoryMmap;
use crate::vstate::vm::{KvmVm, Vm};

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
    /// PCI device manager error: {0}
    PciDeviceManager(#[from] PciManagerError),
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
    /// Operation not supported on this VM type
    NotSupported,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
/// Error while searching for a VirtIO device
pub enum FindDeviceError {
    /// Device not found
    DeviceNotFound,
}

#[derive(Debug, Default)]
/// A manager of all peripheral devices of Firecracker
pub struct DeviceManager {
    /// MMIO Platform devices (non-virtio)
    pub mmio_platform_devices: MMIOPlatformDevices,
    #[cfg(target_arch = "x86_64")]
    /// Legacy devices (`None` if not initialized)
    pub legacy_devices: Option<PortIODeviceManager>,
    /// ACPI devices
    pub acpi_devices: ACPIDeviceManager,
    /// Virtio devices (MMIO or PCI)
    pub virtio_devices: VirtioDevices,
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
            self.mmio_platform_devices.serial.as_ref().map(|device| {
                let locked = device.inner.lock().expect("Poisoned lock");
                locked.serial.state().into()
            })
        }

        #[cfg(target_arch = "x86_64")]
        {
            self.legacy_devices.as_ref().map(|legacy| {
                legacy
                    .stdio_serial
                    .lock()
                    .expect("Poisoned lock")
                    .serial
                    .state()
                    .into()
            })
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn create_legacy_devices(
        event_manager: &mut EventManager,
        vcpus_exit_evt: &EventFd,
        vm: &KvmVm,
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
        vm: &Arc<KvmVm>,
        serial_output: Option<&PathBuf>,
        serial_rate_limiter: Option<TokenBucket>,
        pci_enabled: bool,
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
            mmio_platform_devices: MMIOPlatformDevices::new(),
            #[cfg(target_arch = "x86_64")]
            legacy_devices: Some(legacy_devices),
            acpi_devices: ACPIDeviceManager::default(),
            virtio_devices: Self::create_virtio_devices(pci_enabled, vm)?,
        })
    }

    fn create_virtio_devices(
        pci_enabled: bool,
        vm: &Arc<KvmVm>,
    ) -> Result<VirtioDevices, PciManagerError> {
        if pci_enabled {
            Ok(VirtioDevices::Pci(PciDevices::new(vm)?))
        } else {
            Ok(VirtioDevices::Mmio(MMIOVirtioDevices::new()))
        }
    }

    /// Attaches a boot-time VirtioDevice device to the device and event managers.
    pub(crate) fn attach_boot_virtio_device<
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
        let vm = vm.as_kvm().ok_or(AttachDeviceError::NotSupported)?;
        match &mut self.virtio_devices {
            VirtioDevices::Mmio(mmio_devices) => mmio_devices
                .attach_mmio_virtio_device(vm, id, device, cmdline, event_manager, is_vhost_user)
                .map_err(AttachDeviceError::from),
            VirtioDevices::Pci(pci_devices) => pci_devices
                .attach_pci_virtio_device(vm, id, device, event_manager)
                .map_err(AttachDeviceError::from),
        }
    }

    /// Attaches a [`BootTimer`] to the VM
    pub(crate) fn attach_boot_timer_device(
        &mut self,
        vm: &KvmVm,
        request_ts: TimestampUs,
    ) -> Result<(), AttachDeviceError> {
        let boot_timer = Arc::new(Mutex::new(BootTimer::new(request_ts)));

        self.mmio_platform_devices
            .register_mmio_boot_timer(&vm.common.mmio_bus, boot_timer)?;

        Ok(())
    }

    pub(crate) fn attach_vmgenid_device(&mut self, vm: &KvmVm) -> Result<(), AttachDeviceError> {
        self.acpi_devices.attach_vmgenid(vm)?;
        self.acpi_devices.activate_vmgenid(vm)?;
        Ok(())
    }

    pub(crate) fn attach_vmclock_device(&mut self, vm: &KvmVm) -> Result<(), AttachDeviceError> {
        self.acpi_devices.attach_vmclock(vm)?;
        self.acpi_devices.activate_vmclock(vm)?;
        Ok(())
    }

    pub fn attach_vfio_device(
        &mut self,
        vm: &Arc<KvmVm>,
        config: VfioConfig,
    ) -> Result<(), AttachDeviceError> {
        match &mut self.virtio_devices {
            VirtioDevices::Mmio(_) => Err(AttachDeviceError::NotSupported),
            VirtioDevices::Pci(devices) => devices
                .attach_vfio_device(vm, config)
                .map_err(AttachDeviceError::from),
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) fn append_aml_bytes(
        &self,
        dsdt_data: &mut Vec<u8>,
    ) -> Result<(), acpi_tables::aml::AmlError> {
        match &self.virtio_devices {
            VirtioDevices::Mmio(devices) => devices.append_aml_bytes(dsdt_data)?,
            VirtioDevices::Pci(devices) => devices.append_aml_bytes(dsdt_data)?,
        }

        self.acpi_devices.append_aml_bytes(dsdt_data)
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn mmio_virtio_devices(&self) -> Option<&MMIOVirtioDevices> {
        match &self.virtio_devices {
            VirtioDevices::Mmio(mmio_devices) => Some(mmio_devices),
            VirtioDevices::Pci(_) => None,
        }
    }

    pub(crate) fn pci_devices(&self) -> Option<&PciDevices> {
        match &self.virtio_devices {
            VirtioDevices::Pci(pci_devices) => Some(pci_devices),
            VirtioDevices::Mmio(_) => None,
        }
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn attach_legacy_devices_aarch64(
        &mut self,
        vm: &KvmVm,
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
            self.mmio_platform_devices
                .register_mmio_serial(vm, serial, None)?;
            self.mmio_platform_devices
                .add_mmio_serial_to_cmdline(cmdline)?;
        }

        let rtc = Arc::new(Mutex::new(RTCDevice::new()));
        self.mmio_platform_devices
            .register_mmio_rtc(vm, rtc, None)?;
        Ok(())
    }

    /// Artificially kick VirtIO devices as if they had external events.
    pub fn kick_virtio_devices(&self) {
        info!("Artificially kick devices");
        self.for_each_virtio_device_mut(|_, device| device.kick());
    }

    /// Mark queue memory dirty for activated VirtIO devices
    pub fn mark_virtio_queue_memory_dirty(&self, mem: &GuestMemoryMmap) {
        self.for_each_virtio_device_mut(|_, device| {
            if device.is_activated() {
                // SAFETY:
                // This should never fail as we mark pages only if device has already been
                // activated, and the address validation was already performed on device
                // activation.
                device.mark_queue_memory_dirty(mem).unwrap();
            }
        });
    }

    /// Get a VirtIO device of type `virtio_type` with ID `device_id`
    pub fn get_virtio_device(
        &self,
        device_type: VirtioDeviceType,
        device_id: &str,
    ) -> Option<Arc<Mutex<dyn VirtioDevice>>> {
        match &self.virtio_devices {
            VirtioDevices::Mmio(devices) => devices.get_device(device_type, device_id),
            VirtioDevices::Pci(devices) => devices.get_device(device_type, device_id),
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
        match &self.virtio_devices {
            VirtioDevices::Mmio(mmio_devices) => mmio_devices.for_each_virtio_device(&mut f),
            VirtioDevices::Pci(pci_devices) => pci_devices.for_each_virtio_device(&mut f),
        }
    }

    fn for_each_virtio_device_mut(
        &self,
        mut f: impl FnMut(VirtioDeviceType, &mut dyn VirtioDevice),
    ) {
        match &self.virtio_devices {
            VirtioDevices::Mmio(mmio_devices) => {
                mmio_devices.for_each_virtio_device_mut(&mut f);
            }
            VirtioDevices::Pci(pci_devices) => {
                pci_devices.for_each_virtio_device_mut(&mut f);
            }
        }
    }

    /// Attaches a device after VM start
    pub fn hotplug_device(
        &mut self,
        vm: Arc<KvmVm>,
        config: HotplugDeviceConfig,
        event_manager: &mut EventManager,
    ) -> Result<(), VmmActionError> {
        let dev_type = config.device_type();
        match dev_type {
            VirtioDeviceType::Balloon => {
                if let Some(pci_devices) = self.pci_devices()
                    && !pci_devices.vfio_devices.is_empty()
                {
                    return Err(VmmActionError::IncompatibleDeviceConfiguration(
                        ResourcesError::VfioWithBalloon,
                    ));
                }
            }
            VirtioDeviceType::Mem => {
                if let Some(pci_devices) = self.pci_devices()
                    && !pci_devices.vfio_devices.is_empty()
                {
                    return Err(VmmActionError::IncompatibleDeviceConfiguration(
                        ResourcesError::VfioWithMemHotplug,
                    ));
                }
            }
            _ => {}
        }

        let dev_id = config.device_id().to_string();
        let device_id = (dev_type, dev_id.clone());

        match &self.virtio_devices {
            VirtioDevices::Pci(pci_devices) => {
                if pci_devices.contains_virtio_device(&device_id) {
                    return Err(VmmActionError::DeviceIdInUse);
                }
            }
            VirtioDevices::Mmio(_) => return Err(VmmActionError::PciNotEnabled),
        }

        let device = match config {
            HotplugDeviceConfig::Block(cfg) => Self::hotplug_make_block(cfg)?,
            HotplugDeviceConfig::Pmem(cfg) => Self::hotplug_make_pmem(vm.clone(), cfg)?,
            HotplugDeviceConfig::Net(cfg) => self.hotplug_make_net(cfg)?,
        };

        match &mut self.virtio_devices {
            VirtioDevices::Pci(pci_devices) => pci_devices
                .attach_pci_virtio_device(&vm, dev_id, device, event_manager)
                .map_err(VmmActionError::PciManager),
            VirtioDevices::Mmio(_) => Err(VmmActionError::PciNotEnabled),
        }
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
        vm: Arc<KvmVm>,
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
        vm: Arc<KvmVm>,
        device_id: VirtioDeviceId,
        event_manager: &mut EventManager,
    ) -> Result<(), VmmActionError> {
        match &mut self.virtio_devices {
            VirtioDevices::Pci(pci_devices) => {
                let virtio_device = pci_devices
                    .get_device(device_id.0, &device_id.1)
                    .ok_or(VmmActionError::DeviceNotFound)?;

                if Self::is_root_device(&*virtio_device.lock().expect("Poisoned lock")) {
                    return Err(VmmActionError::CannotUnplugRootDevice);
                }

                pci_devices
                    .detach_pci_virtio_device(&vm, device_id, event_manager)
                    .map_err(VmmActionError::PciManager)
            }
            VirtioDevices::Mmio(_) => Err(VmmActionError::PciNotEnabled),
        }
    }

    /// Returns true if the given virtio device is a root block or pmem device.
    fn is_root_device(device: &dyn VirtioDevice) -> bool {
        if let Some(block) = device.as_any().downcast_ref::<Block>() {
            return block.root_device();
        }
        if let Some(pmem) = device.as_any().downcast_ref::<Pmem>() {
            return pmem.config.root_device;
        }
        false
    }
}

#[derive(Debug)]
pub enum VirtioDevices {
    Mmio(MMIOVirtioDevices),
    Pci(PciDevices),
}

impl Default for VirtioDevices {
    fn default() -> Self {
        Self::Mmio(MMIOVirtioDevices::new())
    }
}

/// Serialised state of the virtio devices, mirroring the active [`VirtioDevices`]
/// transport variant. Only the transport actually in use is serialised.
///
/// Prefer large enum over Box + heap-alloc, since snapshot restore is latency sensitive.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VirtioDevicesState {
    /// Virtio devices attached over the MMIO transport.
    Mmio(persist::DeviceStates),
    /// Virtio devices attached over the PCI transport.
    Pci(pci_mngr::PciDevicesState),
}

impl Default for VirtioDevicesState {
    fn default() -> Self {
        // Mirror `VirtioDevices::default()`, which uses the MMIO transport.
        Self::Mmio(persist::DeviceStates::default())
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
/// State of devices in the system
pub struct DevicesState {
    /// Virtio devices state
    pub virtio_state: VirtioDevicesState,
    /// MMIO platform (non-virtio) devices state
    pub mmio_platform_state: MMIOPlatformDevicesState,
    /// ACPI devices state
    pub acpi_state: persist::ACPIDeviceManagerState,
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
    /// Resource allocator error: {0}
    ResourceAllocator(#[from] vm_allocator::Error),
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
    pub vm: &'a Arc<KvmVm>,
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
        let virtio_state = match &self.virtio_devices {
            VirtioDevices::Mmio(mmio_devices) => VirtioDevicesState::Mmio(mmio_devices.save()),
            VirtioDevices::Pci(pci_devices) => VirtioDevicesState::Pci(pci_devices.save()),
        };

        DevicesState {
            virtio_state,
            mmio_platform_state: self.mmio_platform_devices.save(),
            acpi_state: self.acpi_devices.save(),
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

        // Restore MMIO platform devices
        let platform_ctor_args = MMIOPlatformDevicesConstructorArgs {
            vm: constructor_args.vm,
            event_manager: constructor_args.event_manager,
            vm_resources: constructor_args.vm_resources,
            serial_state: state.serial_state.as_ref(),
        };
        let mmio_platform_devices =
            MMIOPlatformDevices::restore(platform_ctor_args, &state.mmio_platform_state)
                .map_err(DeviceManagerPersistError::MmioRestore)?;

        // Restore ACPI devices
        let acpi_devices = ACPIDeviceManager::restore(constructor_args.vm, &state.acpi_state)?;

        let virtio_devices = match &state.virtio_state {
            VirtioDevicesState::Pci(pci_state) => {
                let pci_ctor_args = PciDevicesConstructorArgs {
                    vm: constructor_args.vm,
                    mem: constructor_args.mem,
                    vm_resources: constructor_args.vm_resources,
                    instance_id: constructor_args.instance_id,
                    event_manager: constructor_args.event_manager,
                };
                let pci_devices = PciDevices::restore(pci_ctor_args, pci_state)
                    .map_err(DeviceManagerPersistError::PciRestore)?;
                VirtioDevices::Pci(pci_devices)
            }
            VirtioDevicesState::Mmio(mmio_state) => {
                let mmio_ctor_args = MMIODevManagerConstructorArgs {
                    mem: constructor_args.mem,
                    vm: constructor_args.vm,
                    event_manager: constructor_args.event_manager,
                    vm_resources: constructor_args.vm_resources,
                    instance_id: constructor_args.instance_id,
                };
                let mmio_virtio_devices = MMIOVirtioDevices::restore(mmio_ctor_args, mmio_state)
                    .map_err(DeviceManagerPersistError::MmioRestore)?;
                VirtioDevices::Mmio(mmio_virtio_devices)
            }
        };

        Ok(DeviceManager {
            mmio_platform_devices,
            #[cfg(target_arch = "x86_64")]
            legacy_devices: Some(legacy_devices),
            acpi_devices,
            virtio_devices,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::builder::tests::{
        CustomBlockConfig, default_kernel_cmdline, default_vmm, default_vmm_with_pci,
        insert_block_devices,
    };
    use crate::devices::acpi::vmclock::VmClock;
    use crate::devices::acpi::vmgenid::VmGenId;
    use crate::devices::virtio::block::CacheType;
    use crate::rpc_interface::VmmActionError;
    use crate::vmm_config::HotplugDeviceConfig;
    use crate::vmm_config::drive::{BlockDeviceConfig, DriveError};
    use crate::vmm_config::net::{NetworkInterfaceConfig, NetworkInterfaceError};
    use crate::vmm_config::pmem::{PmemConfig, PmemConfigError};
    use crate::vstate::resources::ResourceAllocator;

    pub(crate) fn default_device_manager() -> DeviceManager {
        let mut resource_allocator = ResourceAllocator::new();
        let mmio_platform_devices = MMIOPlatformDevices::new();
        let acpi_devices = ACPIDeviceManager::new(
            VmGenId::new(&mut resource_allocator).unwrap(),
            VmClock::new(&mut resource_allocator).unwrap(),
        );
        let virtio_devices = VirtioDevices::Mmio(MMIOVirtioDevices::new());

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
            mmio_platform_devices,
            #[cfg(target_arch = "x86_64")]
            legacy_devices: Some(legacy_devices),
            acpi_devices,
            virtio_devices,
        }
    }

    pub(crate) fn default_device_manager_with_pci(vm: &Arc<KvmVm>) -> DeviceManager {
        let mut device_manager = default_device_manager();
        device_manager.virtio_devices = VirtioDevices::Pci(PciDevices::new(vm).unwrap());
        device_manager
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn mmio_devices_mut(device_manager: &mut DeviceManager) -> &mut MMIOVirtioDevices {
        let VirtioDevices::Mmio(mmio_devices) = &mut device_manager.virtio_devices else {
            panic!("MMIO transport should be enabled");
        };
        mmio_devices
    }

    pub(crate) fn pci_devices(device_manager: &DeviceManager) -> &PciDevices {
        let VirtioDevices::Pci(pci_devices) = &device_manager.virtio_devices else {
            panic!("PCI transport should be enabled");
        };
        pci_devices
    }

    pub(crate) fn pci_devices_mut(device_manager: &mut DeviceManager) -> &mut PciDevices {
        let VirtioDevices::Pci(pci_devices) = &mut device_manager.virtio_devices else {
            panic!("PCI transport should be enabled");
        };
        pci_devices
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_attach_legacy_serial() {
        let mut vmm = default_vmm();
        assert!(vmm.device_manager.mmio_platform_devices.rtc.is_none());
        assert!(vmm.device_manager.mmio_platform_devices.serial.is_none());

        let mut cmdline = Cmdline::new(4096).unwrap();
        let mut event_manager = EventManager::new().unwrap();
        vmm.device_manager
            .attach_legacy_devices_aarch64(
                vmm.vm.as_kvm().unwrap(),
                &mut event_manager,
                &mut cmdline,
                None,
                None,
            )
            .unwrap();
        assert!(vmm.device_manager.mmio_platform_devices.rtc.is_some());
        assert!(vmm.device_manager.mmio_platform_devices.serial.is_none());

        let mut vmm = default_vmm();
        cmdline.insert("console", "/dev/blah").unwrap();
        vmm.device_manager
            .attach_legacy_devices_aarch64(
                vmm.vm.as_kvm().unwrap(),
                &mut event_manager,
                &mut cmdline,
                None,
                None,
            )
            .unwrap();
        assert!(vmm.device_manager.mmio_platform_devices.rtc.is_some());
        assert!(vmm.device_manager.mmio_platform_devices.serial.is_some());

        assert!(
            cmdline
                .as_cstring()
                .unwrap()
                .into_string()
                .unwrap()
                .contains(&format!(
                    "earlycon=uart,mmio,0x{:08x}",
                    vmm.device_manager
                        .mmio_platform_devices
                        .serial
                        .as_ref()
                        .unwrap()
                        .resources
                        .addr
                ))
        );
    }

    fn make_hotplug_block_cfg(drive_id: &str, f: &TempFile, is_root: bool) -> BlockDeviceConfig {
        BlockDeviceConfig {
            drive_id: drive_id.to_string(),
            partuuid: None,
            is_root_device: is_root,
            cache_type: CacheType::Unsafe,
            is_read_only: Some(false),
            path_on_host: Some(f.as_path().to_str().unwrap().to_string()),
            rate_limiter: None,
            file_engine_type: None,
            socket: None,
        }
    }

    #[test]
    fn test_hotplug_block() {
        let mut evt_manager = EventManager::new().unwrap();
        let mut vmm = default_vmm_with_pci();
        let f = TempFile::new().unwrap();

        // Successful case
        let cfg = HotplugDeviceConfig::Block(make_hotplug_block_cfg("block0", &f, false));
        vmm.hotplug_device(cfg, &mut evt_manager).unwrap();
        assert!(
            pci_devices(&vmm.device_manager)
                .virtio_devices
                .contains_key(&(VirtioDeviceType::Block, "block0".to_string()))
        );

        // Duplicate device ID is rejected
        let cfg2 = HotplugDeviceConfig::Block(make_hotplug_block_cfg("block0", &f, false));
        assert!(matches!(
            vmm.hotplug_device(cfg2, &mut evt_manager),
            Err(VmmActionError::DeviceIdInUse)
        ));

        // Root block device is rejected
        let cfg3 = HotplugDeviceConfig::Block(make_hotplug_block_cfg("block1", &f, true));
        assert!(matches!(
            vmm.hotplug_device(cfg3, &mut evt_manager),
            Err(VmmActionError::DriveConfig(
                DriveError::RootBlockDeviceAlreadyAdded
            ))
        ));

        // Unplugging a non-existent device fails
        let device_id = (VirtioDeviceType::Block, "block9".to_string());
        assert!(matches!(
            vmm.hot_unplug_device(device_id, &mut evt_manager),
            Err(VmmActionError::DeviceNotFound)
        ));

        // Successful unplug
        let device_id = (VirtioDeviceType::Block, "block0".to_string());
        vmm.hot_unplug_device(device_id.clone(), &mut evt_manager)
            .unwrap();
        assert!(
            !pci_devices(&vmm.device_manager)
                .virtio_devices
                .contains_key(&device_id)
        );
    }

    #[test]
    fn test_hotplug_pci_not_enabled() {
        let mut vmm = default_vmm();
        let mut evt_manager = EventManager::new().unwrap();
        let f = TempFile::new().unwrap();

        let cfg = HotplugDeviceConfig::Block(make_hotplug_block_cfg("block0", &f, false));
        assert!(matches!(
            vmm.hotplug_device(cfg, &mut evt_manager),
            Err(VmmActionError::PciNotEnabled)
        ));
    }

    #[test]
    fn test_hotunplug_pci_not_enabled() {
        let mut vmm = default_vmm();
        let mut evt_manager = EventManager::new().unwrap();
        let mut cmdline = default_kernel_cmdline();

        // Add an MMIO block device
        let block_configs = vec![CustomBlockConfig::new(
            "root".to_string(),
            true,
            None,
            true,
            CacheType::Unsafe,
        )];
        insert_block_devices(&mut vmm, &mut cmdline, &mut evt_manager, block_configs);

        // Unplugging MMIO devices must be rejected
        let device_id = (VirtioDeviceType::Block, "root".to_string());
        assert!(matches!(
            vmm.hot_unplug_device(device_id, &mut evt_manager),
            Err(VmmActionError::PciNotEnabled)
        ));
    }

    #[test]
    fn test_hotplug_pmem() {
        let mut vmm = default_vmm_with_pci();
        let mut evt_manager = EventManager::new().unwrap();
        let f = TempFile::new().unwrap();
        f.as_file().set_len(0x1000).unwrap();

        // Successful case
        let cfg = HotplugDeviceConfig::Pmem(PmemConfig {
            id: "pmem0".to_string(),
            path_on_host: f.as_path().to_str().unwrap().to_string(),
            root_device: false,
            read_only: false,
            ..Default::default()
        });
        vmm.hotplug_device(cfg, &mut evt_manager).unwrap();
        assert!(
            pci_devices(&vmm.device_manager)
                .virtio_devices
                .contains_key(&(VirtioDeviceType::Pmem, "pmem0".to_string()))
        );

        // Root pmem device is rejected
        let f2 = TempFile::new().unwrap();
        let cfg2 = HotplugDeviceConfig::Pmem(PmemConfig {
            id: "pmem1".to_string(),
            path_on_host: f2.as_path().to_str().unwrap().to_string(),
            root_device: true,
            read_only: false,
            ..Default::default()
        });
        assert!(matches!(
            vmm.hotplug_device(cfg2, &mut evt_manager),
            Err(VmmActionError::PmemConfig(
                PmemConfigError::AddingSecondRootDevice
            ))
        ));

        // Unplugging a non-existent device fails
        let device_id = (VirtioDeviceType::Pmem, "pmem9".to_string());
        assert!(matches!(
            vmm.hot_unplug_device(device_id, &mut evt_manager),
            Err(VmmActionError::DeviceNotFound)
        ));

        // Successful unplug
        let device_id = (VirtioDeviceType::Pmem, "pmem0".to_string());
        vmm.hot_unplug_device(device_id.clone(), &mut evt_manager)
            .unwrap();
        assert!(
            !pci_devices(&vmm.device_manager)
                .virtio_devices
                .contains_key(&device_id)
        );
    }

    #[test]
    fn test_hotplug_net() {
        let mut vmm = default_vmm_with_pci();
        let mut evt_manager = EventManager::new().unwrap();

        let mac = "AA:FC:00:00:00:01";

        // Successful case
        let cfg = HotplugDeviceConfig::Net(NetworkInterfaceConfig {
            iface_id: "eth0".to_string(),
            host_dev_name: "hostname".to_string(),
            guest_mac: Some(mac.parse().unwrap()),
            mtu: None,
            rx_rate_limiter: None,
            tx_rate_limiter: None,
        });
        vmm.hotplug_device(cfg, &mut evt_manager).unwrap();
        assert!(
            pci_devices(&vmm.device_manager)
                .virtio_devices
                .contains_key(&(VirtioDeviceType::Net, "eth0".to_string()))
        );

        // Duplicate MAC is rejected
        let cfg2 = HotplugDeviceConfig::Net(NetworkInterfaceConfig {
            iface_id: "eth1".to_string(),
            host_dev_name: "hostname2".to_string(),
            guest_mac: Some(mac.parse().unwrap()),
            mtu: None,
            rx_rate_limiter: None,
            tx_rate_limiter: None,
        });
        assert!(matches!(
            vmm.hotplug_device(cfg2, &mut evt_manager),
            Err(VmmActionError::NetworkConfig(
                NetworkInterfaceError::GuestMacAddressInUse(_)
            ))
        ));

        // Unplugging a non-existent device fails
        let device_id = (VirtioDeviceType::Net, "eth9".to_string());
        assert!(matches!(
            vmm.hot_unplug_device(device_id, &mut evt_manager),
            Err(VmmActionError::DeviceNotFound)
        ));

        // Successful unplug
        let device_id = (VirtioDeviceType::Net, "eth0".to_string());
        vmm.hot_unplug_device(device_id.clone(), &mut evt_manager)
            .unwrap();
        assert!(
            !pci_devices(&vmm.device_manager)
                .virtio_devices
                .contains_key(&device_id)
        );
    }

    #[test]
    fn test_unplug_root_block() {
        let mut evt_manager = EventManager::new().unwrap();
        let mut vmm = default_vmm_with_pci();
        let f = TempFile::new().unwrap();

        // Simulate a root block device added pre-boot by attaching it
        // directly to the PCI bus (bypassing the hotplug path which
        // rejects root devices).
        let cfg = make_hotplug_block_cfg("rootfs", &f, true);
        let block = Block::new(cfg).unwrap();
        pci_devices_mut(&mut vmm.device_manager)
            .attach_pci_virtio_device(
                vmm.vm.as_kvm().unwrap(),
                "rootfs".to_string(),
                Arc::new(Mutex::new(block)),
                &mut evt_manager,
            )
            .unwrap();

        // Hot-unplugging the root block device must be rejected
        let device_id = (VirtioDeviceType::Block, "rootfs".to_string());
        assert!(matches!(
            vmm.hot_unplug_device(device_id, &mut evt_manager),
            Err(VmmActionError::CannotUnplugRootDevice)
        ));
    }

    #[test]
    fn test_unplug_root_pmem() {
        let mut evt_manager = EventManager::new().unwrap();
        let mut vmm = default_vmm_with_pci();
        let f = TempFile::new().unwrap();
        f.as_file().set_len(0x1000).unwrap();

        // Simulate a root pmem device added pre-boot by attaching it
        // directly to the PCI bus.
        let cfg = PmemConfig {
            id: "pmem_root".to_string(),
            path_on_host: f.as_path().to_str().unwrap().to_string(),
            root_device: true,
            read_only: false,
            ..Default::default()
        };
        let pmem = Pmem::new(vmm.vm.as_kvm().unwrap().clone(), cfg).unwrap();
        pci_devices_mut(&mut vmm.device_manager)
            .attach_pci_virtio_device(
                vmm.vm.as_kvm().unwrap(),
                "pmem_root".to_string(),
                Arc::new(Mutex::new(pmem)),
                &mut evt_manager,
            )
            .unwrap();

        // Hot-unplugging the root pmem device must be rejected
        let device_id = (VirtioDeviceType::Pmem, "pmem_root".to_string());
        assert!(matches!(
            vmm.hot_unplug_device(device_id, &mut evt_manager),
            Err(VmmActionError::CannotUnplugRootDevice)
        ));
    }
}
