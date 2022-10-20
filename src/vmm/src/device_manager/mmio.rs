// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::{fmt, io};

use acpi::aml;
#[cfg(target_arch = "aarch64")]
use arch::aarch64::DeviceInfoForFDT;
use arch::DeviceType;
use arch::DeviceType::Virtio;
#[cfg(target_arch = "aarch64")]
use devices::legacy::RTCDevice;
#[cfg(target_arch = "aarch64")]
use devices::legacy::SerialDevice;
use devices::pseudo::BootTimer;
use devices::virtio::{
    Balloon, Block, MmioTransport, Net, VirtioDevice, TYPE_BALLOON, TYPE_BLOCK, TYPE_NET,
    TYPE_VSOCK,
};
use devices::BusDevice;
use kvm_ioctls::{IoEventAddress, VmFd};
#[cfg(target_arch = "aarch64")]
use linux_loader::loader::Cmdline;
use logger::info;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
#[cfg(target_arch = "aarch64")]
use vm_memory::GuestAddress;

use crate::acpi::AcpiConfig;
use crate::resource_manager::{AllocPolicy, ResourceManager};

/// Errors for MMIO device manager.
#[derive(Debug)]
pub enum Error {
    /// Failed to perform an operation on the bus.
    Bus(devices::BusError),
    /// Appending to kernel command line failed.
    Cmdline(linux_loader::cmdline::Error),
    /// The device couldn't be found.
    DeviceNotFound,
    /// Failure in creating or cloning an event fd.
    EventFd(io::Error),
    /// Incorrect device type.
    IncorrectDeviceType,
    /// Internal device error.
    InternalDeviceError(String),
    /// Invalid configuration attempted.
    InvalidInput,
    /// Registering an IO Event failed.
    RegisterIoEvent(kvm_ioctls::Error),
    /// Registering an IRQ FD failed.
    RegisterIrqFd(kvm_ioctls::Error),
    /// Failed to update the mmio device.
    UpdateFailed,
    /// Allocation logic error.
    AllocatorError(vm_allocator::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Bus(err) => write!(f, "failed to perform bus operation: {}", err),
            Error::Cmdline(err) => {
                write!(f, "unable to add device to kernel command line: {}", err)
            }
            Error::EventFd(err) => write!(f, "failed to create or clone event descriptor: {}", err),
            Error::IncorrectDeviceType => write!(f, "incorrect device type"),
            Error::InternalDeviceError(err) => write!(f, "device error: {}", err),
            Error::InvalidInput => write!(f, "invalid configuration"),
            Error::RegisterIoEvent(e) => write!(f, "failed to register IO event: {}", e),
            Error::RegisterIrqFd(e) => write!(f, "failed to register irqfd: {}", e),
            Error::DeviceNotFound => write!(f, "the device couldn't be found"),
            Error::UpdateFailed => write!(f, "failed to update the mmio device"),
            Error::AllocatorError(e) => write!(f, "failed to allocate requested resource: {}", e),
        }
    }
}

type Result<T> = ::std::result::Result<T, Error>;

/// This represents the size of the mmio device specified to the kernel through ACPI
/// It has to be larger than 0x100 (the offset where the configuration space starts from
/// the beginning of the memory mapped device registers) + the size of the configuration space
/// Currently hardcoded to 4K.
pub const MMIO_LEN: u64 = 0x1000;

/// Stores the address range and irq allocated to this device.
#[derive(Clone, Debug, PartialEq, Eq, Versionize)]
// NOTICE: Any changes to this structure require a snapshot version bump.
pub struct MMIODeviceInfo {
    /// Mmio address at which the device is registered.
    pub addr: u64,
    /// Mmio addr range length.
    pub len: u64,
    /// Used Irq line(s) for the device.
    pub irqs: Vec<u32>,
}

/// Manages the complexities of registering a MMIO device.
pub struct MMIODeviceManager {
    pub(crate) bus: devices::Bus,
    pub(crate) id_to_dev_info: HashMap<(DeviceType, String), MMIODeviceInfo>,
    num_devices: u8,
}

impl MMIODeviceManager {
    /// Create a new DeviceManager handling mmio devices (virtio net, block).
    pub fn new() -> Result<MMIODeviceManager> {
        Ok(MMIODeviceManager {
            bus: devices::Bus::new(),
            id_to_dev_info: HashMap::new(),
            num_devices: 0,
        })
    }

    /// Allocates resources for a new device to be added.
    pub fn allocate_mmio_resources(
        resource_manager: &mut ResourceManager,
        irq_count: u32,
    ) -> Result<MMIODeviceInfo> {
        let irqs = resource_manager
            .allocate_gsi(irq_count)
            .map_err(Error::AllocatorError)?;
        let device_info = MMIODeviceInfo {
            addr: resource_manager
                .allocate_mmio_addresses(MMIO_LEN, MMIO_LEN, AllocPolicy::FirstMatch)
                .map_err(Error::AllocatorError)?,
            len: MMIO_LEN,
            irqs,
        };
        Ok(device_info)
    }

    /// Register a device at some MMIO address.
    fn register_mmio_device(
        &mut self,
        identifier: (DeviceType, String),
        device_info: MMIODeviceInfo,
        device: Arc<Mutex<dyn BusDevice>>,
    ) -> Result<()> {
        self.bus
            .insert(device, device_info.addr, device_info.len)
            .map_err(Error::Bus)?;
        self.id_to_dev_info.insert(identifier, device_info);
        Ok(())
    }

    fn register_acpi_device(&self, acpi_config: &mut AcpiConfig, device_info: &MMIODeviceInfo) {
        acpi_config.add_device(&aml::Device::new(
            format!("_SB_.VR{:02}", self.num_devices).as_str().into(),
            vec![
                &aml::Name::new("_HID".into(), &"LNRO0005"),
                &aml::Name::new("_UID".into(), &self.num_devices),
                &aml::Name::new(
                    "_CRS".into(),
                    &aml::ResourceTemplate::new(vec![
                        &aml::Memory32Fixed::new(
                            true,
                            device_info.addr as u32,
                            device_info.len as u32,
                        ),
                        &aml::Interrupt::new(true, true, false, false, device_info.irqs[0]),
                    ]),
                ),
            ],
        ))
    }

    /// Register a virtio-over-MMIO device to be used via MMIO transport at a specific slot.
    pub fn register_mmio_virtio(
        &mut self,
        vm: &VmFd,
        device_id: String,
        mmio_device: MmioTransport,
        device_info: &MMIODeviceInfo,
    ) -> Result<()> {
        // Our virtio devices are currently hardcoded to use a single IRQ.
        // Validate that requirement.
        if device_info.irqs.len() != 1 {
            return Err(Error::InvalidInput);
        }
        let identifier;
        {
            let locked_device = mmio_device.locked_device();
            identifier = (DeviceType::Virtio(locked_device.device_type()), device_id);
            for (i, queue_evt) in locked_device.queue_events().iter().enumerate() {
                let io_addr = IoEventAddress::Mmio(
                    device_info.addr + u64::from(devices::virtio::NOTIFY_REG_OFFSET),
                );
                vm.register_ioevent(queue_evt, &io_addr, i as u32)
                    .map_err(Error::RegisterIoEvent)?;
            }
            vm.register_irqfd(locked_device.interrupt_evt(), device_info.irqs[0])
                .map_err(Error::RegisterIrqFd)?;
        }

        self.register_mmio_device(
            identifier,
            device_info.clone(),
            Arc::new(Mutex::new(mmio_device)),
        )
    }

    /// Allocate slot and register an already created virtio-over-MMIO device.
    pub(crate) fn register_mmio_virtio_for_boot(
        &mut self,
        resource_manager: &mut ResourceManager,
        acpi_config: &mut AcpiConfig,
        vm: &VmFd,
        device_id: String,
        mmio_device: MmioTransport,
    ) -> Result<MMIODeviceInfo> {
        let device_info = Self::allocate_mmio_resources(resource_manager, 1)?;
        self.register_mmio_virtio(vm, device_id, mmio_device, &device_info)?;
        self.num_devices += 1;
        self.register_acpi_device(acpi_config, &device_info);
        Ok(device_info)
    }

    #[cfg(target_arch = "aarch64")]
    /// Register an early console at the specified MMIO configuration if given as parameter,
    /// otherwise allocate a new MMIO resources for it.
    pub fn register_mmio_serial(
        &mut self,
        resource_manager: &mut ResourceManager,
        vm: &VmFd,
        serial: Arc<Mutex<SerialDevice>>,
        device_info_opt: Option<MMIODeviceInfo>,
    ) -> Result<()> {
        // Create a new MMIODeviceInfo object on boot path or unwrap the
        // existing object on restore path.
        let device_info = if let Some(device_info) = device_info_opt {
            device_info
        } else {
            Self::allocate_mmio_resources(resource_manager, 1)?
        };

        vm.register_irqfd(
            serial.lock().expect("Poisoned lock").serial.interrupt_evt(),
            device_info.irqs[0],
        )
        .map_err(Error::RegisterIrqFd)?;

        let identifier = (DeviceType::Serial, DeviceType::Serial.to_string());
        // Register the newly created Serial object.
        self.register_mmio_device(identifier, device_info, serial)
    }

    #[cfg(target_arch = "aarch64")]
    /// Append the registered early console to the kernel cmdline.
    pub fn add_mmio_serial_to_cmdline(&self, cmdline: &mut Cmdline) -> Result<()> {
        let device_info = self
            .id_to_dev_info
            .get(&(DeviceType::Serial, DeviceType::Serial.to_string()))
            .ok_or(Error::DeviceNotFound)?;
        cmdline
            .insert("earlycon", &format!("uart,mmio,0x{:08x}", device_info.addr))
            .map_err(Error::Cmdline)
    }

    #[cfg(target_arch = "aarch64")]
    /// Create and register a MMIO RTC device at the specified MMIO configuration if
    /// given as parameter, otherwise allocate a new MMIO resources for it.
    pub fn register_mmio_rtc(
        &mut self,
        resource_manager: &mut ResourceManager,
        rtc: Arc<Mutex<RTCDevice>>,
        device_info_opt: Option<MMIODeviceInfo>,
    ) -> Result<()> {
        // Create a new MMIODeviceInfo object on boot path or unwrap the
        // existing object on restore path.
        let device_info = if let Some(device_info) = device_info_opt {
            device_info
        } else {
            Self::allocate_mmio_resources(resource_manager, 1)?
        };

        // Create a new identifier for the RTC device.
        let identifier = (DeviceType::Rtc, DeviceType::Rtc.to_string());
        // Attach the newly created RTC device.
        self.register_mmio_device(identifier, device_info, rtc)
    }

    /// Register a boot timer device.
    pub fn register_mmio_boot_timer(
        &mut self,
        resource_manager: &mut ResourceManager,
        device: BootTimer,
    ) -> Result<()> {
        // Attach a new boot timer device.
        let device_info = Self::allocate_mmio_resources(resource_manager, 0)?;

        let identifier = (DeviceType::BootTimer, DeviceType::BootTimer.to_string());
        self.register_mmio_device(identifier, device_info, Arc::new(Mutex::new(device)))
    }

    /// Gets the information of the devices registered up to some point in time.
    pub fn get_device_info(&self) -> &HashMap<(DeviceType, String), MMIODeviceInfo> {
        &self.id_to_dev_info
    }

    #[cfg(target_arch = "x86_64")]
    /// Gets the number of interrupts used by the devices registered.
    pub fn used_irqs_count(&self) -> usize {
        let mut irq_number = 0;
        self.get_device_info()
            .iter()
            .for_each(|(_, device_info)| irq_number += device_info.irqs.len());
        irq_number
    }

    /// Gets the the specified device.
    pub fn get_device(
        &self,
        device_type: DeviceType,
        device_id: &str,
    ) -> Option<&Mutex<dyn BusDevice>> {
        if let Some(device_info) = self
            .id_to_dev_info
            .get(&(device_type, device_id.to_string()))
        {
            if let Some((_, device)) = self.bus.get_device(device_info.addr) {
                return Some(device);
            }
        }
        None
    }

    /// Run fn for each registered device.
    pub fn for_each_device<F, E>(&self, mut f: F) -> std::result::Result<(), E>
    where
        F: FnMut(
            &DeviceType,
            &String,
            &MMIODeviceInfo,
            &Mutex<dyn BusDevice>,
        ) -> std::result::Result<(), E>,
    {
        for ((device_type, device_id), device_info) in self.get_device_info().iter() {
            let bus_device = self
                .get_device(*device_type, device_id)
                // Safe to unwrap() because we know the device exists.
                .unwrap();
            f(device_type, device_id, device_info, bus_device)?;
        }
        Ok(())
    }

    /// Run fn for each registered virtio device.
    pub fn for_each_virtio_device<F, E>(&self, mut f: F) -> std::result::Result<(), E>
    where
        F: FnMut(
            u32,
            &String,
            &MMIODeviceInfo,
            Arc<Mutex<dyn VirtioDevice>>,
        ) -> std::result::Result<(), E>,
    {
        self.for_each_device(|device_type, device_id, device_info, bus_device| {
            if let Virtio(virtio_type) = device_type {
                let virtio_device = bus_device
                    .lock()
                    .expect("Poisoned lock")
                    .as_any()
                    .downcast_ref::<MmioTransport>()
                    .expect("Unexpected BusDevice type")
                    .device();
                f(*virtio_type, device_id, device_info, virtio_device)?;
            }
            Ok(())
        })?;

        Ok(())
    }

    /// Run fn `f()` for the virtio device matching `virtio_type` and `id`.
    pub fn with_virtio_device_with_id<T, F>(&self, virtio_type: u32, id: &str, f: F) -> Result<()>
    where
        T: VirtioDevice + 'static,
        F: FnOnce(&mut T) -> std::result::Result<(), String>,
    {
        if let Some(busdev) = self.get_device(DeviceType::Virtio(virtio_type), id) {
            let virtio_device = busdev
                .lock()
                .expect("Poisoned lock")
                .as_any()
                .downcast_ref::<MmioTransport>()
                .expect("Unexpected BusDevice type")
                .device();
            let mut dev = virtio_device.lock().expect("Poisoned lock");
            f(dev
                .as_mut_any()
                .downcast_mut::<T>()
                .ok_or(Error::IncorrectDeviceType)?)
            .map_err(Error::InternalDeviceError)?;
        } else {
            return Err(Error::DeviceNotFound);
        }
        Ok(())
    }

    /// Artificially kick devices as if they had external events.
    pub fn kick_devices(&self) {
        info!("Artificially kick devices.");
        // We only kick virtio devices for now.
        let _: Result<()> = self.for_each_virtio_device(|virtio_type, id, _info, dev| {
            let mut virtio = dev.lock().expect("Poisoned lock");
            match virtio_type {
                TYPE_BALLOON => {
                    let balloon = virtio.as_mut_any().downcast_mut::<Balloon>().unwrap();
                    // If device is activated, kick the balloon queue(s) to make up for any
                    // pending or in-flight epoll events we may have not captured in snapshot.
                    // Stats queue doesn't need kicking as it is notified via a `timer_fd`.
                    if balloon.is_activated() {
                        info!("kick balloon {}.", id);
                        balloon.process_virtio_queues();
                    }
                }
                TYPE_BLOCK => {
                    let block = virtio.as_mut_any().downcast_mut::<Block>().unwrap();
                    // If device is activated, kick the block queue(s) to make up for any
                    // pending or in-flight epoll events we may have not captured in snapshot.
                    // No need to kick Ratelimiters because they are restored 'unblocked' so
                    // any inflight `timer_fd` events can be safely discarded.
                    if block.is_activated() {
                        info!("kick block {}.", id);
                        block.process_virtio_queues();
                    }
                }
                TYPE_NET => {
                    let net = virtio.as_mut_any().downcast_mut::<Net>().unwrap();
                    // If device is activated, kick the net queue(s) to make up for any
                    // pending or in-flight epoll events we may have not captured in snapshot.
                    // No need to kick Ratelimiters because they are restored 'unblocked' so
                    // any inflight `timer_fd` events can be safely discarded.
                    if net.is_activated() {
                        info!("kick net {}.", id);
                        net.process_virtio_queues();
                    }
                }
                TYPE_VSOCK => {
                    // Vsock has complicated protocol that isn't resilient to any packet loss,
                    // so for Vsock we don't support connection persistence through snapshot.
                    // Any in-flight packets or events are simply lost.
                    // Vsock is restored 'empty'.
                }
                _ => (),
            }
            Ok(())
        });
    }
}

#[cfg(target_arch = "aarch64")]
impl DeviceInfoForFDT for MMIODeviceInfo {
    fn addr(&self) -> u64 {
        self.addr
    }
    fn irq(&self) -> u32 {
        self.irqs[0]
    }
    fn length(&self) -> u64 {
        self.len
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    use devices::virtio::{ActivateResult, Queue, VirtioDevice};
    use utils::errno;
    use utils::eventfd::EventFd;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    use super::*;
    use crate::acpi::AcpiConfig;
    use crate::builder;

    const QUEUE_SIZES: &[u16] = &[64];

    impl MMIODeviceManager {
        fn register_virtio_test_device(
            &mut self,
            vm: &VmFd,
            guest_mem: GuestMemoryMmap,
            resource_manager: &mut ResourceManager,
            acpi_config: &mut AcpiConfig,
            device: Arc<Mutex<dyn devices::virtio::VirtioDevice>>,
            dev_id: &str,
        ) -> Result<u64> {
            let mmio_device = MmioTransport::new(guest_mem, device);
            let device_info = self.register_mmio_virtio_for_boot(
                resource_manager,
                acpi_config,
                vm,
                dev_id.to_string(),
                mmio_device,
            )?;
            Ok(device_info.addr)
        }
    }

    #[allow(dead_code)]
    struct DummyDevice {
        dummy: u32,
        queues: Vec<Queue>,
        queue_evts: [EventFd; 1],
        interrupt_evt: EventFd,
    }

    impl DummyDevice {
        pub fn new() -> Self {
            DummyDevice {
                dummy: 0,
                queues: QUEUE_SIZES.iter().map(|&s| Queue::new(s)).collect(),
                queue_evts: [EventFd::new(libc::EFD_NONBLOCK).expect("cannot create eventFD")],
                interrupt_evt: EventFd::new(libc::EFD_NONBLOCK).expect("cannot create eventFD"),
            }
        }
    }

    impl devices::virtio::VirtioDevice for DummyDevice {
        fn avail_features(&self) -> u64 {
            0
        }

        fn acked_features(&self) -> u64 {
            0
        }

        fn set_acked_features(&mut self, _: u64) {}

        fn device_type(&self) -> u32 {
            0
        }

        fn queues(&self) -> &[Queue] {
            &self.queues
        }

        fn queues_mut(&mut self) -> &mut [Queue] {
            &mut self.queues
        }

        fn queue_events(&self) -> &[EventFd] {
            &self.queue_evts
        }

        fn interrupt_evt(&self) -> &EventFd {
            &self.interrupt_evt
        }

        fn interrupt_status(&self) -> Arc<AtomicUsize> {
            Arc::new(AtomicUsize::new(0))
        }

        fn ack_features_by_page(&mut self, page: u32, value: u32) {
            let _ = page;
            let _ = value;
        }

        fn read_config(&self, offset: u64, data: &mut [u8]) {
            let _ = offset;
            let _ = data;
        }

        fn write_config(&mut self, offset: u64, data: &[u8]) {
            let _ = offset;
            let _ = data;
        }

        fn activate(&mut self, _: GuestMemoryMmap) -> ActivateResult {
            Ok(())
        }

        fn is_activated(&self) -> bool {
            false
        }
    }

    #[test]
    fn test_register_virtio_device() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem = vm_memory::test_utils::create_anon_guest_memory(
            &[(start_addr1, 0x1000), (start_addr2, 0x1000)],
            false,
        )
        .unwrap();
        let mut vm = builder::setup_kvm_vm(&guest_mem, false).unwrap();
        let mut device_manager = MMIODeviceManager::new().unwrap();
        let mut resource_manager = ResourceManager::new().unwrap();
        let mut acpi_config = AcpiConfig::new();

        let dummy = Arc::new(Mutex::new(DummyDevice::new()));
        #[cfg(target_arch = "x86_64")]
        assert!(builder::setup_interrupt_controller(&mut vm).is_ok());
        #[cfg(target_arch = "aarch64")]
        assert!(builder::setup_interrupt_controller(&mut vm, 1).is_ok());

        assert!(device_manager
            .register_virtio_test_device(
                vm.fd(),
                guest_mem,
                &mut resource_manager,
                &mut acpi_config,
                dummy,
                "dummy"
            )
            .is_ok());
    }

    #[test]
    fn test_register_too_many_devices() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem = vm_memory::test_utils::create_anon_guest_memory(
            &[(start_addr1, 0x1000), (start_addr2, 0x1000)],
            false,
        )
        .unwrap();
        let mut vm = builder::setup_kvm_vm(&guest_mem, false).unwrap();
        let mut device_manager = MMIODeviceManager::new().unwrap();
        let mut resource_manager = ResourceManager::new().unwrap();
        let mut acpi_config = AcpiConfig::new();

        #[cfg(target_arch = "x86_64")]
        assert!(builder::setup_interrupt_controller(&mut vm).is_ok());
        #[cfg(target_arch = "aarch64")]
        assert!(builder::setup_interrupt_controller(&mut vm, 1).is_ok());

        for _i in arch::IRQ_BASE..=arch::IRQ_MAX {
            device_manager
                .register_virtio_test_device(
                    vm.fd(),
                    guest_mem.clone(),
                    &mut resource_manager,
                    &mut acpi_config,
                    Arc::new(Mutex::new(DummyDevice::new())),
                    "dummy1",
                )
                .unwrap();
        }
        assert_eq!(
            format!(
                "{}",
                device_manager
                    .register_virtio_test_device(
                        vm.fd(),
                        guest_mem,
                        &mut resource_manager,
                        &mut acpi_config,
                        Arc::new(Mutex::new(DummyDevice::new())),
                        "dummy2"
                    )
                    .unwrap_err()
            ),
            "failed to allocate requested resource: The requested resource is not available."
                .to_string()
        );
    }

    #[test]
    fn test_dummy_device() {
        let dummy = DummyDevice::new();
        assert_eq!(dummy.device_type(), 0);
        assert_eq!(dummy.queues().len(), QUEUE_SIZES.len());
    }

    #[test]
    fn test_error_debug_display() {
        let check_fmt_err = |err: Error| {
            // Use an exhaustive 'match' to make sure we cover all error variants.
            // When adding a new variant here, don't forget to also call this function with it.
            let msg = match err {
                Error::Bus(_) => format!("{}{:?}", err, err),
                Error::Cmdline(_) => format!("{}{:?}", err, err),
                Error::DeviceNotFound => format!("{}{:?}", err, err),
                Error::EventFd(_) => format!("{}{:?}", err, err),
                Error::IncorrectDeviceType => format!("{}{:?}", err, err),
                Error::InternalDeviceError(_) => format!("{}{:?}", err, err),
                Error::InvalidInput => format!("{}{:?}", err, err),
                Error::RegisterIoEvent(_) => format!("{}{:?}", err, err),
                Error::RegisterIrqFd(_) => format!("{}{:?}", err, err),
                Error::UpdateFailed => format!("{}{:?}", err, err),
                Error::AllocatorError(_) => format!("{}{:?}", err, err),
            };
            assert!(!msg.is_empty());
        };
        check_fmt_err(Error::Bus(devices::BusError::Overlap));
        check_fmt_err(Error::Cmdline(linux_loader::cmdline::Error::TooLarge));
        check_fmt_err(Error::DeviceNotFound);
        check_fmt_err(Error::EventFd(io::Error::from_raw_os_error(0)));
        check_fmt_err(Error::IncorrectDeviceType);
        check_fmt_err(Error::InternalDeviceError(String::new()));
        check_fmt_err(Error::InvalidInput);
        check_fmt_err(Error::AllocatorError(vm_allocator::Error::Overflow));
        check_fmt_err(Error::RegisterIoEvent(errno::Error::new(0)));
        check_fmt_err(Error::RegisterIrqFd(errno::Error::new(0)));
        check_fmt_err(Error::UpdateFailed);
    }

    #[test]
    fn test_device_info() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem = vm_memory::test_utils::create_anon_guest_memory(
            &[(start_addr1, 0x1000), (start_addr2, 0x1000)],
            false,
        )
        .unwrap();
        let mut vm = builder::setup_kvm_vm(&guest_mem, false).unwrap();

        let mem_clone = guest_mem.clone();

        #[cfg(target_arch = "x86_64")]
        assert!(builder::setup_interrupt_controller(&mut vm).is_ok());
        #[cfg(target_arch = "aarch64")]
        assert!(builder::setup_interrupt_controller(&mut vm, 1).is_ok());

        let mut device_manager = MMIODeviceManager::new().unwrap();
        let mut resource_manager = ResourceManager::new().unwrap();
        let mut acpi_config = AcpiConfig::new();
        let dummy = Arc::new(Mutex::new(DummyDevice::new()));

        let type_id = dummy.lock().unwrap().device_type();
        let id = String::from("foo");
        let addr = device_manager
            .register_virtio_test_device(
                vm.fd(),
                guest_mem,
                &mut resource_manager,
                &mut acpi_config,
                dummy,
                &id,
            )
            .unwrap();
        assert!(device_manager
            .get_device(DeviceType::Virtio(type_id), &id)
            .is_some());
        assert_eq!(
            addr,
            device_manager.id_to_dev_info[&(DeviceType::Virtio(type_id), id.clone())].addr
        );
        assert_eq!(
            arch::IRQ_BASE,
            device_manager.id_to_dev_info[&(DeviceType::Virtio(type_id), id)].irqs[0]
        );

        let id = "bar";
        assert!(device_manager
            .get_device(DeviceType::Virtio(type_id), id)
            .is_none());

        let dummy2 = Arc::new(Mutex::new(DummyDevice::new()));
        let id2 = String::from("foo2");
        device_manager
            .register_virtio_test_device(
                vm.fd(),
                mem_clone,
                &mut resource_manager,
                &mut acpi_config,
                dummy2,
                &id2,
            )
            .unwrap();

        let mut count = 0;
        let _: Result<()> = device_manager.for_each_device(|devtype, devid, _, _| {
            assert_eq!(*devtype, DeviceType::Virtio(type_id));
            match devid.as_str() {
                "foo" => count += 1,
                "foo2" => count += 2,
                _ => unreachable!(),
            };
            Ok(())
        });
        assert_eq!(count, 3);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(device_manager.used_irqs_count(), 2);
    }

    #[test]
    fn test_slot_irq_allocation() {
        let mut resource_manager = ResourceManager::new().unwrap();

        // If we ask for 0 GSIs, we'll get 0 GSIs
        let device_info =
            MMIODeviceManager::allocate_mmio_resources(&mut resource_manager, 0).unwrap();
        assert_eq!(device_info.irqs.len(), 0);
        // If we ask 1 we'll get 1 and it will be the first available 1 (arch::IRQ_BASE)
        let device_info =
            MMIODeviceManager::allocate_mmio_resources(&mut resource_manager, 1).unwrap();
        assert_eq!(device_info.irqs[0], arch::IRQ_BASE);
        // If we ask all of the range now, we should fail
        assert_eq!(
            format!(
                "{}",
                MMIODeviceManager::allocate_mmio_resources(
                    &mut resource_manager,
                    arch::IRQ_MAX - arch::IRQ_BASE + 1
                )
                .unwrap_err()
            ),
            "failed to allocate requested resource: The requested resource is not available."
                .to_string()
        );

        // At this point, only 1 GSI (`arch::IRQ_BASE`) has been allocated, let's try to allocate
        // the rest of them apart from 1
        let device_info = MMIODeviceManager::allocate_mmio_resources(
            &mut resource_manager,
            arch::IRQ_MAX - arch::IRQ_BASE - 1,
        )
        .unwrap();
        // Now, we should have the list:
        // [IRQ_BASE + 1, IRQ_BASE + 2, IRQ_BASE + 3, IRQ_BASE + 4, ..., IRQ_MAX - 1]
        assert_eq!(device_info.irqs[0], arch::IRQ_BASE + 1);
        assert_eq!(*device_info.irqs.last().unwrap(), arch::IRQ_MAX - 1);

        // We cannot allocate 2 more
        assert_eq!(
            format!(
                "{}",
                MMIODeviceManager::allocate_mmio_resources(&mut resource_manager, 2).unwrap_err()
            ),
            "failed to allocate requested resource: The requested resource is not available."
                .to_string()
        );

        // We can allocate 1 though and it should be the last one of the range
        assert_eq!(
            MMIODeviceManager::allocate_mmio_resources(&mut resource_manager, 1)
                .unwrap()
                .irqs[0],
            arch::IRQ_MAX
        );

        // We have allocated all GSIs, but we should be able to allocate a slot if we don't
        // need a GSI
        assert!(MMIODeviceManager::allocate_mmio_resources(&mut resource_manager, 0).is_ok());
    }
}
