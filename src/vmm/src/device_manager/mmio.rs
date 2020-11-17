// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::{fmt, io};

#[cfg(target_arch = "aarch64")]
use arch::aarch64::DeviceInfoForFDT;
use arch::DeviceType;
use devices::pseudo::BootTimer;
use devices::virtio::{
    Balloon, Block, MmioTransport, Net, VirtioDevice, TYPE_BALLOON, TYPE_BLOCK, TYPE_NET,
    TYPE_VSOCK,
};
use devices::BusDevice;
use kernel::cmdline as kernel_cmdline;
use kvm_ioctls::{IoEventAddress, VmFd};
use logger::info;
#[cfg(target_arch = "aarch64")]
use utils::eventfd::EventFd;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;

/// Errors for MMIO device manager.
#[derive(Debug)]
pub enum Error {
    /// Failed to perform an operation on the bus.
    BusError(devices::BusError),
    /// Appending to kernel command line failed.
    Cmdline(kernel_cmdline::Error),
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
    /// No more IRQs are available.
    IrqsExhausted,
    /// Registering an IO Event failed.
    RegisterIoEvent(kvm_ioctls::Error),
    /// Registering an IRQ FD failed.
    RegisterIrqFd(kvm_ioctls::Error),
    /// Failed to update the mmio device.
    UpdateFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::BusError(e) => write!(f, "failed to perform bus operation: {}", e),
            Error::Cmdline(e) => write!(f, "unable to add device to kernel command line: {}", e),
            Error::EventFd(e) => write!(f, "failed to create or clone event descriptor: {}", e),
            Error::IncorrectDeviceType => write!(f, "incorrect device type"),
            Error::InternalDeviceError(e) => write!(f, "device error: {}", e),
            Error::InvalidInput => write!(f, "invalid configuration"),
            Error::IrqsExhausted => write!(f, "no more IRQs are available"),
            Error::RegisterIoEvent(e) => write!(f, "failed to register IO event: {}", e),
            Error::RegisterIrqFd(e) => write!(f, "failed to register irqfd: {}", e),
            Error::DeviceNotFound => write!(f, "the device couldn't be found"),
            Error::UpdateFailed => write!(f, "failed to update the mmio device"),
        }
    }
}

type Result<T> = ::std::result::Result<T, Error>;

/// This represents the size of the mmio device specified to the kernel as a cmdline option
/// It has to be larger than 0x100 (the offset where the configuration space starts from
/// the beginning of the memory mapped device registers) + the size of the configuration space
/// Currently hardcoded to 4K.
const MMIO_LEN: u64 = 0x1000;

/// Stores the address range and irq allocated to this device.
#[derive(Clone, Debug, PartialEq, Versionize)]
pub struct MMIODeviceInfo {
    /// Mmio address at which the device is registered.
    pub addr: u64,
    /// Mmio addr range length.
    pub len: u64,
    /// Used Irq line(s) for the device.
    pub irqs: Vec<u32>,
}

struct IrqManager {
    #[cfg(target_arch = "x86_64")]
    first: u32,
    last: u32,
    next_avail: u32,
}

impl IrqManager {
    pub fn new(first: u32, last: u32) -> Self {
        Self {
            #[cfg(target_arch = "x86_64")]
            first,
            last,
            next_avail: first,
        }
    }

    pub fn get(&mut self, count: u32) -> Result<Vec<u32>> {
        if self.next_avail + count > self.last + 1 {
            return Err(Error::IrqsExhausted);
        }
        let mut irqs = Vec::with_capacity(count as usize);
        for _ in 0..count {
            irqs.push(self.next_avail);
            self.next_avail += 1;
        }
        Ok(irqs)
    }

    #[cfg(target_arch = "x86_64")]
    pub fn check(&self, irqs: &[u32]) -> Result<()> {
        for irq in irqs {
            // Check for out of range.
            if self.first > *irq || *irq > self.last {
                return Err(Error::InvalidInput);
            }
        }
        Ok(())
    }
}

/// Manages the complexities of registering a MMIO device.
pub struct MMIODeviceManager {
    pub(crate) bus: devices::Bus,
    // Right now only used on x86_64, but aarch64 will also use these shortly.
    #[cfg(target_arch = "x86_64")]
    mmio_base: u64,
    next_avail_mmio: u64,
    irqs: IrqManager,
    pub(crate) id_to_dev_info: HashMap<(DeviceType, String), MMIODeviceInfo>,
}

impl MMIODeviceManager {
    /// Create a new DeviceManager handling mmio devices (virtio net, block).
    pub fn new(mmio_base: u64, irq_interval: (u32, u32)) -> MMIODeviceManager {
        MMIODeviceManager {
            #[cfg(target_arch = "x86_64")]
            mmio_base,
            next_avail_mmio: mmio_base,
            irqs: IrqManager::new(irq_interval.0, irq_interval.1),
            bus: devices::Bus::new(),
            id_to_dev_info: HashMap::new(),
        }
    }

    /// Allocates resources for a new device to be added.
    fn allocate_new_slot(&mut self, irq_count: u32) -> Result<MMIODeviceInfo> {
        let irqs = self.irqs.get(irq_count)?;
        let slot = MMIODeviceInfo {
            addr: self.next_avail_mmio,
            len: MMIO_LEN,
            irqs,
        };
        self.next_avail_mmio += MMIO_LEN;
        Ok(slot)
    }

    #[cfg(target_arch = "x86_64")]
    /// Does a slot sanity check against expected values.
    pub fn slot_sanity_check(&self, slot: &MMIODeviceInfo) -> Result<()> {
        if slot.addr < self.mmio_base || slot.len != MMIO_LEN {
            return Err(Error::InvalidInput);
        }
        self.irqs.check(&slot.irqs)
    }

    fn register_mmio_device(
        &mut self,
        identifier: (DeviceType, String),
        slot: MMIODeviceInfo,
        device: Arc<Mutex<dyn BusDevice>>,
    ) -> Result<()> {
        self.bus
            .insert(device, slot.addr, slot.len)
            .map_err(Error::BusError)?;
        self.id_to_dev_info.insert(identifier, slot);
        Ok(())
    }

    /// Register a virtio-over-MMIO device to be used via MMIO transport at a specific slot.
    pub fn register_virtio_mmio_device(
        &mut self,
        vm: &VmFd,
        device_id: String,
        mmio_device: MmioTransport,
        slot: &MMIODeviceInfo,
    ) -> Result<()> {
        // Our virtio devices are currently hardcoded to use a single IRQ.
        // Validate that requirement.
        if slot.irqs.len() != 1 {
            return Err(Error::InvalidInput);
        }
        let identifier;
        {
            let locked_device = mmio_device.locked_device();
            identifier = (DeviceType::Virtio(locked_device.device_type()), device_id);
            for (i, queue_evt) in locked_device.queue_events().iter().enumerate() {
                let io_addr =
                    IoEventAddress::Mmio(slot.addr + u64::from(devices::virtio::NOTIFY_REG_OFFSET));
                vm.register_ioevent(queue_evt, &io_addr, i as u32)
                    .map_err(Error::RegisterIoEvent)?;
            }
            vm.register_irqfd(locked_device.interrupt_evt(), slot.irqs[0])
                .map_err(Error::RegisterIrqFd)?;
        }

        self.register_mmio_device(identifier, slot.clone(), Arc::new(Mutex::new(mmio_device)))
    }

    /// Append a registered virtio-over-MMIO device to the kernel cmdline.
    #[cfg(target_arch = "x86_64")]
    pub fn add_virtio_device_to_cmdline(
        cmdline: &mut kernel_cmdline::Cmdline,
        slot: &MMIODeviceInfo,
    ) -> Result<()> {
        // as per doc, [virtio_mmio.]device=<size>@<baseaddr>:<irq> needs to be appended
        // to kernel commandline for virtio mmio devices to get recognized
        // the size parameter has to be transformed to KiB, so dividing hexadecimal value in
        // bytes to 1024; further, the '{}' formatting rust construct will automatically
        // transform it to decimal
        cmdline
            .insert(
                "virtio_mmio.device",
                &format!("{}K@0x{:08x}:{}", slot.len / 1024, slot.addr, slot.irqs[0]),
            )
            .map_err(Error::Cmdline)
    }

    /// Allocate slot and register an already created virtio-over-MMIO device. Also Adds the device
    /// to the boot cmdline.
    pub fn register_new_virtio_mmio_device(
        &mut self,
        vm: &VmFd,
        device_id: String,
        mmio_device: MmioTransport,
        _cmdline: &mut kernel_cmdline::Cmdline,
    ) -> Result<MMIODeviceInfo> {
        let mmio_slot = self.allocate_new_slot(1)?;
        self.register_virtio_mmio_device(vm, device_id, mmio_device, &mmio_slot)?;
        #[cfg(target_arch = "x86_64")]
        Self::add_virtio_device_to_cmdline(_cmdline, &mmio_slot)?;
        Ok(mmio_slot)
    }

    #[cfg(target_arch = "aarch64")]
    /// Register an early console at some MMIO address.
    pub fn register_mmio_serial(
        &mut self,
        vm: &VmFd,
        serial: Arc<Mutex<devices::legacy::Serial>>,
    ) -> Result<()> {
        let slot = self.allocate_new_slot(1)?;
        vm.register_irqfd(
            &serial.lock().expect("Poisoned lock").interrupt_evt(),
            slot.irqs[0],
        )
        .map_err(Error::RegisterIrqFd)?;

        let identifier = (DeviceType::Serial, DeviceType::Serial.to_string());
        self.register_mmio_device(identifier, slot, serial)
    }

    #[cfg(target_arch = "aarch64")]
    /// Append the registered early console to the kernel cmdline.
    pub fn add_mmio_serial_to_cmdline(&self, cmdline: &mut kernel_cmdline::Cmdline) -> Result<()> {
        let mmio_slot = self
            .id_to_dev_info
            .get(&(DeviceType::Serial, DeviceType::Serial.to_string()))
            .ok_or(Error::DeviceNotFound)?;
        cmdline
            .insert("earlycon", &format!("uart,mmio,0x{:08x}", mmio_slot.addr))
            .map_err(Error::Cmdline)
    }

    #[cfg(target_arch = "aarch64")]
    /// Create and register a new MMIO RTC device.
    pub fn register_new_mmio_rtc(&mut self, vm: &VmFd) -> Result<()> {
        // Create and attach a new RTC device.
        let slot = self.allocate_new_slot(1)?;
        let rtc_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?;
        let device = devices::legacy::RTC::new(rtc_evt.try_clone().map_err(Error::EventFd)?);
        vm.register_irqfd(&rtc_evt, slot.irqs[0])
            .map_err(Error::RegisterIrqFd)?;

        let identifier = (DeviceType::RTC, DeviceType::RTC.to_string());
        self.register_mmio_device(identifier, slot, Arc::new(Mutex::new(device)))
    }

    /// Create and register a boot timer device.
    pub fn register_new_mmio_boot_timer(&mut self, device: BootTimer) -> Result<()> {
        // Create and attach a new boot timer device.
        let slot = self.allocate_new_slot(0)?;

        let identifier = (DeviceType::BootTimer, DeviceType::BootTimer.to_string());
        self.register_mmio_device(identifier, slot, Arc::new(Mutex::new(device)))
    }

    /// Gets the information of the devices registered up to some point in time.
    pub fn get_device_info(&self) -> &HashMap<(DeviceType, String), MMIODeviceInfo> {
        &self.id_to_dev_info
    }

    /// Gets the the specified device.
    pub fn get_device(
        &self,
        device_type: DeviceType,
        device_id: &str,
    ) -> Option<&Mutex<dyn BusDevice>> {
        if let Some(dev_info) = self
            .id_to_dev_info
            .get(&(device_type, device_id.to_string()))
        {
            if let Some((_, device)) = self.bus.get_device(dev_info.addr) {
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
        let _: Result<()> = self.for_each_device(|devtype, id, _, bus_dev| {
            // We only kick virtio devices for now.
            if let DeviceType::Virtio(virtio_type) = *devtype {
                let bus_dev = bus_dev.lock().expect("Poisoned lock");
                // Virtio devices are guaranteed MmioTransport.
                let mmio_dev = bus_dev.as_any().downcast_ref::<MmioTransport>().unwrap();
                let mut virtio = mmio_dev.locked_device();
                match virtio_type {
                    TYPE_BALLOON => {
                        info!("kick balloon {}.", id);
                        let balloon = virtio.as_mut_any().downcast_mut::<Balloon>().unwrap();
                        // If device is activated, kick the balloon queue(s) to make up for any
                        // pending or in-flight epoll events we may have not captured in snapshot.
                        // Stats queue doesn't need kicking as it is notified via a `timer_fd`.
                        if balloon.is_activated() {
                            balloon.process_virtio_queues();
                        }
                    }
                    TYPE_BLOCK => {
                        info!("kick block {}.", id);
                        let block = virtio.as_mut_any().downcast_mut::<Block>().unwrap();
                        // If device is activated, kick the block queue(s) to make up for any
                        // pending or in-flight epoll events we may have not captured in snapshot.
                        // No need to kick Ratelimiters because they are restored 'unblocked' so
                        // any inflight `timer_fd` events can be safely discarded.
                        if block.is_activated() {
                            block.process_virtio_queues();
                        }
                    }
                    TYPE_NET => {
                        info!("kick net {}.", id);
                        let net = virtio.as_mut_any().downcast_mut::<Net>().unwrap();
                        // If device is activated, kick the net queue(s) to make up for any
                        // pending or in-flight epoll events we may have not captured in snapshot.
                        // No need to kick Ratelimiters because they are restored 'unblocked' so
                        // any inflight `timer_fd` events can be safely discarded.
                        if net.is_activated() {
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
            };
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
    use super::*;
    use crate::builder;
    use devices::virtio::{ActivateResult, Queue, VirtioDevice};
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;
    use utils::errno;
    use utils::eventfd::EventFd;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    const QUEUE_SIZES: &[u16] = &[64];

    impl MMIODeviceManager {
        fn register_virtio_test_device(
            &mut self,
            vm: &VmFd,
            guest_mem: GuestMemoryMmap,
            device: Arc<Mutex<dyn devices::virtio::VirtioDevice>>,
            cmdline: &mut kernel_cmdline::Cmdline,
            dev_id: &str,
        ) -> Result<u64> {
            let mmio_device = MmioTransport::new(guest_mem, device);
            let mmio_slot =
                self.register_new_virtio_mmio_device(vm, dev_id.to_string(), mmio_device, cmdline)?;
            Ok(mmio_slot.addr)
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
        let guest_mem =
            GuestMemoryMmap::from_ranges(&[(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();
        let mut vm = builder::setup_kvm_vm(&guest_mem, false).unwrap();
        let mut device_manager =
            MMIODeviceManager::new(0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));

        let mut cmdline = kernel_cmdline::Cmdline::new(4096);
        let dummy = Arc::new(Mutex::new(DummyDevice::new()));
        #[cfg(target_arch = "x86_64")]
        assert!(builder::setup_interrupt_controller(&mut vm).is_ok());
        #[cfg(target_arch = "aarch64")]
        assert!(builder::setup_interrupt_controller(&mut vm, 1).is_ok());

        assert!(device_manager
            .register_virtio_test_device(vm.fd(), guest_mem, dummy, &mut cmdline, "dummy")
            .is_ok());
    }

    #[test]
    fn test_register_too_many_devices() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem =
            GuestMemoryMmap::from_ranges(&[(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();
        let mut vm = builder::setup_kvm_vm(&guest_mem, false).unwrap();
        let mut device_manager =
            MMIODeviceManager::new(0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));

        let mut cmdline = kernel_cmdline::Cmdline::new(4096);
        #[cfg(target_arch = "x86_64")]
        assert!(builder::setup_interrupt_controller(&mut vm).is_ok());
        #[cfg(target_arch = "aarch64")]
        assert!(builder::setup_interrupt_controller(&mut vm, 1).is_ok());

        for _i in arch::IRQ_BASE..=arch::IRQ_MAX {
            device_manager
                .register_virtio_test_device(
                    vm.fd(),
                    guest_mem.clone(),
                    Arc::new(Mutex::new(DummyDevice::new())),
                    &mut cmdline,
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
                        Arc::new(Mutex::new(DummyDevice::new())),
                        &mut cmdline,
                        "dummy2"
                    )
                    .unwrap_err()
            ),
            "no more IRQs are available".to_string()
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
        let check_fmt_err = |e: Error| {
            // Use an exhaustive 'match' to make sure we cover all error variants.
            // When adding a new variant here, don't forget to also call this function with it.
            let msg = match e {
                Error::BusError(_) => format!("{}{:?}", e, e),
                Error::Cmdline(_) => format!("{}{:?}", e, e),
                Error::DeviceNotFound => format!("{}{:?}", e, e),
                Error::EventFd(_) => format!("{}{:?}", e, e),
                Error::IncorrectDeviceType => format!("{}{:?}", e, e),
                Error::InternalDeviceError(_) => format!("{}{:?}", e, e),
                Error::InvalidInput => format!("{}{:?}", e, e),
                Error::IrqsExhausted => format!("{}{:?}", e, e),
                Error::RegisterIoEvent(_) => format!("{}{:?}", e, e),
                Error::RegisterIrqFd(_) => format!("{}{:?}", e, e),
                Error::UpdateFailed => format!("{}{:?}", e, e),
            };
            assert!(!msg.is_empty());
        };
        check_fmt_err(Error::BusError(devices::BusError::Overlap));
        check_fmt_err(Error::Cmdline(kernel_cmdline::Error::CommandLineCopy));
        check_fmt_err(Error::DeviceNotFound);
        check_fmt_err(Error::EventFd(io::Error::from_raw_os_error(0)));
        check_fmt_err(Error::IncorrectDeviceType);
        check_fmt_err(Error::InternalDeviceError(String::new()));
        check_fmt_err(Error::InvalidInput);
        check_fmt_err(Error::IrqsExhausted);
        check_fmt_err(Error::RegisterIoEvent(errno::Error::new(0)));
        check_fmt_err(Error::RegisterIrqFd(errno::Error::new(0)));
        check_fmt_err(Error::UpdateFailed);
    }

    #[test]
    fn test_device_info() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem =
            GuestMemoryMmap::from_ranges(&[(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();
        let mut vm = builder::setup_kvm_vm(&guest_mem, false).unwrap();

        #[cfg(target_arch = "x86_64")]
        // Only used for x86_64 part of the test.
        let mem_clone = guest_mem.clone();

        #[cfg(target_arch = "x86_64")]
        assert!(builder::setup_interrupt_controller(&mut vm).is_ok());
        #[cfg(target_arch = "aarch64")]
        assert!(builder::setup_interrupt_controller(&mut vm, 1).is_ok());

        let mut device_manager =
            MMIODeviceManager::new(0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));
        let mut cmdline = kernel_cmdline::Cmdline::new(4096);
        let dummy = Arc::new(Mutex::new(DummyDevice::new()));

        let type_id = dummy.lock().unwrap().device_type();
        let id = String::from("foo");
        let addr = device_manager
            .register_virtio_test_device(vm.fd(), guest_mem, dummy, &mut cmdline, &id)
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
            .get_device(DeviceType::Virtio(type_id), &id)
            .is_none());

        #[cfg(target_arch = "x86_64")]
        {
            let dummy2 = Arc::new(Mutex::new(DummyDevice::new()));
            let id2 = String::from("foo2");
            device_manager
                .register_virtio_test_device(vm.fd(), mem_clone, dummy2, &mut cmdline, &id2)
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
        }
    }

    #[test]
    fn test_slot_irq_allocation() {
        let mut device_manager =
            MMIODeviceManager::new(0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));
        let _addr = device_manager.allocate_new_slot(0);
        assert_eq!(device_manager.irqs.next_avail, arch::IRQ_BASE);
        let _addr = device_manager.allocate_new_slot(1);
        assert_eq!(device_manager.irqs.next_avail, arch::IRQ_BASE + 1);
        assert_eq!(
            format!(
                "{}",
                device_manager
                    .allocate_new_slot(arch::IRQ_MAX - arch::IRQ_BASE + 1)
                    .unwrap_err()
            ),
            "no more IRQs are available".to_string()
        );

        let _addr = device_manager.allocate_new_slot(arch::IRQ_MAX - arch::IRQ_BASE - 1);
        assert_eq!(device_manager.irqs.next_avail, arch::IRQ_MAX);
        assert_eq!(
            format!("{}", device_manager.allocate_new_slot(2).unwrap_err()),
            "no more IRQs are available".to_string()
        );

        let _addr = device_manager.allocate_new_slot(1);
        assert_eq!(device_manager.irqs.next_avail, arch::IRQ_MAX + 1);
        assert!(device_manager.allocate_new_slot(0).is_ok());
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_slot_sanity_checks() {
        let mmio_base = 0xd000_0000;
        let device_manager = MMIODeviceManager::new(mmio_base, (arch::IRQ_BASE, arch::IRQ_MAX));

        // Valid slot.
        let slot = MMIODeviceInfo {
            addr: mmio_base,
            len: MMIO_LEN,
            irqs: vec![arch::IRQ_BASE, arch::IRQ_BASE + 1],
        };
        device_manager.slot_sanity_check(&slot).unwrap();
        // 'addr' below base.
        let slot = MMIODeviceInfo {
            addr: mmio_base - 1,
            len: MMIO_LEN,
            irqs: vec![arch::IRQ_BASE, arch::IRQ_BASE + 1],
        };
        device_manager.slot_sanity_check(&slot).unwrap_err();
        // Invalid 'len'.
        let slot = MMIODeviceInfo {
            addr: mmio_base,
            len: MMIO_LEN - 1,
            irqs: vec![arch::IRQ_BASE, arch::IRQ_BASE + 1],
        };
        device_manager.slot_sanity_check(&slot).unwrap_err();
        // 'irq' below range.
        let slot = MMIODeviceInfo {
            addr: mmio_base,
            len: MMIO_LEN,
            irqs: vec![arch::IRQ_BASE - 1, arch::IRQ_BASE + 1],
        };
        device_manager.slot_sanity_check(&slot).unwrap_err();
        // 'irq' above range.
        let slot = MMIODeviceInfo {
            addr: mmio_base,
            len: MMIO_LEN,
            irqs: vec![arch::IRQ_BASE, arch::IRQ_MAX + 1],
        };
        device_manager.slot_sanity_check(&slot).unwrap_err();
    }
}
