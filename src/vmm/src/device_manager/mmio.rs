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
use devices::{virtio::MmioTransport, BusDevice};
use kernel::cmdline as kernel_cmdline;
use kvm_ioctls::{IoEventAddress, VmFd};
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
    /// Failure in creating or cloning an event fd.
    EventFd(io::Error),
    /// Invalid configuration attempted.
    InvalidInput,
    /// No more IRQs are available.
    IrqsExhausted,
    /// Registering an IO Event failed.
    RegisterIoEvent(kvm_ioctls::Error),
    /// Registering an IRQ FD failed.
    RegisterIrqFd(kvm_ioctls::Error),
    /// The device couldn't be found
    DeviceNotFound,
    /// Failed to update the mmio device.
    UpdateFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::BusError(ref e) => write!(f, "failed to perform bus operation: {}", e),
            Error::Cmdline(ref e) => {
                write!(f, "unable to add device to kernel command line: {}", e)
            }
            Error::EventFd(ref e) => write!(f, "failed to create or clone event descriptor: {}", e),
            Error::InvalidInput => write!(f, "invalid configuration"),
            Error::IrqsExhausted => write!(f, "no more IRQs are available"),
            Error::RegisterIoEvent(ref e) => write!(f, "failed to register IO event: {}", e),
            Error::RegisterIrqFd(ref e) => write!(f, "failed to register irqfd: {}", e),
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
    fn test_error_messages() {
        let device_manager = MMIODeviceManager::new(0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));
        let mut cmdline = kernel_cmdline::Cmdline::new(4096);
        let e = Error::Cmdline(
            cmdline
                .insert(
                    "virtio_mmio=device",
                    &format!(
                        "{}K@0x{:08x}:{}",
                        MMIO_LEN / 1024,
                        device_manager.next_avail_mmio,
                        device_manager.next_avail_irq
                    ),
                )
                .unwrap_err(),
        );
        assert_eq!(
            format!("{}", e),
            format!(
                "unable to add device to kernel command line: {}",
                kernel_cmdline::Error::HasEquals
            ),
        );
        assert_eq!(
            format!("{}", Error::UpdateFailed),
            "failed to update the mmio device"
        );
        assert_eq!(
            format!("{}", Error::BusError(devices::BusError::Overlap)),
            format!(
                "failed to perform bus operation: {}",
                devices::BusError::Overlap
            )
        );
        let err = Error::InvalidInput;
        format!("{}{:?}", err, err);
        assert_eq!(
            format!("{}", Error::IrqsExhausted),
            "no more IRQs are available"
        );
        assert_eq!(
            format!("{}", Error::RegisterIoEvent(errno::Error::new(0))),
            format!("failed to register IO event: {}", errno::Error::new(0))
        );
        assert_eq!(
            format!("{}", Error::RegisterIrqFd(errno::Error::new(0))),
            format!("failed to register irqfd: {}", errno::Error::new(0))
        );
    }

    #[test]
    fn test_device_info() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem =
            GuestMemoryMmap::from_ranges(&[(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();
        let mut vm = builder::setup_kvm_vm(&guest_mem, false).unwrap();

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
