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
use devices;

// Temporarly we have this hard coupling here until we refactor all devices and
// have a single path of registering devices. Right now we have 2, one using
// epoll_context and another using EventManager.
use devices::virtio::block::Block;
use devices::virtio::TYPE_BLOCK;

use devices::BusDevice;
use kernel::cmdline as kernel_cmdline;
use kvm_ioctls::{IoEventAddress, VmFd};
#[cfg(target_arch = "aarch64")]
use utils::eventfd::EventFd;

/// Errors for MMIO device manager.
#[derive(Debug)]
pub enum Error {
    /// Failed to perform an operation on the bus.
    BusError(devices::BusError),
    /// Could not create the mmio device to wrap a VirtioDevice.
    CreateMmioDevice(io::Error),
    /// Appending to kernel command line failed.
    Cmdline(kernel_cmdline::Error),
    /// Failure in creating or cloning an event fd.
    EventFd(io::Error),
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
            Error::CreateMmioDevice(ref e) => write!(f, "failed to create mmio device: {}", e),
            Error::Cmdline(ref e) => {
                write!(f, "unable to add device to kernel command line: {}", e)
            }
            Error::EventFd(ref e) => write!(f, "failed to create or clone event descriptor: {}", e),
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

/// This represents the offset at which the device should call BusDevice::write in order to write
/// to its configuration space.
pub const MMIO_CFG_SPACE_OFF: u64 = 0x100;

/// Manages the complexities of registering a MMIO device.
pub struct MMIODeviceManager {
    pub bus: devices::Bus,
    mmio_base: u64,
    irq: u32,
    last_irq: u32,
    id_to_dev_info: HashMap<(DeviceType, String), MMIODeviceInfo>,
    block_devices: HashMap<String, Arc<Mutex<Block>>>,
}

impl MMIODeviceManager {
    /// Create a new DeviceManager handling mmio devices (virtio net, block).
    pub fn new(mmio_base: &mut u64, irq_interval: (u32, u32)) -> MMIODeviceManager {
        if cfg!(target_arch = "aarch64") {
            *mmio_base += MMIO_LEN;
        }
        MMIODeviceManager {
            mmio_base: *mmio_base,
            irq: irq_interval.0,
            last_irq: irq_interval.1,
            bus: devices::Bus::new(),
            id_to_dev_info: HashMap::new(),
            block_devices: HashMap::new(),
        }
    }

    // Common function for registering mmio transport resources: mmio io events, interrupts
    // Also attaches the transport device to the I/O Bus.
    fn register_device_resources(
        &mut self,
        vm: &VmFd,
        transport_device: devices::virtio::MmioTransport,
        cmdline: &mut kernel_cmdline::Cmdline,
        device_id: &str,
        device_type: u32,
    ) -> Result<()> {
        if self.irq > self.last_irq {
            return Err(Error::IrqsExhausted);
        }

        let queue_evts = transport_device
            .locked_device()
            .get_queue_events()
            .map_err(Error::EventFd)?;

        for (i, queue_evt) in queue_evts.iter().enumerate() {
            let io_addr = IoEventAddress::Mmio(
                self.mmio_base + u64::from(devices::virtio::NOTIFY_REG_OFFSET),
            );

            vm.register_ioevent(queue_evt, &io_addr, i as u32)
                .map_err(Error::RegisterIoEvent)?;
        }

        let interrupt_evt = transport_device
            .locked_device()
            .get_interrupt()
            .map_err(Error::EventFd)?;
        vm.register_irqfd(&interrupt_evt, self.irq)
            .map_err(Error::RegisterIrqFd)?;

        self.bus
            .insert(
                Arc::new(Mutex::new(transport_device)),
                self.mmio_base,
                MMIO_LEN,
            )
            .map_err(Error::BusError)?;

        // as per doc, [virtio_mmio.]device=<size>@<baseaddr>:<irq> needs to be appended
        // to kernel commandline for virtio mmio devices to get recognized
        // the size parameter has to be transformed to KiB, so dividing hexadecimal value in
        // bytes to 1024; further, the '{}' formatting rust construct will automatically
        // transform it to decimal

        #[cfg(target_arch = "x86_64")]
        cmdline
            .insert(
                "virtio_mmio.device",
                &format!("{}K@0x{:08x}:{}", MMIO_LEN / 1024, self.mmio_base, self.irq),
            )
            .map_err(Error::Cmdline)?;

        let ret = self.mmio_base;

        self.id_to_dev_info.insert(
            (DeviceType::Virtio(device_type), device_id.to_string()),
            MMIODeviceInfo {
                addr: ret,
                len: MMIO_LEN,
                irq: self.irq,
            },
        );

        self.mmio_base += MMIO_LEN;
        self.irq += 1;

        Ok(())
    }

    // This is the secondary path for registering devices.
    // TODO: Replace with a generic path for all devices insted of being
    // Block specific.
    //
    // Register a new block device using Mmio as transport.
    pub fn register_block_device(
        &mut self,
        vm: &VmFd,
        transport_device: devices::virtio::MmioTransport,
        device: Arc<Mutex<devices::virtio::Block>>,
        cmdline: &mut kernel_cmdline::Cmdline,
        device_id: &str,
    ) -> Result<()> {
        self.register_device_resources(vm, transport_device, cmdline, device_id, TYPE_BLOCK)?;
        // Temporarly use this hashmap. It is used to retrieve the Block object
        // in update_drive_handler().
        self.block_devices.insert(device_id.to_owned(), device);

        Ok(())
    }

    /// Register an already created MMIO device to be used via MMIO transport.
    pub fn register_mmio_device(
        &mut self,
        vm: &VmFd,
        mmio_device: devices::virtio::MmioTransport,
        cmdline: &mut kernel_cmdline::Cmdline,
        type_id: u32,
        device_id: &str,
    ) -> Result<u64> {
        if self.irq > self.last_irq {
            return Err(Error::IrqsExhausted);
        }

        let queue_evts = mmio_device
            .locked_device()
            .get_queue_events()
            .map_err(Error::EventFd)?;

        for (i, queue_evt) in queue_evts.iter().enumerate() {
            let io_addr = IoEventAddress::Mmio(
                self.mmio_base + u64::from(devices::virtio::NOTIFY_REG_OFFSET),
            );

            vm.register_ioevent(queue_evt, &io_addr, i as u32)
                .map_err(Error::RegisterIoEvent)?;
        }

        let interrupt_evt = mmio_device
            .locked_device()
            .get_interrupt()
            .map_err(Error::EventFd)?;
        vm.register_irqfd(&interrupt_evt, self.irq)
            .map_err(Error::RegisterIrqFd)?;

        self.bus
            .insert(Arc::new(Mutex::new(mmio_device)), self.mmio_base, MMIO_LEN)
            .map_err(Error::BusError)?;

        // as per doc, [virtio_mmio.]device=<size>@<baseaddr>:<irq> needs to be appended
        // to kernel commandline for virtio mmio devices to get recognized
        // the size parameter has to be transformed to KiB, so dividing hexadecimal value in
        // bytes to 1024; further, the '{}' formatting rust construct will automatically
        // transform it to decimal

        #[cfg(target_arch = "x86_64")]
        cmdline
            .insert(
                "virtio_mmio.device",
                &format!("{}K@0x{:08x}:{}", MMIO_LEN / 1024, self.mmio_base, self.irq),
            )
            .map_err(Error::Cmdline)?;
        let ret = self.mmio_base;

        self.id_to_dev_info.insert(
            (DeviceType::Virtio(type_id), device_id.to_string()),
            MMIODeviceInfo {
                addr: ret,
                len: MMIO_LEN,
                irq: self.irq,
            },
        );

        self.mmio_base += MMIO_LEN;
        self.irq += 1;

        Ok(ret)
    }

    #[cfg(target_arch = "aarch64")]
    /// Register an early console at some MMIO address.
    pub fn register_mmio_serial(
        &mut self,
        vm: &VmFd,
        cmdline: &mut kernel_cmdline::Cmdline,
        serial: Arc<Mutex<devices::legacy::Serial>>,
    ) -> Result<()> {
        if self.irq > self.last_irq {
            return Err(Error::IrqsExhausted);
        }

        vm.register_irqfd(&serial.lock().unwrap().interrupt_evt(), self.irq)
            .map_err(Error::RegisterIrqFd)?;

        self.bus
            .insert(serial, self.mmio_base, MMIO_LEN)
            .map_err(|err| Error::BusError(err))?;

        cmdline
            .insert("earlycon", &format!("uart,mmio,0x{:08x}", self.mmio_base))
            .map_err(Error::Cmdline)?;

        let ret = self.mmio_base;
        self.id_to_dev_info.insert(
            (DeviceType::Serial, DeviceType::Serial.to_string()),
            MMIODeviceInfo {
                addr: ret,
                len: MMIO_LEN,
                irq: self.irq,
            },
        );

        self.mmio_base += MMIO_LEN;
        self.irq += 1;

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    /// Register a MMIO RTC device.
    pub fn register_mmio_rtc(&mut self, vm: &VmFd) -> Result<()> {
        if self.irq > self.last_irq {
            return Err(Error::IrqsExhausted);
        }

        // Attaching the RTC device.
        let rtc_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?;
        let device = devices::legacy::RTC::new(rtc_evt.try_clone().map_err(Error::EventFd)?);
        vm.register_irqfd(&rtc_evt, self.irq)
            .map_err(Error::RegisterIrqFd)?;

        self.bus
            .insert(Arc::new(Mutex::new(device)), self.mmio_base, MMIO_LEN)
            .map_err(|err| Error::BusError(err))?;

        let ret = self.mmio_base;
        self.id_to_dev_info.insert(
            (DeviceType::RTC, "rtc".to_string()),
            MMIODeviceInfo {
                addr: ret,
                len: MMIO_LEN,
                irq: self.irq,
            },
        );

        self.mmio_base += MMIO_LEN;
        self.irq += 1;

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
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

    pub fn get_block_device(&self, device_id: &str) -> Option<&Arc<Mutex<Block>>> {
        self.block_devices.get(device_id)
    }
}

/// Private structure for storing information about the MMIO device registered at some address on the bus.
#[derive(Clone, Debug)]
pub struct MMIODeviceInfo {
    addr: u64,
    irq: u32,
    len: u64,
}

#[cfg(target_arch = "aarch64")]
impl DeviceInfoForFDT for MMIODeviceInfo {
    fn addr(&self) -> u64 {
        self.addr
    }
    fn irq(&self) -> u32 {
        self.irq
    }
    fn length(&self) -> u64 {
        self.len
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::builder;
    use super::*;
    use arch;
    use devices::virtio::{ActivateResult, Queue, VirtioDevice, TYPE_BLOCK};
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;
    use utils::errno;
    use utils::eventfd::EventFd;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    const QUEUE_SIZES: &[u16] = &[64];

    impl MMIODeviceManager {
        fn register_virtio_device(
            &mut self,
            vm: &VmFd,
            guest_mem: GuestMemoryMmap,
            device: Arc<Mutex<dyn devices::virtio::VirtioDevice>>,
            cmdline: &mut kernel_cmdline::Cmdline,
            type_id: u32,
            device_id: &str,
        ) -> Result<u64> {
            let mmio_device = devices::virtio::MmioTransport::new(guest_mem, device)
                .map_err(Error::CreateMmioDevice)?;

            self.register_mmio_device(vm, mmio_device, cmdline, type_id, device_id)
        }

        fn update_drive(&self, device_id: &str, new_size: u64) -> Result<()> {
            match self.get_device(DeviceType::Virtio(TYPE_BLOCK), device_id) {
                Some(device) => {
                    let data = devices::virtio::build_config_space(new_size);
                    let mut busdev = device.lock().map_err(|_| Error::UpdateFailed)?;

                    busdev.write(MMIO_CFG_SPACE_OFF, &data[..]);
                    busdev
                        .interrupt(devices::virtio::VIRTIO_MMIO_INT_CONFIG)
                        .unwrap();

                    Ok(())
                }
                None => Err(Error::DeviceNotFound),
            }
        }
    }

    #[allow(dead_code)]
    struct DummyDevice {
        dummy: u32,
        queues: Vec<Queue>,
        queue_evt: EventFd,
        interrupt_evt: EventFd,
    }

    impl DummyDevice {
        pub fn new() -> Self {
            DummyDevice {
                dummy: 0,
                queues: QUEUE_SIZES.iter().map(|&s| Queue::new(s)).collect(),
                queue_evt: EventFd::new(libc::EFD_NONBLOCK).expect("cannot create eventFD"),
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

        fn get_queues(&mut self) -> &mut Vec<Queue> {
            &mut self.queues
        }

        fn get_queue_events(&self) -> std::result::Result<Vec<EventFd>, std::io::Error> {
            Ok(vec![self.queue_evt.try_clone()?])
        }

        fn get_interrupt(&self) -> std::result::Result<EventFd, std::io::Error> {
            Ok(self.interrupt_evt.try_clone()?)
        }

        fn get_interrupt_status(&self) -> Arc<AtomicUsize> {
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

        #[allow(unused_variables)]
        #[allow(unused_mut)]
        fn activate(&mut self, mem: GuestMemoryMmap) -> ActivateResult {
            Ok(())
        }
    }

    #[test]
    fn test_register_virtio_device() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem =
            GuestMemoryMmap::from_ranges(&[(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();
        let mut vm = builder::setup_kvm_vm(&guest_mem).unwrap();
        let mut device_manager =
            MMIODeviceManager::new(&mut 0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));

        let mut cmdline = kernel_cmdline::Cmdline::new(4096);
        let dummy = Arc::new(Mutex::new(DummyDevice::new()));
        #[cfg(target_arch = "x86_64")]
        assert!(builder::setup_interrupt_controller(&mut vm).is_ok());
        #[cfg(target_arch = "aarch64")]
        assert!(builder::setup_interrupt_controller(&mut vm, 1).is_ok());

        assert!(device_manager
            .register_virtio_device(vm.fd(), guest_mem, dummy, &mut cmdline, 0, "dummy")
            .is_ok());
    }

    #[test]
    fn test_register_too_many_devices() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem =
            GuestMemoryMmap::from_ranges(&[(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();
        let mut vm = builder::setup_kvm_vm(&guest_mem).unwrap();
        let mut device_manager =
            MMIODeviceManager::new(&mut 0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));

        let mut cmdline = kernel_cmdline::Cmdline::new(4096);
        #[cfg(target_arch = "x86_64")]
        assert!(builder::setup_interrupt_controller(&mut vm).is_ok());
        #[cfg(target_arch = "aarch64")]
        assert!(builder::setup_interrupt_controller(&mut vm, 1).is_ok());

        for _i in arch::IRQ_BASE..=arch::IRQ_MAX {
            device_manager
                .register_virtio_device(
                    vm.fd(),
                    guest_mem.clone(),
                    Arc::new(Mutex::new(DummyDevice::new())),
                    &mut cmdline,
                    0,
                    "dummy1",
                )
                .unwrap();
        }
        assert_eq!(
            format!(
                "{}",
                device_manager
                    .register_virtio_device(
                        vm.fd(),
                        guest_mem,
                        Arc::new(Mutex::new(DummyDevice::new())),
                        &mut cmdline,
                        0,
                        "dummy2"
                    )
                    .unwrap_err()
            ),
            "no more IRQs are available".to_string()
        );
    }

    #[test]
    fn test_dummy_device() {
        let mut dummy = DummyDevice::new();
        assert_eq!(dummy.device_type(), 0);
        assert_eq!(dummy.get_queues().len(), QUEUE_SIZES.len());

        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem =
            GuestMemoryMmap::from_ranges(&[(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();

        // test activate
        let result = dummy.activate(guest_mem);
        assert!(result.is_ok());
    }

    #[test]
    fn test_error_messages() {
        let device_manager =
            MMIODeviceManager::new(&mut 0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));
        let mut cmdline = kernel_cmdline::Cmdline::new(4096);
        let e = Error::Cmdline(
            cmdline
                .insert(
                    "virtio_mmio=device",
                    &format!(
                        "{}K@0x{:08x}:{}",
                        MMIO_LEN / 1024,
                        device_manager.mmio_base,
                        device_manager.irq
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
        assert_eq!(
            format!(
                "{}",
                Error::CreateMmioDevice(io::Error::from_raw_os_error(0))
            ),
            format!(
                "failed to create mmio device: {}",
                io::Error::from_raw_os_error(0)
            )
        );
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
    fn test_update_drive() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem =
            GuestMemoryMmap::from_ranges(&[(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();
        let vm = builder::setup_kvm_vm(&guest_mem).unwrap();
        let mut device_manager =
            MMIODeviceManager::new(&mut 0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));
        let mut cmdline = kernel_cmdline::Cmdline::new(4096);
        let dummy = Arc::new(Mutex::new(DummyDevice::new()));

        if device_manager
            .register_virtio_device(vm.fd(), guest_mem, dummy, &mut cmdline, TYPE_BLOCK, "foo")
            .is_ok()
        {
            assert!(device_manager.update_drive("foo", 1_048_576).is_ok());
        }
        assert!(device_manager
            .update_drive("invalid_id", 1_048_576)
            .is_err());
    }

    #[test]
    fn test_device_info() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem =
            GuestMemoryMmap::from_ranges(&[(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();
        let vm = builder::setup_kvm_vm(&guest_mem).unwrap();
        let mut device_manager =
            MMIODeviceManager::new(&mut 0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));
        let mut cmdline = kernel_cmdline::Cmdline::new(4096);
        let dummy = Arc::new(Mutex::new(DummyDevice::new()));

        let type_id = 0;
        let id = String::from("foo");
        if let Ok(addr) = device_manager.register_virtio_device(
            vm.fd(),
            guest_mem,
            dummy,
            &mut cmdline,
            type_id,
            &id,
        ) {
            assert!(device_manager
                .get_device(DeviceType::Virtio(type_id), &id)
                .is_some());
            assert_eq!(
                addr,
                device_manager.id_to_dev_info[&(DeviceType::Virtio(type_id), id.clone())].addr
            );
            assert_eq!(
                arch::IRQ_BASE,
                device_manager.id_to_dev_info[&(DeviceType::Virtio(type_id), id.clone())].irq
            );
        }
        let id = "bar";
        assert!(device_manager
            .get_device(DeviceType::Virtio(type_id), &id)
            .is_none());
    }
}
