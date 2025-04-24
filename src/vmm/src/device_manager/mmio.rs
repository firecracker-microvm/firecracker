// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};

#[cfg(target_arch = "x86_64")]
use acpi_tables::{Aml, aml};
use kvm_ioctls::{IoEventAddress, VmFd};
use linux_loader::cmdline as kernel_cmdline;
#[cfg(target_arch = "x86_64")]
use log::debug;
use log::info;
use serde::{Deserialize, Serialize};
use vm_allocator::AllocPolicy;

use super::resources::ResourceAllocator;
#[cfg(target_arch = "aarch64")]
use crate::devices::legacy::{RTCDevice, SerialDevice};
use crate::devices::pseudo::BootTimer;
use crate::devices::virtio::balloon::Balloon;
use crate::devices::virtio::block::device::Block;
use crate::devices::virtio::device::VirtioDevice;
use crate::devices::virtio::net::Net;
use crate::devices::virtio::rng::Entropy;
use crate::devices::virtio::transport::mmio::MmioTransport;
use crate::devices::virtio::vsock::{TYPE_VSOCK, Vsock, VsockUnixBackend};
use crate::devices::virtio::{TYPE_BALLOON, TYPE_BLOCK, TYPE_NET, TYPE_RNG};
#[cfg(target_arch = "x86_64")]
use crate::vstate::memory::GuestAddress;

/// Errors for MMIO device manager.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum MmioError {
    /// Failed to allocate requested resource: {0}
    Allocator(#[from] vm_allocator::Error),
    /// Failed to insert device on the bus: {0}
    BusInsert(#[from] vm_device::BusError),
    /// Failed to allocate requested resourc: {0}
    Cmdline(#[from] linux_loader::cmdline::Error),
    /// Failed to find the device on the bus.
    DeviceNotFound,
    /// Invalid device type found on the MMIO bus.
    InvalidDeviceType,
    /// {0}
    InternalDeviceError(String),
    /// Could not create IRQ for MMIO device: {0}
    CreateIrq(#[from] std::io::Error),
    /// Invalid MMIO IRQ configuration.
    InvalidIrqConfig,
    /// Failed to register IO event: {0}
    RegisterIoEvent(kvm_ioctls::Error),
    /// Failed to register irqfd: {0}
    RegisterIrqFd(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to create AML code for device
    AmlError(#[from] aml::AmlError),
}

/// This represents the size of the mmio device specified to the kernel through ACPI and as a
/// command line option.
/// It has to be larger than 0x100 (the offset where the configuration space starts from
/// the beginning of the memory mapped device registers) + the size of the configuration space
/// Currently hardcoded to 4K.
pub const MMIO_LEN: u64 = 0x1000;

/// Stores the address range and irq allocated to this device.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MMIODeviceInfo {
    /// Mmio address at which the device is registered.
    pub addr: u64,
    /// Mmio addr range length.
    pub len: u64,
    /// Used Irq line for the device.
    pub irq: Option<u32>,
}

#[cfg(target_arch = "x86_64")]
fn add_virtio_aml(
    dsdt_data: &mut Vec<u8>,
    addr: u64,
    len: u64,
    irq: u32,
) -> Result<(), aml::AmlError> {
    let dev_id = irq - crate::arch::GSI_BASE;
    debug!(
        "acpi: Building AML for VirtIO device _SB_.V{:03}. memory range: {:#010x}:{} irq: {}",
        dev_id, addr, len, irq
    );
    aml::Device::new(
        format!("V{:03}", dev_id).as_str().try_into()?,
        vec![
            &aml::Name::new("_HID".try_into()?, &"LNRO0005")?,
            &aml::Name::new("_UID".try_into()?, &dev_id)?,
            &aml::Name::new("_CCA".try_into()?, &aml::ONE)?,
            &aml::Name::new(
                "_CRS".try_into()?,
                &aml::ResourceTemplate::new(vec![
                    &aml::Memory32Fixed::new(
                        true,
                        addr.try_into().unwrap(),
                        len.try_into().unwrap(),
                    ),
                    &aml::Interrupt::new(true, true, false, false, irq),
                ]),
            )?,
        ],
    )
    .append_aml_bytes(dsdt_data)
}

#[derive(Debug, Clone)]
/// A descriptor for MMIO devices
pub struct MMIODevice<T> {
    /// MMIO resources allocated to the device
    pub(crate) resources: MMIODeviceInfo,
    /// The actual device
    pub(crate) inner: Arc<Mutex<T>>,
}

/// Manages the complexities of registering a MMIO device.
#[derive(Debug)]
pub struct MMIODeviceManager {
    pub(crate) bus: Arc<vm_device::Bus>,
    /// VirtIO devices using an MMIO transport layer
    pub(crate) virtio_devices: HashMap<(u32, String), MMIODevice<MmioTransport>>,
    /// Boot timer device
    pub(crate) boot_timer: Option<MMIODevice<BootTimer>>,
    #[cfg(target_arch = "aarch64")]
    /// Real-Time clock on Aarch64 platforms
    pub(crate) rtc: Option<MMIODevice<RTCDevice>>,
    #[cfg(target_arch = "aarch64")]
    /// Serial device on Aarch64 platforms
    pub(crate) serial: Option<MMIODevice<SerialDevice>>,
    #[cfg(target_arch = "x86_64")]
    // We create the AML byte code for every VirtIO device in the order we build
    // it, so that we ensure the root block device is appears first in the DSDT.
    // This is needed, so that the root device appears as `/dev/vda` in the guest
    // filesystem.
    // The alternative would be that we iterate the bus to get the data after all
    // of the devices are build. However, iterating the bus won't give us the
    // devices in the order they were added.
    pub(crate) dsdt_data: Vec<u8>,
}

impl MMIODeviceManager {
    /// Create a new DeviceManager handling mmio devices (virtio net, block).
    pub fn new() -> MMIODeviceManager {
        MMIODeviceManager {
            bus: Arc::new(vm_device::Bus::new()),
            virtio_devices: HashMap::new(),
            boot_timer: None,
            #[cfg(target_arch = "aarch64")]
            rtc: None,
            #[cfg(target_arch = "aarch64")]
            serial: None,
            #[cfg(target_arch = "x86_64")]
            dsdt_data: vec![],
        }
    }

    /// Allocates resources for a new device to be added.
    fn allocate_mmio_resources(
        &mut self,
        resource_allocator: &mut ResourceAllocator,
        irq_count: u32,
    ) -> Result<MMIODeviceInfo, MmioError> {
        let irq = match resource_allocator.allocate_gsi(irq_count)?[..] {
            [] => None,
            [irq] => Some(irq),
            _ => return Err(MmioError::InvalidIrqConfig),
        };

        let device_info = MMIODeviceInfo {
            addr: resource_allocator.allocate_mmio_memory(
                MMIO_LEN,
                MMIO_LEN,
                AllocPolicy::FirstMatch,
            )?,
            len: MMIO_LEN,
            irq,
        };
        Ok(device_info)
    }

    /// Register a virtio-over-MMIO device to be used via MMIO transport at a specific slot.
    pub fn register_mmio_virtio(
        &mut self,
        vm: &VmFd,
        device_id: String,
        mmio_device: MmioTransport,
        device_info: &MMIODeviceInfo,
    ) -> Result<(), MmioError> {
        // Our virtio devices are currently hardcoded to use a single IRQ.
        // Validate that requirement.
        let Some(irq) = device_info.irq else {
            return Err(MmioError::InvalidIrqConfig);
        };
        let identifier;
        {
            let locked_device = mmio_device.locked_device();
            identifier = (locked_device.device_type(), device_id);
            for (i, queue_evt) in locked_device.queue_events().iter().enumerate() {
                let io_addr = IoEventAddress::Mmio(
                    device_info.addr + u64::from(crate::devices::virtio::NOTIFY_REG_OFFSET),
                );
                vm.register_ioevent(queue_evt, &io_addr, u32::try_from(i).unwrap())
                    .map_err(MmioError::RegisterIoEvent)?;
            }
            vm.register_irqfd(&mmio_device.interrupt.irq_evt, irq)
                .map_err(MmioError::RegisterIrqFd)?;
        }

        let device = Arc::new(Mutex::new(mmio_device));
        self.bus
            .insert(device.clone(), device_info.addr, device_info.len)?;
        self.virtio_devices.insert(
            identifier,
            MMIODevice {
                resources: *device_info,
                inner: device,
            },
        );

        Ok(())
    }

    /// Append a registered virtio-over-MMIO device to the kernel cmdline.
    #[cfg(target_arch = "x86_64")]
    pub fn add_virtio_device_to_cmdline(
        cmdline: &mut kernel_cmdline::Cmdline,
        device_info: &MMIODeviceInfo,
    ) -> Result<(), MmioError> {
        // as per doc, [virtio_mmio.]device=<size>@<baseaddr>:<irq> needs to be appended
        // to kernel command line for virtio mmio devices to get recognized
        // the size parameter has to be transformed to KiB, so dividing hexadecimal value in
        // bytes to 1024; further, the '{}' formatting rust construct will automatically
        // transform it to decimal
        cmdline
            .add_virtio_mmio_device(
                device_info.len,
                GuestAddress(device_info.addr),
                device_info.irq.unwrap(),
                None,
            )
            .map_err(MmioError::Cmdline)
    }

    /// Allocate slot and register an already created virtio-over-MMIO device. Also Adds the device
    /// to the boot cmdline.
    pub fn register_mmio_virtio_for_boot(
        &mut self,
        vm: &VmFd,
        resource_allocator: &mut ResourceAllocator,
        device_id: String,
        mmio_device: MmioTransport,
        _cmdline: &mut kernel_cmdline::Cmdline,
    ) -> Result<MMIODeviceInfo, MmioError> {
        let device_info = self.allocate_mmio_resources(resource_allocator, 1)?;
        self.register_mmio_virtio(vm, device_id, mmio_device, &device_info)?;
        #[cfg(target_arch = "x86_64")]
        {
            Self::add_virtio_device_to_cmdline(_cmdline, &device_info)?;
            add_virtio_aml(
                &mut self.dsdt_data,
                device_info.addr,
                device_info.len,
                // We are sure that `irqs` has at least one element; allocate_mmio_resources makes
                // sure of it.
                device_info.irq.unwrap(),
            )?;
        }
        Ok(device_info)
    }

    #[cfg(target_arch = "aarch64")]
    /// Register an early console at the specified MMIO configuration if given as parameter,
    /// otherwise allocate a new MMIO resources for it.
    pub fn register_mmio_serial(
        &mut self,
        vm: &VmFd,
        resource_allocator: &mut ResourceAllocator,
        serial: Arc<Mutex<SerialDevice>>,
        device_info_opt: Option<MMIODeviceInfo>,
    ) -> Result<(), MmioError> {
        // Create a new MMIODeviceInfo object on boot path or unwrap the
        // existing object on restore path.
        let device_info = if let Some(device_info) = device_info_opt {
            device_info
        } else {
            self.allocate_mmio_resources(resource_allocator, 1)?
        };

        vm.register_irqfd(
            serial.lock().expect("Poisoned lock").serial.interrupt_evt(),
            device_info.irq.unwrap(),
        )
        .map_err(MmioError::RegisterIrqFd)?;

        self.bus
            .insert(serial.clone(), device_info.addr, device_info.len)?;
        self.serial = Some(MMIODevice {
            resources: device_info,
            inner: serial,
        });
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    /// Append the registered early console to the kernel cmdline.
    pub fn add_mmio_serial_to_cmdline(
        &self,
        cmdline: &mut kernel_cmdline::Cmdline,
    ) -> Result<(), MmioError> {
        match &self.serial {
            Some(device) => {
                cmdline.insert(
                    "earlycon",
                    &format!("uart,mmio,0x{:08x}", device.resources.addr),
                )?;
                Ok(())
            }
            None => Err(MmioError::DeviceNotFound),
        }
    }

    #[cfg(target_arch = "aarch64")]
    /// Create and register a MMIO RTC device at the specified MMIO configuration if
    /// given as parameter, otherwise allocate a new MMIO resources for it.
    pub fn register_mmio_rtc(
        &mut self,
        resource_allocator: &mut ResourceAllocator,
        rtc: RTCDevice,
        device_info_opt: Option<MMIODeviceInfo>,
    ) -> Result<(), MmioError> {
        let device = Arc::new(Mutex::new(rtc));
        // Create a new MMIODeviceInfo object on boot path or unwrap the
        // existing object on restore path.
        let device_info = if let Some(device_info) = device_info_opt {
            device_info
        } else {
            self.allocate_mmio_resources(resource_allocator, 1)?
        };

        self.bus
            .insert(device.clone(), device_info.addr, device_info.len)?;
        self.rtc = Some(MMIODevice {
            resources: device_info,
            inner: device,
        });

        Ok(())
    }

    /// Register a boot timer device.
    pub fn register_mmio_boot_timer(
        &mut self,
        resource_allocator: &mut ResourceAllocator,
        boot_timer: BootTimer,
    ) -> Result<(), MmioError> {
        // Attach a new boot timer device.
        let device_info = self.allocate_mmio_resources(resource_allocator, 0)?;

        let device = Arc::new(Mutex::new(boot_timer));
        self.bus
            .insert(device.clone(), device_info.addr, device_info.len)?;
        self.boot_timer = Some(MMIODevice {
            resources: device_info,
            inner: device,
        });
        Ok(())
    }

    /// Gets the specified device.
    pub fn get_virtio_device(
        &self,
        virtio_type: u32,
        device_id: &str,
    ) -> Option<&MMIODevice<MmioTransport>> {
        self.virtio_devices
            .get(&(virtio_type, device_id.to_string()))
    }

    /// Run fn for each registered virtio device.
    pub fn for_each_virtio_device<F, E: Debug>(&self, mut f: F) -> Result<(), E>
    where
        F: FnMut(&u32, &String, &MMIODevice<MmioTransport>) -> Result<(), E>,
    {
        for ((virtio_type, device_id), mmio_device) in &self.virtio_devices {
            f(virtio_type, device_id, mmio_device)?;
        }
        Ok(())
    }

    /// Run fn `f()` for the virtio device matching `virtio_type` and `id`.
    pub fn with_virtio_device_with_id<T, F>(
        &self,
        virtio_type: u32,
        id: &str,
        f: F,
    ) -> Result<(), MmioError>
    where
        T: VirtioDevice + 'static + Debug,
        F: FnOnce(&mut T) -> Result<(), String>,
    {
        if let Some(device) = self.get_virtio_device(virtio_type, id) {
            let virtio_device = device.inner.lock().expect("Poisoned lock").device();
            let mut dev = virtio_device.lock().expect("Poisoned lock");
            f(dev
                .as_mut_any()
                .downcast_mut::<T>()
                .ok_or(MmioError::InvalidDeviceType)?)
            .map_err(MmioError::InternalDeviceError)?;
        } else {
            return Err(MmioError::DeviceNotFound);
        }
        Ok(())
    }

    /// Artificially kick devices as if they had external events.
    pub fn kick_devices(&self) {
        info!("Artificially kick devices.");
        // We only kick virtio devices for now.
        let _: Result<(), MmioError> = self.for_each_virtio_device(|virtio_type, id, device| {
            let mmio_transport_locked = device.inner.lock().expect("Poisoned locked");
            let mut virtio = mmio_transport_locked.locked_device();
            match *virtio_type {
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
                    // We only care about kicking virtio block.
                    // If we need to kick vhost-user-block we can do nothing.
                    if let Some(block) = virtio.as_mut_any().downcast_mut::<Block>() {
                        // If device is activated, kick the block queue(s) to make up for any
                        // pending or in-flight epoll events we may have not captured in
                        // snapshot. No need to kick Ratelimiters
                        // because they are restored 'unblocked' so
                        // any inflight `timer_fd` events can be safely discarded.
                        if block.is_activated() {
                            info!("kick block {}.", id);
                            block.process_virtio_queues().unwrap();
                        }
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
                        net.process_virtio_queues().unwrap();
                    }
                }
                TYPE_VSOCK => {
                    // Vsock has complicated protocol that isn't resilient to any packet loss,
                    // so for Vsock we don't support connection persistence through snapshot.
                    // Any in-flight packets or events are simply lost.
                    // Vsock is restored 'empty'.
                    // The only reason we still `kick` it is to make guest process
                    // `TRANSPORT_RESET_EVENT` event we sent during snapshot creation.
                    let vsock = virtio
                        .as_mut_any()
                        .downcast_mut::<Vsock<VsockUnixBackend>>()
                        .unwrap();
                    if vsock.is_activated() {
                        info!("kick vsock {id}.");
                        vsock.signal_used_queue(0).unwrap();
                    }
                }
                TYPE_RNG => {
                    let entropy = virtio.as_mut_any().downcast_mut::<Entropy>().unwrap();
                    if entropy.is_activated() {
                        info!("kick entropy {id}.");
                        entropy.process_virtio_queues().unwrap();
                    }
                }
                _ => (),
            }
            Ok(())
        });
    }

    #[cfg(target_arch = "aarch64")]
    pub fn virtio_device_info(&self) -> Vec<&MMIODeviceInfo> {
        let mut device_info = Vec::new();
        for (_, dev) in self.virtio_devices.iter() {
            device_info.push(&dev.resources);
        }
        device_info
    }

    #[cfg(target_arch = "aarch64")]
    pub fn rtc_device_info(&self) -> Option<&MMIODeviceInfo> {
        self.rtc.as_ref().map(|device| &device.resources)
    }

    #[cfg(target_arch = "aarch64")]
    pub fn serial_device_info(&self) -> Option<&MMIODeviceInfo> {
        self.serial.as_ref().map(|device| &device.resources)
    }
}

#[cfg(test)]
mod tests {

    use std::ops::Deref;
    use std::sync::Arc;

    use vmm_sys_util::eventfd::EventFd;

    use super::*;
    use crate::devices::virtio::ActivateError;
    use crate::devices::virtio::device::VirtioDevice;
    use crate::devices::virtio::queue::Queue;
    use crate::devices::virtio::transport::VirtioInterrupt;
    use crate::devices::virtio::transport::mmio::IrqTrigger;
    use crate::test_utils::multi_region_mem_raw;
    use crate::vstate::kvm::Kvm;
    use crate::vstate::memory::{GuestAddress, GuestMemoryMmap};
    use crate::{Vm, arch};

    const QUEUE_SIZES: &[u16] = &[64];

    impl MMIODeviceManager {
        fn register_virtio_test_device(
            &mut self,
            vm: &VmFd,
            guest_mem: GuestMemoryMmap,
            resource_allocator: &mut ResourceAllocator,
            device: Arc<Mutex<dyn VirtioDevice>>,
            cmdline: &mut kernel_cmdline::Cmdline,
            dev_id: &str,
        ) -> Result<u64, MmioError> {
            let interrupt = Arc::new(IrqTrigger::new());
            let mmio_device = MmioTransport::new(guest_mem, interrupt, device, false);
            let device_info = self.register_mmio_virtio_for_boot(
                vm,
                resource_allocator,
                dev_id.to_string(),
                mmio_device,
                cmdline,
            )?;
            Ok(device_info.addr)
        }

        #[cfg(target_arch = "x86_64")]
        /// Gets the number of interrupts used by the devices registered.
        pub fn used_irqs_count(&self) -> usize {
            self.virtio_devices
                .iter()
                .filter(|(_, mmio_dev)| mmio_dev.resources.irq.is_some())
                .count()
        }
    }

    #[allow(dead_code)]
    #[derive(Debug)]
    struct DummyDevice {
        dummy: u32,
        queues: Vec<Queue>,
        queue_evts: [EventFd; 1],
        interrupt_trigger: Option<Arc<IrqTrigger>>,
    }

    impl DummyDevice {
        pub fn new() -> Self {
            DummyDevice {
                dummy: 0,
                queues: QUEUE_SIZES.iter().map(|&s| Queue::new(s)).collect(),
                queue_evts: [EventFd::new(libc::EFD_NONBLOCK).expect("cannot create eventFD")],
                interrupt_trigger: None,
            }
        }
    }

    impl VirtioDevice for DummyDevice {
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

        fn interrupt_trigger(&self) -> &dyn VirtioInterrupt {
            self.interrupt_trigger.as_ref().unwrap().deref()
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

        fn activate(
            &mut self,
            _: GuestMemoryMmap,
            _: Arc<dyn VirtioInterrupt>,
        ) -> Result<(), ActivateError> {
            Ok(())
        }

        fn is_activated(&self) -> bool {
            false
        }
    }

    #[test]
    #[cfg_attr(target_arch = "x86_64", allow(unused_mut))]
    fn test_register_virtio_device() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem = multi_region_mem_raw(&[(start_addr1, 0x1000), (start_addr2, 0x1000)]);
        let kvm = Kvm::new(vec![]).expect("Cannot create Kvm");
        let mut vm = Vm::new(&kvm).unwrap();
        vm.register_memory_regions(guest_mem).unwrap();
        let mut device_manager = MMIODeviceManager::new();
        let mut resource_allocator = ResourceAllocator::new().unwrap();

        let mut cmdline = kernel_cmdline::Cmdline::new(4096).unwrap();
        let dummy = Arc::new(Mutex::new(DummyDevice::new()));
        #[cfg(target_arch = "x86_64")]
        vm.setup_irqchip().unwrap();
        #[cfg(target_arch = "aarch64")]
        vm.setup_irqchip(1).unwrap();

        device_manager
            .register_virtio_test_device(
                vm.fd(),
                vm.guest_memory().clone(),
                &mut resource_allocator,
                dummy,
                &mut cmdline,
                "dummy",
            )
            .unwrap();

        assert!(device_manager.get_virtio_device(0, "foo").is_none());
        let dev = device_manager.get_virtio_device(0, "dummy").unwrap();
        assert_eq!(dev.resources.addr, arch::MMIO_MEM_START);
        assert_eq!(dev.resources.len, MMIO_LEN);
        assert_eq!(
            dev.resources.irq,
            Some(arch::GSI_BASE)
        );

        device_manager
            .for_each_virtio_device(|virtio_type, device_id, mmio_device| {
                assert_eq!(*virtio_type, 0);
                assert_eq!(device_id, "dummy");
                assert_eq!(mmio_device.resources.addr, arch::MMIO_MEM_START);
                assert_eq!(mmio_device.resources.len, MMIO_LEN);
                assert_eq!(
                    mmio_device.resources.irq,
                    Some(arch::GSI_BASE)
                );
                Ok::<(), ()>(())
            })
            .unwrap();
    }

    #[test]
    #[cfg_attr(target_arch = "x86_64", allow(unused_mut))]
    fn test_register_too_many_devices() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem = multi_region_mem_raw(&[(start_addr1, 0x1000), (start_addr2, 0x1000)]);
        let kvm = Kvm::new(vec![]).expect("Cannot create Kvm");
        let mut vm = Vm::new(&kvm).unwrap();
        vm.register_memory_regions(guest_mem).unwrap();
        let mut device_manager = MMIODeviceManager::new();
        let mut resource_allocator = ResourceAllocator::new().unwrap();

        let mut cmdline = kernel_cmdline::Cmdline::new(4096).unwrap();
        #[cfg(target_arch = "x86_64")]
        vm.setup_irqchip().unwrap();
        #[cfg(target_arch = "aarch64")]
        vm.setup_irqchip(1).unwrap();

        for _i in crate::arch::GSI_BASE..=crate::arch::GSI_MAX {
            device_manager
                .register_virtio_test_device(
                    vm.fd(),
                    vm.guest_memory().clone(),
                    &mut resource_allocator,
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
                        vm.guest_memory().clone(),
                        &mut resource_allocator,
                        Arc::new(Mutex::new(DummyDevice::new())),
                        &mut cmdline,
                        "dummy2"
                    )
                    .unwrap_err()
            ),
            "Failed to allocate requested resource: The requested resource is not available."
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
    #[cfg_attr(target_arch = "x86_64", allow(unused_mut))]
    fn test_device_info() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem = multi_region_mem_raw(&[(start_addr1, 0x1000), (start_addr2, 0x1000)]);
        let kvm = Kvm::new(vec![]).expect("Cannot create Kvm");
        let mut vm = Vm::new(&kvm).unwrap();
        vm.register_memory_regions(guest_mem).unwrap();

        #[cfg(target_arch = "x86_64")]
        vm.setup_irqchip().unwrap();
        #[cfg(target_arch = "aarch64")]
        vm.setup_irqchip(1).unwrap();

        let mut device_manager = MMIODeviceManager::new();
        let mut resource_allocator = ResourceAllocator::new().unwrap();
        let mut cmdline = kernel_cmdline::Cmdline::new(4096).unwrap();
        let dummy = Arc::new(Mutex::new(DummyDevice::new()));

        let type_id = dummy.lock().unwrap().device_type();
        let id = String::from("foo");
        let addr = device_manager
            .register_virtio_test_device(
                vm.fd(),
                vm.guest_memory().clone(),
                &mut resource_allocator,
                dummy,
                &mut cmdline,
                &id,
            )
            .unwrap();
        assert!(device_manager.get_virtio_device(type_id, &id).is_some());
        assert_eq!(
            addr,
            device_manager.virtio_devices[&(type_id, id.clone())]
                .resources
                .addr
        );
        assert_eq!(
            crate::arch::GSI_BASE,
            device_manager.virtio_devices[&(type_id, id)]
                .resources
                .irq
                .unwrap()
        );

        let id = "bar";
        assert!(device_manager.get_virtio_device(type_id, id).is_none());

        let dummy2 = Arc::new(Mutex::new(DummyDevice::new()));
        let id2 = String::from("foo2");
        device_manager
            .register_virtio_test_device(
                vm.fd(),
                vm.guest_memory().clone(),
                &mut resource_allocator,
                dummy2,
                &mut cmdline,
                &id2,
            )
            .unwrap();

        let mut count = 0;
        let _: Result<(), MmioError> =
            device_manager.for_each_virtio_device(|devtype, devid, _| {
                assert_eq!(*devtype, type_id);
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
    fn test_no_irq_allocation() {
        let mut device_manager = MMIODeviceManager::new();
        let mut resource_allocator = ResourceAllocator::new().unwrap();

        let device_info = device_manager
            .allocate_mmio_resources(&mut resource_allocator, 0)
            .unwrap();
        assert!(device_info.irq.is_none());
    }

    #[test]
    fn test_irq_allocation() {
        let mut device_manager = MMIODeviceManager::new();
        let mut resource_allocator = ResourceAllocator::new().unwrap();

        let device_info = device_manager
            .allocate_mmio_resources(&mut resource_allocator, 1)
            .unwrap();
        assert_eq!(device_info.irq.unwrap(), crate::arch::GSI_BASE);
    }

    #[test]
    fn test_allocation_failure() {
        let mut device_manager = MMIODeviceManager::new();
        let mut resource_allocator = ResourceAllocator::new().unwrap();
        assert_eq!(
            format!(
                "{}",
                device_manager
                    .allocate_mmio_resources(&mut resource_allocator, 2)
                    .unwrap_err()
            ),
            "Invalid MMIO IRQ configuration.".to_string()
        );
    }
}
