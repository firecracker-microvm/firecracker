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
use kvm_ioctls::IoEventAddress;
use linux_loader::cmdline as kernel_cmdline;
#[cfg(target_arch = "x86_64")]
use log::debug;
use serde::{Deserialize, Serialize};
use vm_allocator::AllocPolicy;

use crate::Vm;
use crate::arch::BOOT_DEVICE_MEM_START;
#[cfg(target_arch = "aarch64")]
use crate::arch::{RTC_MEM_START, SERIAL_MEM_START};
#[cfg(target_arch = "aarch64")]
use crate::devices::legacy::{RTCDevice, SerialDevice};
use crate::devices::pseudo::BootTimer;
use crate::devices::virtio::device::VirtioDevice;
use crate::devices::virtio::transport::mmio::MmioTransport;
#[cfg(target_arch = "x86_64")]
use crate::vstate::memory::GuestAddress;
use crate::vstate::resources::ResourceAllocator;

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
    /// Used GSI (interrupt line) for the device.
    pub gsi: Option<u32>,
}

#[cfg(target_arch = "x86_64")]
fn add_virtio_aml(
    dsdt_data: &mut Vec<u8>,
    addr: u64,
    len: u64,
    gsi: u32,
) -> Result<(), aml::AmlError> {
    let dev_id = gsi - crate::arch::GSI_LEGACY_START;
    debug!(
        "acpi: Building AML for VirtIO device _SB_.V{:03}. memory range: {:#010x}:{} gsi: {}",
        dev_id, addr, len, gsi
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
                    &aml::Interrupt::new(true, true, false, false, gsi),
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
#[derive(Debug, Default)]
pub struct MMIODeviceManager {
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
        Default::default()
    }

    /// Allocates resources for a new device to be added.
    fn allocate_mmio_resources(
        &mut self,
        resource_allocator: &mut ResourceAllocator,
        irq_count: u32,
    ) -> Result<MMIODeviceInfo, MmioError> {
        let gsi = match resource_allocator.allocate_gsi_legacy(irq_count)?[..] {
            [] => None,
            [gsi] => Some(gsi),
            _ => return Err(MmioError::InvalidIrqConfig),
        };

        let device_info = MMIODeviceInfo {
            addr: resource_allocator.allocate_32bit_mmio_memory(
                MMIO_LEN,
                MMIO_LEN,
                AllocPolicy::FirstMatch,
            )?,
            len: MMIO_LEN,
            gsi,
        };
        Ok(device_info)
    }

    /// Register a virtio-over-MMIO device to be used via MMIO transport at a specific slot.
    pub fn register_mmio_virtio(
        &mut self,
        vm: &Vm,
        device_id: String,
        device: MMIODevice<MmioTransport>,
    ) -> Result<(), MmioError> {
        // Our virtio devices are currently hardcoded to use a single IRQ.
        // Validate that requirement.
        let gsi = device.resources.gsi.ok_or(MmioError::InvalidIrqConfig)?;
        let identifier;
        {
            let mmio_device = device.inner.lock().expect("Poisoned lock");
            let locked_device = mmio_device.locked_device();
            identifier = (locked_device.device_type(), device_id);
            for (i, queue_evt) in locked_device.queue_events().iter().enumerate() {
                let io_addr = IoEventAddress::Mmio(
                    device.resources.addr + u64::from(crate::devices::virtio::NOTIFY_REG_OFFSET),
                );
                vm.fd()
                    .register_ioevent(queue_evt, &io_addr, u32::try_from(i).unwrap())
                    .map_err(MmioError::RegisterIoEvent)?;
            }
            vm.register_irq(&mmio_device.interrupt.irq_evt, gsi)
                .map_err(MmioError::RegisterIrqFd)?;
        }

        vm.common.mmio_bus.insert(
            device.inner.clone(),
            device.resources.addr,
            device.resources.len,
        )?;
        self.virtio_devices.insert(identifier, device);

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
                device_info.gsi.unwrap(),
                None,
            )
            .map_err(MmioError::Cmdline)
    }

    /// Allocate slot and register an already created virtio-over-MMIO device. Also Adds the device
    /// to the boot cmdline.
    pub fn register_mmio_virtio_for_boot(
        &mut self,
        vm: &Vm,
        device_id: String,
        mmio_device: MmioTransport,
        _cmdline: &mut kernel_cmdline::Cmdline,
    ) -> Result<(), MmioError> {
        let device = MMIODevice {
            resources: self.allocate_mmio_resources(&mut vm.resource_allocator(), 1)?,
            inner: Arc::new(Mutex::new(mmio_device)),
        };

        #[cfg(target_arch = "x86_64")]
        {
            Self::add_virtio_device_to_cmdline(_cmdline, &device.resources)?;
            add_virtio_aml(
                &mut self.dsdt_data,
                device.resources.addr,
                device.resources.len,
                // We are sure that `irqs` has at least one element; allocate_mmio_resources makes
                // sure of it.
                device.resources.gsi.unwrap(),
            )?;
        }
        self.register_mmio_virtio(vm, device_id, device)?;
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    /// Register an early console at the specified MMIO configuration if given as parameter,
    /// otherwise allocate a new MMIO resources for it.
    pub fn register_mmio_serial(
        &mut self,
        vm: &Vm,
        serial: Arc<Mutex<SerialDevice>>,
        device_info_opt: Option<MMIODeviceInfo>,
    ) -> Result<(), MmioError> {
        // Create a new MMIODeviceInfo object on boot path or unwrap the
        // existing object on restore path.
        let device_info = if let Some(device_info) = device_info_opt {
            device_info
        } else {
            let gsi = vm.resource_allocator().allocate_gsi_legacy(1)?;
            MMIODeviceInfo {
                addr: SERIAL_MEM_START,
                len: MMIO_LEN,
                gsi: Some(gsi[0]),
            }
        };

        vm.register_irq(
            serial.lock().expect("Poisoned lock").serial.interrupt_evt(),
            device_info.gsi.unwrap(),
        )
        .map_err(MmioError::RegisterIrqFd)?;

        let device = MMIODevice {
            resources: device_info,
            inner: serial,
        };

        vm.common.mmio_bus.insert(
            device.inner.clone(),
            device.resources.addr,
            device.resources.len,
        )?;

        self.serial = Some(device);
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    /// Append the registered early console to the kernel cmdline.
    ///
    /// This assumes that the device has been registered with the device manager.
    pub fn add_mmio_serial_to_cmdline(
        &self,
        cmdline: &mut kernel_cmdline::Cmdline,
    ) -> Result<(), MmioError> {
        let device = self.serial.as_ref().unwrap();
        cmdline.insert(
            "earlycon",
            &format!("uart,mmio,0x{:08x}", device.resources.addr),
        )?;
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    /// Create and register a MMIO RTC device at the specified MMIO configuration if
    /// given as parameter, otherwise allocate a new MMIO resources for it.
    pub fn register_mmio_rtc(
        &mut self,
        vm: &Vm,
        rtc: Arc<Mutex<RTCDevice>>,
        device_info_opt: Option<MMIODeviceInfo>,
    ) -> Result<(), MmioError> {
        // Create a new MMIODeviceInfo object on boot path or unwrap the
        // existing object on restore path.
        let device_info = if let Some(device_info) = device_info_opt {
            device_info
        } else {
            let gsi = vm.resource_allocator().allocate_gsi_legacy(1)?;
            MMIODeviceInfo {
                addr: RTC_MEM_START,
                len: MMIO_LEN,
                gsi: Some(gsi[0]),
            }
        };

        let device = MMIODevice {
            resources: device_info,
            inner: rtc,
        };

        vm.common.mmio_bus.insert(
            device.inner.clone(),
            device.resources.addr,
            device.resources.len,
        )?;
        self.rtc = Some(device);
        Ok(())
    }

    /// Register a boot timer device.
    pub fn register_mmio_boot_timer(
        &mut self,
        mmio_bus: &vm_device::Bus,
        boot_timer: Arc<Mutex<BootTimer>>,
    ) -> Result<(), MmioError> {
        // Attach a new boot timer device.
        let device_info = MMIODeviceInfo {
            addr: BOOT_DEVICE_MEM_START,
            len: MMIO_LEN,
            gsi: None,
        };

        let device = MMIODevice {
            resources: device_info,
            inner: boot_timer,
        };

        mmio_bus.insert(
            device.inner.clone(),
            device.resources.addr,
            device.resources.len,
        )?;
        self.boot_timer = Some(device);

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
pub(crate) mod tests {

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
    use crate::{Vm, arch, impl_device_type};

    const QUEUE_SIZES: &[u16] = &[64];

    impl MMIODeviceManager {
        pub(crate) fn register_virtio_test_device(
            &mut self,
            vm: &Vm,
            guest_mem: GuestMemoryMmap,
            device: Arc<Mutex<dyn VirtioDevice>>,
            cmdline: &mut kernel_cmdline::Cmdline,
            dev_id: &str,
        ) -> Result<u64, MmioError> {
            let interrupt = Arc::new(IrqTrigger::new());
            let mmio_device = MmioTransport::new(guest_mem, interrupt, device.clone(), false);
            self.register_mmio_virtio_for_boot(vm, dev_id.to_string(), mmio_device, cmdline)?;
            Ok(self
                .get_virtio_device(device.lock().unwrap().device_type(), dev_id)
                .unwrap()
                .resources
                .addr)
        }

        #[cfg(target_arch = "x86_64")]
        /// Gets the number of interrupts used by the devices registered.
        pub fn used_irqs_count(&self) -> usize {
            self.virtio_devices
                .iter()
                .filter(|(_, mmio_dev)| mmio_dev.resources.gsi.is_some())
                .count()
        }
    }

    #[allow(dead_code)]
    #[derive(Debug)]
    pub(crate) struct DummyDevice {
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
        impl_device_type!(0);

        fn avail_features(&self) -> u64 {
            0
        }

        fn acked_features(&self) -> u64 {
            0
        }

        fn set_acked_features(&mut self, _: u64) {}

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

        let mut cmdline = kernel_cmdline::Cmdline::new(4096).unwrap();
        let dummy = Arc::new(Mutex::new(DummyDevice::new()));
        #[cfg(target_arch = "x86_64")]
        vm.setup_irqchip().unwrap();
        #[cfg(target_arch = "aarch64")]
        vm.setup_irqchip(1).unwrap();

        device_manager
            .register_virtio_test_device(
                &vm,
                vm.guest_memory().clone(),
                dummy,
                &mut cmdline,
                "dummy",
            )
            .unwrap();

        assert!(device_manager.get_virtio_device(0, "foo").is_none());
        let dev = device_manager.get_virtio_device(0, "dummy").unwrap();
        assert_eq!(dev.resources.addr, arch::MEM_32BIT_DEVICES_START);
        assert_eq!(dev.resources.len, MMIO_LEN);
        assert_eq!(dev.resources.gsi, Some(arch::GSI_LEGACY_START));

        device_manager
            .for_each_virtio_device(|virtio_type, device_id, mmio_device| {
                assert_eq!(*virtio_type, 0);
                assert_eq!(device_id, "dummy");
                assert_eq!(mmio_device.resources.addr, arch::MEM_32BIT_DEVICES_START);
                assert_eq!(mmio_device.resources.len, MMIO_LEN);
                assert_eq!(mmio_device.resources.gsi, Some(arch::GSI_LEGACY_START));
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

        let mut cmdline = kernel_cmdline::Cmdline::new(4096).unwrap();
        #[cfg(target_arch = "x86_64")]
        vm.setup_irqchip().unwrap();
        #[cfg(target_arch = "aarch64")]
        vm.setup_irqchip(1).unwrap();

        for _i in crate::arch::GSI_LEGACY_START..=crate::arch::GSI_LEGACY_END {
            device_manager
                .register_virtio_test_device(
                    &vm,
                    vm.guest_memory().clone(),
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
                        &vm,
                        vm.guest_memory().clone(),
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
        let mut cmdline = kernel_cmdline::Cmdline::new(4096).unwrap();
        let dummy = Arc::new(Mutex::new(DummyDevice::new()));

        let type_id = dummy.lock().unwrap().device_type();
        let id = String::from("foo");
        let addr = device_manager
            .register_virtio_test_device(&vm, vm.guest_memory().clone(), dummy, &mut cmdline, &id)
            .unwrap();
        assert!(device_manager.get_virtio_device(type_id, &id).is_some());
        assert_eq!(
            addr,
            device_manager.virtio_devices[&(type_id, id.clone())]
                .resources
                .addr
        );
        assert_eq!(
            crate::arch::GSI_LEGACY_START,
            device_manager.virtio_devices[&(type_id, id)]
                .resources
                .gsi
                .unwrap()
        );

        let id = "bar";
        assert!(device_manager.get_virtio_device(type_id, id).is_none());

        let dummy2 = Arc::new(Mutex::new(DummyDevice::new()));
        let id2 = String::from("foo2");
        device_manager
            .register_virtio_test_device(&vm, vm.guest_memory().clone(), dummy2, &mut cmdline, &id2)
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
        let mut resource_allocator = ResourceAllocator::new();

        let device_info = device_manager
            .allocate_mmio_resources(&mut resource_allocator, 0)
            .unwrap();
        assert!(device_info.gsi.is_none());
    }

    #[test]
    fn test_irq_allocation() {
        let mut device_manager = MMIODeviceManager::new();
        let mut resource_allocator = ResourceAllocator::new();

        let device_info = device_manager
            .allocate_mmio_resources(&mut resource_allocator, 1)
            .unwrap();
        assert_eq!(device_info.gsi.unwrap(), crate::arch::GSI_LEGACY_START);
    }

    #[test]
    fn test_allocation_failure() {
        let mut device_manager = MMIODeviceManager::new();
        let mut resource_allocator = ResourceAllocator::new();
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
