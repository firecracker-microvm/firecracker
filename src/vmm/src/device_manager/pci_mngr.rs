// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::sync::{Arc, Mutex};

use event_manager::MutEventSubscriber;
use kvm_ioctls::{IoEventAddress, NoDatamatch};
use log::debug;
use pci::{PciBarRegionType, PciDevice, PciDeviceError, PciRootError};
use serde::{Deserialize, Serialize};
use vm_device::BusError;

use crate::Vm;
use crate::device_manager::resources::ResourceAllocator;
use crate::devices::pci::PciSegment;
use crate::devices::virtio::device::VirtioDevice;
use crate::devices::virtio::transport::pci::device::{VirtioPciDevice, VirtioPciDeviceError};
use crate::vstate::vm::InterruptError;

#[derive(Debug, Default)]
pub struct PciDevices {
    /// PCIe segment of the VMM, if PCI is enabled. We currently support a single PCIe segment.
    pub pci_segment: Option<PciSegment>,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum PciManagerError {
    /// Resource allocation error: {0}
    ResourceAllocation(#[from] vm_allocator::Error),
    /// Bus error: {0}
    Bus(#[from] BusError),
    /// PCI root error: {0}
    PciRoot(#[from] PciRootError),
    /// MSI error: {0}
    Msi(#[from] InterruptError),
    /// VirtIO PCI device error: {0}
    VirtioPciDevice(#[from] VirtioPciDeviceError),
    /// PCI device error: {0}
    PciDeviceError(#[from] PciDeviceError),
    /// KVM error: {0}
    Kvm(#[from] vmm_sys_util::errno::Error),
}

impl PciDevices {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn attach_pci_segment(
        &mut self,
        resource_allocator: &Arc<ResourceAllocator>,
    ) -> Result<(), PciManagerError> {
        // We only support a single PCIe segment. Calling this function twice is a Firecracker
        // internal error.
        assert!(self.pci_segment.is_none());

        // Currently we don't assign any IRQs to PCI devices. We will be using MSI-X interrupts
        // only.
        let pci_segment = PciSegment::new(0, resource_allocator, &[0u8; 32])?;
        self.pci_segment = Some(pci_segment);

        Ok(())
    }

    pub fn save(&self) -> PciDevicesState {
        PciDevicesState {
            pci_enabled: self.pci_segment.is_some(),
        }
    }

    pub fn restore(
        &mut self,
        state: &PciDevicesState,
        resource_allocator: &Arc<ResourceAllocator>,
    ) -> Result<(), PciManagerError> {
        if state.pci_enabled {
            self.attach_pci_segment(resource_allocator)?;
        }

        Ok(())
    }

    pub(crate) fn attach_pci_virtio_device<
        T: 'static + VirtioDevice + MutEventSubscriber + Debug,
    >(
        &mut self,
        vm: &Arc<Vm>,
        resource_allocator: &ResourceAllocator,
        id: String,
        device: Arc<Mutex<T>>,
    ) -> Result<(), PciManagerError> {
        // We should only be reaching this point if PCI is enabled
        let pci_segment = self.pci_segment.as_ref().unwrap();
        let pci_device_bdf = pci_segment.next_device_bdf()?;
        debug!("Allocating BDF: {pci_device_bdf:?} for device");
        let mem = vm.guest_memory().clone();

        // Allocate one MSI vector per queue, plus one for configuration
        let msix_num =
            u16::try_from(device.lock().expect("Poisoned lock").queues().len() + 1).unwrap();

        let msix_vectors = Arc::new(Vm::create_msix_group(
            vm.clone(),
            resource_allocator,
            0,
            msix_num,
        )?);

        // Create the transport
        let mut virtio_device = VirtioPciDevice::new(
            id.clone(),
            mem,
            device,
            msix_vectors,
            pci_device_bdf.into(),
            true,
            None,
        )?;

        // Allocate bars
        let mut mmio32_allocator = resource_allocator
            .mmio32_memory
            .lock()
            .expect("Poisoned lock");
        let mut mmio64_allocator = resource_allocator
            .mmio64_memory
            .lock()
            .expect("Poisoned lock");

        let bars =
            virtio_device.allocate_bars(&mut mmio32_allocator, &mut mmio64_allocator, None)?;

        let virtio_device = Arc::new(Mutex::new(virtio_device));
        pci_segment
            .pci_bus
            .lock()
            .expect("Poisoned lock")
            .add_device(pci_device_bdf.device() as u32, virtio_device.clone())?;

        for bar in &bars {
            match bar.region_type() {
                PciBarRegionType::IoRegion => {
                    #[cfg(target_arch = "x86_64")]
                    resource_allocator.pio_bus.insert(
                        virtio_device.clone(),
                        bar.addr(),
                        bar.size(),
                    )?;
                    #[cfg(target_arch = "aarch64")]
                    log::error!("pci: We do not support I/O region allocation")
                }
                PciBarRegionType::Memory32BitRegion | PciBarRegionType::Memory64BitRegion => {
                    resource_allocator.mmio_bus.insert(
                        virtio_device.clone(),
                        bar.addr(),
                        bar.size(),
                    )?;
                }
            }
        }

        let locked_device = virtio_device.lock().expect("Poisoned lock");

        let bar_addr = locked_device.config_bar_addr();
        for (i, queue_evt) in locked_device
            .virtio_device()
            .lock()
            .expect("Poisoned lock")
            .queue_events()
            .iter()
            .enumerate()
        {
            const NOTIFICATION_BAR_OFFSET: u64 = 0x6000;
            const NOTIFY_OFF_MULTIPLIER: u64 = 4;
            let notify_base = bar_addr + NOTIFICATION_BAR_OFFSET;
            let io_addr = IoEventAddress::Mmio(notify_base + i as u64 * NOTIFY_OFF_MULTIPLIER);
            vm.fd().register_ioevent(queue_evt, &io_addr, NoDatamatch)?;
        }

        Ok(())
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct PciDevicesState {
    pci_enabled: bool,
}
