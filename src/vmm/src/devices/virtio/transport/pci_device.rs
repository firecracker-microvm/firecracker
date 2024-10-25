// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::any::Any;
use std::cmp;
use std::fmt::{Debug, Formatter};
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};

use anyhow::anyhow;
use pci::{
    BarReprogrammingParams, MsixCap, MsixConfig, PciBarConfiguration, PciBarRegionType,
    PciCapability, PciCapabilityId, PciClassCode, PciConfiguration, PciDevice, PciDeviceError,
    PciHeaderType, PciMassStorageSubclass, PciNetworkControllerSubclass, PciSubclass,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use crate::devices::virtio::device::{VirtioDevice, VirtioInterrupt, VirtioInterruptType};
use crate::devices::virtio::queue::Queue;
use crate::vstate::memory::GuestMemoryMmap;
use vm_system_allocator::{AddressAllocator, SystemAllocator};
use vm_device::dma_mapping::ExternalDmaMapping;
use vm_device::interrupt::{
    InterruptIndex, InterruptManager, InterruptSourceGroup, MsiIrqGroupConfig,
};
use vm_device::{PciBarType, Resource};
use vm_memory::{Address, ByteValued, GuestAddress, Le32};
use vmm_sys_util::eventfd::EventFd;

use super::pci_common_config::VirtioPciCommonConfigState;
use crate::devices::virtio::transport::VirtioPciCommonConfig;
use crate::logger::{debug, error};

const DEVICE_INIT: u32 = 0x00;
const DEVICE_ACKNOWLEDGE: u32 = 0x01;
const DEVICE_DRIVER: u32 = 0x02;
const DEVICE_DRIVER_OK: u32 = 0x04;
const DEVICE_FEATURES_OK: u32 = 0x08;
const DEVICE_FAILED: u32 = 0x80;

const VIRTIO_F_RING_INDIRECT_DESC: u32 = 28;
const VIRTIO_F_RING_EVENT_IDX: u32 = 29;
const VIRTIO_F_VERSION_1: u32 = 32;
const VIRTIO_F_IOMMU_PLATFORM: u32 = 33;
const VIRTIO_F_IN_ORDER: u32 = 35;
const VIRTIO_F_ORDER_PLATFORM: u32 = 36;
#[allow(dead_code)]
const VIRTIO_F_SR_IOV: u32 = 37;
const VIRTIO_F_NOTIFICATION_DATA: u32 = 38;

/// Vector value used to disable MSI for a queue.
const VIRTQ_MSI_NO_VECTOR: u16 = 0xffff;

enum PciCapabilityType {
    Common = 1,
    Notify = 2,
    Isr = 3,
    Device = 4,
    Pci = 5,
    SharedMemory = 8,
}

// This offset represents the 2 bytes omitted from the VirtioPciCap structure
// as they are already handled through add_capability(). These 2 bytes are the
// fields cap_vndr (1 byte) and cap_next (1 byte) defined in the virtio spec.
const VIRTIO_PCI_CAP_OFFSET: usize = 2;

#[allow(dead_code)]
#[repr(packed)]
#[derive(Clone, Copy, Default)]
struct VirtioPciCap {
    cap_len: u8,      // Generic PCI field: capability length
    cfg_type: u8,     // Identifies the structure.
    pci_bar: u8,      // Where to find it.
    id: u8,           // Multiple capabilities of the same type
    padding: [u8; 2], // Pad to full dword.
    offset: Le32,     // Offset within bar.
    length: Le32,     // Length of the structure, in bytes.
}
// SAFETY: All members are simple numbers and any value is valid.
unsafe impl ByteValued for VirtioPciCap {}

impl PciCapability for VirtioPciCap {
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }

    fn id(&self) -> PciCapabilityId {
        PciCapabilityId::VendorSpecific
    }
}

const VIRTIO_PCI_CAP_LEN_OFFSET: u8 = 2;

impl VirtioPciCap {
    pub fn new(cfg_type: PciCapabilityType, pci_bar: u8, offset: u32, length: u32) -> Self {
        VirtioPciCap {
            cap_len: (std::mem::size_of::<VirtioPciCap>() as u8) + VIRTIO_PCI_CAP_LEN_OFFSET,
            cfg_type: cfg_type as u8,
            pci_bar,
            id: 0,
            padding: [0; 2],
            offset: Le32::from(offset),
            length: Le32::from(length),
        }
    }
}

#[allow(dead_code)]
#[repr(packed)]
#[derive(Clone, Copy, Default)]
struct VirtioPciNotifyCap {
    cap: VirtioPciCap,
    notify_off_multiplier: Le32,
}
// SAFETY: All members are simple numbers and any value is valid.
unsafe impl ByteValued for VirtioPciNotifyCap {}

impl PciCapability for VirtioPciNotifyCap {
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }

    fn id(&self) -> PciCapabilityId {
        PciCapabilityId::VendorSpecific
    }
}

impl VirtioPciNotifyCap {
    pub fn new(
        cfg_type: PciCapabilityType,
        pci_bar: u8,
        offset: u32,
        length: u32,
        multiplier: Le32,
    ) -> Self {
        VirtioPciNotifyCap {
            cap: VirtioPciCap {
                cap_len: (std::mem::size_of::<VirtioPciNotifyCap>() as u8)
                    + VIRTIO_PCI_CAP_LEN_OFFSET,
                cfg_type: cfg_type as u8,
                pci_bar,
                id: 0,
                padding: [0; 2],
                offset: Le32::from(offset),
                length: Le32::from(length),
            },
            notify_off_multiplier: multiplier,
        }
    }
}

#[allow(dead_code)]
#[repr(packed)]
#[derive(Clone, Copy, Default)]
struct VirtioPciCap64 {
    cap: VirtioPciCap,
    offset_hi: Le32,
    length_hi: Le32,
}
// SAFETY: All members are simple numbers and any value is valid.
unsafe impl ByteValued for VirtioPciCap64 {}

impl PciCapability for VirtioPciCap64 {
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }

    fn id(&self) -> PciCapabilityId {
        PciCapabilityId::VendorSpecific
    }
}

impl VirtioPciCap64 {
    pub fn new(cfg_type: PciCapabilityType, pci_bar: u8, id: u8, offset: u64, length: u64) -> Self {
        VirtioPciCap64 {
            cap: VirtioPciCap {
                cap_len: (std::mem::size_of::<VirtioPciCap64>() as u8) + VIRTIO_PCI_CAP_LEN_OFFSET,
                cfg_type: cfg_type as u8,
                pci_bar,
                id,
                padding: [0; 2],
                offset: Le32::from(offset as u32),
                length: Le32::from(length as u32),
            },
            offset_hi: Le32::from((offset >> 32) as u32),
            length_hi: Le32::from((length >> 32) as u32),
        }
    }
}

#[allow(dead_code)]
#[repr(packed)]
#[derive(Clone, Copy, Default)]
struct VirtioPciCfgCap {
    cap: VirtioPciCap,
    pci_cfg_data: [u8; 4],
}
// SAFETY: All members are simple numbers and any value is valid.
unsafe impl ByteValued for VirtioPciCfgCap {}

impl PciCapability for VirtioPciCfgCap {
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }

    fn id(&self) -> PciCapabilityId {
        PciCapabilityId::VendorSpecific
    }
}

impl VirtioPciCfgCap {
    fn new() -> Self {
        VirtioPciCfgCap {
            cap: VirtioPciCap::new(PciCapabilityType::Pci, 0, 0, 0),
            ..Default::default()
        }
    }
}

#[derive(Clone, Copy, Default)]
struct VirtioPciCfgCapInfo {
    offset: usize,
    cap: VirtioPciCfgCap,
}

#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum PciVirtioSubclass {
    NonTransitionalBase = 0xff,
}

impl PciSubclass for PciVirtioSubclass {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

// Allocate one bar for the structs pointed to by the capability structures.
// As per the PCI specification, because the same BAR shares MSI-X and non
// MSI-X structures, it is recommended to use 8KiB alignment for all those
// structures.
const COMMON_CONFIG_BAR_OFFSET: u64 = 0x0000;
const COMMON_CONFIG_SIZE: u64 = 56;
const ISR_CONFIG_BAR_OFFSET: u64 = 0x2000;
const ISR_CONFIG_SIZE: u64 = 1;
const DEVICE_CONFIG_BAR_OFFSET: u64 = 0x4000;
const DEVICE_CONFIG_SIZE: u64 = 0x1000;
const NOTIFICATION_BAR_OFFSET: u64 = 0x6000;
const NOTIFICATION_SIZE: u64 = 0x1000;
const MSIX_TABLE_BAR_OFFSET: u64 = 0x8000;
// The size is 256KiB because the table can hold up to 2048 entries, with each
// entry being 128 bits (4 DWORDS).
const MSIX_TABLE_SIZE: u64 = 0x40000;
const MSIX_PBA_BAR_OFFSET: u64 = 0x48000;
// The size is 2KiB because the Pending Bit Array has one bit per vector and it
// can support up to 2048 vectors.
const MSIX_PBA_SIZE: u64 = 0x800;
// The BAR size must be a power of 2.
const CAPABILITY_BAR_SIZE: u64 = 0x80000;
const VIRTIO_COMMON_BAR_INDEX: usize = 0;
const VIRTIO_SHM_BAR_INDEX: usize = 2;

const NOTIFY_OFF_MULTIPLIER: u32 = 4; // A dword per notification address.

const VIRTIO_PCI_VENDOR_ID: u16 = 0x1af4;
const VIRTIO_PCI_DEVICE_ID_BASE: u16 = 0x1040; // Add to device type to get device ID.

#[derive(Serialize, Deserialize)]
struct QueueState {
    max_size: u16,
    size: u16,
    ready: bool,
    desc_table: u64,
    avail_ring: u64,
    used_ring: u64,
}

#[derive(Serialize, Deserialize)]
pub struct VirtioPciDeviceState {
    device_activated: bool,
    queues: Vec<QueueState>,
    interrupt_status: usize,
    cap_pci_cfg_offset: usize,
    cap_pci_cfg: Vec<u8>,
}

#[derive(Error, Debug)]
pub enum VirtioPciDeviceError {
    #[error("Failed creating VirtioPciDevice: {0}")]
    CreateVirtioPciDevice(#[source] anyhow::Error),
}
pub type Result<T> = std::result::Result<T, VirtioPciDeviceError>;

pub struct VirtioPciDevice {
    id: String,

    // PCI configuration registers.
    configuration: PciConfiguration,

    // virtio PCI common configuration
    common_config: VirtioPciCommonConfig,

    // MSI-X config
    msix_config: Option<Arc<Mutex<MsixConfig>>>,

    // Number of MSI-X vectors
    msix_num: u16,

    // Virtio device reference and status
    device: Arc<Mutex<dyn VirtioDevice>>,
    device_activated: Arc<AtomicBool>,

    // PCI interrupts.
    interrupt_status: Arc<AtomicUsize>,
    virtio_interrupt: Option<Arc<dyn VirtioInterrupt>>,
    interrupt_source_group: Arc<dyn InterruptSourceGroup>,

    // Guest memory
    memory: GuestMemoryMmap,

    // Settings PCI BAR
    settings_bar: u8,

    // Whether to use 64-bit bar location or 32-bit
    use_64bit_bar: bool,

    // Add a dedicated structure to hold information about the very specific
    // virtio-pci capability VIRTIO_PCI_CAP_PCI_CFG. This is needed to support
    // the legacy/backward compatible mechanism of letting the guest access the
    // other virtio capabilities without mapping the PCI BARs. This can be
    // needed when the guest tries to early access the virtio configuration of
    // a device.
    cap_pci_cfg_info: VirtioPciCfgCapInfo,

    // Details of bar regions to free
    bar_regions: Vec<PciBarConfiguration>,

    // Optional DMA handler
    dma_handler: Option<Arc<dyn ExternalDmaMapping>>,
}

impl Debug for VirtioPciDevice {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.debug_struct("VirtioPciDevice")
            .field("id", &self.id)
            .finish()
    }
}

impl VirtioPciDevice {
    /// Constructs a new PCI transport for the given virtio device.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        memory: GuestMemoryMmap,
        device: Arc<Mutex<dyn VirtioDevice>>,
        msix_num: u16,
        interrupt_manager: &Arc<dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>>,
        pci_device_bdf: u32,
        use_64bit_bar: bool,
        dma_handler: Option<Arc<dyn ExternalDmaMapping>>,
    ) -> Result<Self> {
        let locked_device = device.lock().unwrap();

        let num_queues = locked_device.queues().len();

        let pci_device_id = VIRTIO_PCI_DEVICE_ID_BASE + locked_device.device_type() as u16;

        let interrupt_source_group = interrupt_manager
            .create_group(MsiIrqGroupConfig {
                base: 0,
                count: msix_num as InterruptIndex,
            })
            .map_err(|e| {
                VirtioPciDeviceError::CreateVirtioPciDevice(anyhow!(
                    "Failed creating MSI interrupt group: {}",
                    e
                ))
            })?;

        let (msix_config, msix_config_clone) = if msix_num > 0 {
            let msix_config = Arc::new(Mutex::new(
                MsixConfig::new(
                    msix_num,
                    interrupt_source_group.clone(),
                    pci_device_bdf,
                    None,
                )
                .unwrap(),
            ));
            let msix_config_clone = msix_config.clone();
            (Some(msix_config), Some(msix_config_clone))
        } else {
            (None, None)
        };

        let (class, subclass) = match locked_device.device_type() {
            TYPE_NET  => (
                PciClassCode::NetworkController,
                &PciNetworkControllerSubclass::EthernetController as &dyn PciSubclass,
            ),
            TYPE_BLOCK => (
                PciClassCode::MassStorage,
                &PciMassStorageSubclass::MassStorage as &dyn PciSubclass,
            ),
            _ => (
                PciClassCode::Other,
                &PciVirtioSubclass::NonTransitionalBase as &dyn PciSubclass,
            ),
        };

        let configuration = PciConfiguration::new(
            VIRTIO_PCI_VENDOR_ID,
            pci_device_id,
            0x1, // For modern virtio-PCI devices
            class,
            subclass,
            None,
            PciHeaderType::Device,
            VIRTIO_PCI_VENDOR_ID,
            pci_device_id,
            msix_config_clone,
            None,
        );

        let common_config = VirtioPciCommonConfig::new(
            VirtioPciCommonConfigState {
                driver_status: 0,
                config_generation: 0,
                device_feature_select: 0,
                driver_feature_select: 0,
                queue_select: 0,
                msix_config: VIRTQ_MSI_NO_VECTOR,
                msix_queues: vec![VIRTQ_MSI_NO_VECTOR; num_queues],
            },
        );
        let (device_activated, interrupt_status, cap_pci_cfg_info) = (false, 0, VirtioPciCfgCapInfo::default());

        // Dropping the MutexGuard to unlock the VirtioDevice. This is required
        // in the context of a restore given the device might require some
        // activation, meaning it will require locking. Dropping the lock
        // prevents from a subtle deadlock.
        std::mem::drop(locked_device);

        let mut virtio_pci_device = VirtioPciDevice {
            id,
            configuration,
            common_config,
            msix_config,
            msix_num,
            device,
            device_activated: Arc::new(AtomicBool::new(device_activated)),
            interrupt_status: Arc::new(AtomicUsize::new(interrupt_status)),
            virtio_interrupt: None,
            memory,
            settings_bar: 0,
            use_64bit_bar,
            interrupt_source_group,
            cap_pci_cfg_info,
            bar_regions: vec![],
            dma_handler,
        };

        if let Some(msix_config) = &virtio_pci_device.msix_config {
            virtio_pci_device.virtio_interrupt = Some(Arc::new(VirtioInterruptMsix::new(
                msix_config.clone(),
                virtio_pci_device.common_config.msix_config.clone(),
                virtio_pci_device.common_config.msix_queues.clone(),
                virtio_pci_device.interrupt_source_group.clone(),
            )));
        }

        Ok(virtio_pci_device)
    }

    fn is_driver_ready(&self) -> bool {
        let ready_bits =
            (DEVICE_ACKNOWLEDGE | DEVICE_DRIVER | DEVICE_DRIVER_OK | DEVICE_FEATURES_OK) as u8;
        self.common_config.driver_status == ready_bits
            && self.common_config.driver_status & DEVICE_FAILED as u8 == 0
    }

    /// Determines if the driver has requested the device (re)init / reset itself
    fn is_driver_init(&self) -> bool {
        self.common_config.driver_status == DEVICE_INIT as u8
    }

    pub fn config_bar_addr(&self) -> u64 {
        self.configuration.get_bar_addr(self.settings_bar as usize)
    }

    fn add_pci_capabilities(
        &mut self,
        settings_bar: u8,
    ) -> std::result::Result<(), PciDeviceError> {
        // Add pointers to the different configuration structures from the PCI capabilities.
        let common_cap = VirtioPciCap::new(
            PciCapabilityType::Common,
            settings_bar,
            COMMON_CONFIG_BAR_OFFSET as u32,
            COMMON_CONFIG_SIZE as u32,
        );
        self.configuration
            .add_capability(&common_cap)
            .map_err(PciDeviceError::CapabilitiesSetup)?;

        let isr_cap = VirtioPciCap::new(
            PciCapabilityType::Isr,
            settings_bar,
            ISR_CONFIG_BAR_OFFSET as u32,
            ISR_CONFIG_SIZE as u32,
        );
        self.configuration
            .add_capability(&isr_cap)
            .map_err(PciDeviceError::CapabilitiesSetup)?;

        // TODO(dgreid) - set based on device's configuration size?
        let device_cap = VirtioPciCap::new(
            PciCapabilityType::Device,
            settings_bar,
            DEVICE_CONFIG_BAR_OFFSET as u32,
            DEVICE_CONFIG_SIZE as u32,
        );
        self.configuration
            .add_capability(&device_cap)
            .map_err(PciDeviceError::CapabilitiesSetup)?;

        let notify_cap = VirtioPciNotifyCap::new(
            PciCapabilityType::Notify,
            settings_bar,
            NOTIFICATION_BAR_OFFSET as u32,
            NOTIFICATION_SIZE as u32,
            Le32::from(NOTIFY_OFF_MULTIPLIER),
        );
        self.configuration
            .add_capability(&notify_cap)
            .map_err(PciDeviceError::CapabilitiesSetup)?;

        let configuration_cap = VirtioPciCfgCap::new();
        self.cap_pci_cfg_info.offset = self
            .configuration
            .add_capability(&configuration_cap)
            .map_err(PciDeviceError::CapabilitiesSetup)?
            + VIRTIO_PCI_CAP_OFFSET;
        self.cap_pci_cfg_info.cap = configuration_cap;

        if self.msix_config.is_some() {
            let msix_cap = MsixCap::new(
                settings_bar,
                self.msix_num,
                MSIX_TABLE_BAR_OFFSET as u32,
                settings_bar,
                MSIX_PBA_BAR_OFFSET as u32,
            );
            self.configuration
                .add_capability(&msix_cap)
                .map_err(PciDeviceError::CapabilitiesSetup)?;
        }

        self.settings_bar = settings_bar;
        Ok(())
    }

    fn read_cap_pci_cfg(&mut self, offset: usize, mut data: &mut [u8]) {
        let cap_slice = self.cap_pci_cfg_info.cap.as_slice();
        let data_len = data.len();
        let cap_len = cap_slice.len();
        if offset + data_len > cap_len {
            error!("Failed to read cap_pci_cfg from config space");
            return;
        }

        if offset < std::mem::size_of::<VirtioPciCap>() {
            if let Some(end) = offset.checked_add(data_len) {
                // This write can't fail, offset and end are checked against config_len.
                data.write_all(&cap_slice[offset..cmp::min(end, cap_len)])
                    .unwrap();
            }
        } else {
            let bar_offset: u32 =
                // SAFETY: we know self.cap_pci_cfg_info.cap.cap.offset is 32bits long.
                unsafe { std::mem::transmute(self.cap_pci_cfg_info.cap.cap.offset) };
            self.read_bar(0, bar_offset as u64, data)
        }
    }

    fn write_cap_pci_cfg(&mut self, offset: usize, data: &[u8]) -> Option<Arc<Barrier>> {
        let cap_slice = self.cap_pci_cfg_info.cap.as_mut_slice();
        let data_len = data.len();
        let cap_len = cap_slice.len();
        if offset + data_len > cap_len {
            error!("Failed to write cap_pci_cfg to config space");
            return None;
        }

        if offset < std::mem::size_of::<VirtioPciCap>() {
            let (_, right) = cap_slice.split_at_mut(offset);
            right[..data_len].copy_from_slice(data);
            None
        } else {
            let bar_offset: u32 =
                // SAFETY: we know self.cap_pci_cfg_info.cap.cap.offset is 32bits long.
                unsafe { std::mem::transmute(self.cap_pci_cfg_info.cap.cap.offset) };
            self.write_bar(0, bar_offset as u64, data)
        }
    }

    pub fn virtio_device(&self) -> Arc<Mutex<dyn VirtioDevice>> {
        self.device.clone()
    }

    fn needs_activation(&self) -> bool {
        !self.device_activated.load(Ordering::SeqCst) && self.is_driver_ready()
    }

    pub fn dma_handler(&self) -> Option<&Arc<dyn ExternalDmaMapping>> {
        self.dma_handler.as_ref()
    }
}


pub struct VirtioInterruptMsix {
    msix_config: Arc<Mutex<MsixConfig>>,
    config_vector: Arc<AtomicU16>,
    queues_vectors: Arc<Mutex<Vec<u16>>>,
    interrupt_source_group: Arc<dyn InterruptSourceGroup>,
}

impl VirtioInterruptMsix {
    pub fn new(
        msix_config: Arc<Mutex<MsixConfig>>,
        config_vector: Arc<AtomicU16>,
        queues_vectors: Arc<Mutex<Vec<u16>>>,
        interrupt_source_group: Arc<dyn InterruptSourceGroup>,
    ) -> Self {
        VirtioInterruptMsix {
            msix_config,
            config_vector,
            queues_vectors,
            interrupt_source_group,
        }
    }
}


impl VirtioInterrupt for VirtioInterruptMsix {
    fn trigger(&self, int_type: VirtioInterruptType) -> std::result::Result<(), std::io::Error> {
        let vector = match int_type {
            VirtioInterruptType::Config => self.config_vector.load(Ordering::Acquire),
            VirtioInterruptType::Queue(queue_index) => {
                self.queues_vectors.lock().unwrap()[queue_index as usize]
            }
        };

        if vector == VIRTQ_MSI_NO_VECTOR {
            return Ok(());
        }

        let config = &mut self.msix_config.lock().unwrap();
        let entry = &config.table_entries[vector as usize];
        // In case the vector control register associated with the entry
        // has its first bit set, this means the vector is masked and the
        // device should not inject the interrupt.
        // Instead, the Pending Bit Array table is updated to reflect there
        // is a pending interrupt for this specific vector.
        if config.masked() || entry.masked() {
            config.set_pba_bit(vector, false);
            return Ok(());
        }

        self.interrupt_source_group
            .trigger(vector as InterruptIndex)
    }

    fn notifier(&self, int_type: VirtioInterruptType) -> Option<EventFd> {
        let vector = match int_type {
            VirtioInterruptType::Config => self.config_vector.load(Ordering::Acquire),
            VirtioInterruptType::Queue(queue_index) => {
                self.queues_vectors.lock().unwrap()[queue_index as usize]
            }
        };

        self.interrupt_source_group
            .notifier(vector as InterruptIndex)
    }
}

impl PciDevice for VirtioPciDevice {
    fn write_config_register(
        &mut self,
        reg_idx: usize,
        offset: u64,
        data: &[u8],
    ) -> Option<Arc<Barrier>> {
        // Handle the special case where the capability VIRTIO_PCI_CAP_PCI_CFG
        // is accessed. This capability has a special meaning as it allows the
        // guest to access other capabilities without mapping the PCI BAR.
        let base = reg_idx * 4;
        if base + offset as usize >= self.cap_pci_cfg_info.offset
            && base + offset as usize + data.len()
                <= self.cap_pci_cfg_info.offset + self.cap_pci_cfg_info.cap.bytes().len()
        {
            let offset = base + offset as usize - self.cap_pci_cfg_info.offset;
            self.write_cap_pci_cfg(offset, data)
        } else {
            self.configuration
                .write_config_register(reg_idx, offset, data);
            None
        }
    }

    fn read_config_register(&mut self, reg_idx: usize) -> u32 {
        // Handle the special case where the capability VIRTIO_PCI_CAP_PCI_CFG
        // is accessed. This capability has a special meaning as it allows the
        // guest to access other capabilities without mapping the PCI BAR.
        let base = reg_idx * 4;
        if base >= self.cap_pci_cfg_info.offset
            && base + 4 <= self.cap_pci_cfg_info.offset + self.cap_pci_cfg_info.cap.bytes().len()
        {
            let offset = base - self.cap_pci_cfg_info.offset;
            let mut data = [0u8; 4];
            self.read_cap_pci_cfg(offset, &mut data);
            u32::from_le_bytes(data)
        } else {
            self.configuration.read_reg(reg_idx)
        }
    }

    fn detect_bar_reprogramming(
        &mut self,
        reg_idx: usize,
        data: &[u8],
    ) -> Option<BarReprogrammingParams> {
        self.configuration.detect_bar_reprogramming(reg_idx, data)
    }

    fn allocate_bars(
        &mut self,
        _allocator: &Arc<Mutex<SystemAllocator>>,
        mmio32_allocator: &mut AddressAllocator,
        mmio64_allocator: &mut AddressAllocator,
        resources: Option<Vec<Resource>>,
    ) -> std::result::Result<Vec<PciBarConfiguration>, PciDeviceError> {
        let mut bars = Vec::new();
        let device_clone = self.device.clone();
        let device = device_clone.lock().unwrap();

        let mut settings_bar_addr = None;
        let mut use_64bit_bar = self.use_64bit_bar;
        let restoring = resources.is_some();
        if let Some(resources) = resources {
            for resource in resources {
                if let Resource::PciBar {
                    index, base, type_, ..
                } = resource
                {
                    if index == VIRTIO_COMMON_BAR_INDEX {
                        settings_bar_addr = Some(GuestAddress(base));
                        use_64bit_bar = match type_ {
                            PciBarType::Io => {
                                return Err(PciDeviceError::InvalidResource(resource))
                            }
                            PciBarType::Mmio32 => false,
                            PciBarType::Mmio64 => true,
                        };
                        break;
                    }
                }
            }
            // Error out if no resource was matching the BAR id.
            if settings_bar_addr.is_none() {
                return Err(PciDeviceError::MissingResource);
            }
        }

        // Allocate the virtio-pci capability BAR.
        // See http://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html#x1-740004
        let (virtio_pci_bar_addr, region_type) = if use_64bit_bar {
            let region_type = PciBarRegionType::Memory64BitRegion;
            let addr = mmio64_allocator
                .allocate(
                    settings_bar_addr,
                    CAPABILITY_BAR_SIZE,
                    Some(CAPABILITY_BAR_SIZE),
                )
                .ok_or(PciDeviceError::IoAllocationFailed(CAPABILITY_BAR_SIZE))?;
            (addr, region_type)
        } else {
            let region_type = PciBarRegionType::Memory32BitRegion;
            let addr = mmio32_allocator
                .allocate(
                    settings_bar_addr,
                    CAPABILITY_BAR_SIZE,
                    Some(CAPABILITY_BAR_SIZE),
                )
                .ok_or(PciDeviceError::IoAllocationFailed(CAPABILITY_BAR_SIZE))?;
            (addr, region_type)
        };

        let bar = PciBarConfiguration::default()
            .set_index(VIRTIO_COMMON_BAR_INDEX)
            .set_address(virtio_pci_bar_addr.raw_value())
            .set_size(CAPABILITY_BAR_SIZE)
            .set_region_type(region_type);

        // The creation of the PCI BAR and its associated capabilities must
        // happen only during the creation of a brand new VM. When a VM is
        // restored from a known state, the BARs are already created with the
        // right content, therefore we don't need to go through this codepath.
        if !restoring {
            self.configuration.add_pci_bar(&bar).map_err(|e| {
                PciDeviceError::IoRegistrationFailed(virtio_pci_bar_addr.raw_value(), e)
            })?;

            // Once the BARs are allocated, the capabilities can be added to the PCI configuration.
            self.add_pci_capabilities(VIRTIO_COMMON_BAR_INDEX as u8)?;
        }

        bars.push(bar);

        self.bar_regions.clone_from(&bars);

        Ok(bars)
    }

    fn free_bars(
        &mut self,
        _allocator: &mut SystemAllocator,
        mmio32_allocator: &mut AddressAllocator,
        mmio64_allocator: &mut AddressAllocator,
    ) -> std::result::Result<(), PciDeviceError> {
        for bar in self.bar_regions.drain(..) {
            match bar.region_type() {
                PciBarRegionType::Memory32BitRegion => {
                    mmio32_allocator.free(GuestAddress(bar.addr()), bar.size());
                }
                PciBarRegionType::Memory64BitRegion => {
                    mmio64_allocator.free(GuestAddress(bar.addr()), bar.size());
                }
                _ => error!("Unexpected PCI bar type"),
            }
        }
        Ok(())
    }

    fn move_bar(
        &mut self,
        old_base: u64,
        new_base: u64,
    ) -> std::result::Result<(), std::io::Error> {
        // We only update our idea of the bar in order to support free_bars() above.
        // The majority of the reallocation is done inside DeviceManager.
        for bar in self.bar_regions.iter_mut() {
            if bar.addr() == old_base {
                *bar = bar.set_address(new_base);
            }
        }

        Ok(())
    }

    fn read_bar(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        match offset {
            o if o < COMMON_CONFIG_BAR_OFFSET + COMMON_CONFIG_SIZE => self.common_config.read(
                o - COMMON_CONFIG_BAR_OFFSET,
                data,
                self.device.clone(),
            ),
            o if (ISR_CONFIG_BAR_OFFSET..ISR_CONFIG_BAR_OFFSET + ISR_CONFIG_SIZE).contains(&o) => {
                if let Some(v) = data.get_mut(0) {
                    // Reading this register resets it to 0.
                    *v = self.interrupt_status.swap(0, Ordering::AcqRel) as u8;
                }
            }
            o if (DEVICE_CONFIG_BAR_OFFSET..DEVICE_CONFIG_BAR_OFFSET + DEVICE_CONFIG_SIZE)
                .contains(&o) =>
            {
                let device = self.device.lock().unwrap();
                device.read_config(o - DEVICE_CONFIG_BAR_OFFSET, data);
            }
            o if (NOTIFICATION_BAR_OFFSET..NOTIFICATION_BAR_OFFSET + NOTIFICATION_SIZE)
                .contains(&o) =>
            {
                // Handled with ioeventfds.
            }
            o if (MSIX_TABLE_BAR_OFFSET..MSIX_TABLE_BAR_OFFSET + MSIX_TABLE_SIZE).contains(&o) => {
                if let Some(msix_config) = &self.msix_config {
                    msix_config
                        .lock()
                        .unwrap()
                        .read_table(o - MSIX_TABLE_BAR_OFFSET, data);
                }
            }
            o if (MSIX_PBA_BAR_OFFSET..MSIX_PBA_BAR_OFFSET + MSIX_PBA_SIZE).contains(&o) => {
                if let Some(msix_config) = &self.msix_config {
                    msix_config
                        .lock()
                        .unwrap()
                        .read_pba(o - MSIX_PBA_BAR_OFFSET, data);
                }
            }
            _ => (),
        }
    }

    fn write_bar(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        match offset {
            o if o < COMMON_CONFIG_BAR_OFFSET + COMMON_CONFIG_SIZE => self.common_config.write(
                o - COMMON_CONFIG_BAR_OFFSET,
                data,
                self.device.clone(),
            ),
            o if (ISR_CONFIG_BAR_OFFSET..ISR_CONFIG_BAR_OFFSET + ISR_CONFIG_SIZE).contains(&o) => {
                if let Some(v) = data.first() {
                    self.interrupt_status
                        .fetch_and(!(*v as usize), Ordering::AcqRel);
                }
            }
            o if (DEVICE_CONFIG_BAR_OFFSET..DEVICE_CONFIG_BAR_OFFSET + DEVICE_CONFIG_SIZE)
                .contains(&o) =>
            {
                let mut device = self.device.lock().unwrap();
                device.write_config(o - DEVICE_CONFIG_BAR_OFFSET, data);
            }
            o if (NOTIFICATION_BAR_OFFSET..NOTIFICATION_BAR_OFFSET + NOTIFICATION_SIZE)
                .contains(&o) =>
            {
                #[cfg(feature = "sev_snp")]
                for (_event, _addr) in self.ioeventfds(_base) {
                    if _addr == _base + offset {
                        _event.write(1).unwrap();
                    }
                }
                // Handled with ioeventfds.
                #[cfg(not(feature = "sev_snp"))]
                error!("Unexpected write to notification BAR: offset = 0x{:x}", o);

            }
            o if (MSIX_TABLE_BAR_OFFSET..MSIX_TABLE_BAR_OFFSET + MSIX_TABLE_SIZE).contains(&o) => {
                if let Some(msix_config) = &self.msix_config {
                    msix_config
                        .lock()
                        .unwrap()
                        .write_table(o - MSIX_TABLE_BAR_OFFSET, data);
                }
            }
            o if (MSIX_PBA_BAR_OFFSET..MSIX_PBA_BAR_OFFSET + MSIX_PBA_SIZE).contains(&o) => {
                if let Some(msix_config) = &self.msix_config {
                    msix_config
                        .lock()
                        .unwrap()
                        .write_pba(o - MSIX_PBA_BAR_OFFSET, data);
                }
            }
            _ => (),
        };

        // Try and activate the device if the driver status has changed
        if self.needs_activation() {
            debug!("Activating device");
            self.virtio_device().lock().unwrap().activate(self.memory.clone(), self.virtio_interrupt.as_ref().map(Arc::clone))
                .unwrap_or_else(|err| error!("Error activating device: {err:?}"));
        } else {
            debug!("Device doesn't need activation");
        }

        // Device has been reset by the driver
        if self.device_activated.load(Ordering::SeqCst) && self.is_driver_init() {
            let mut device = self.device.lock().unwrap();
            let reset_result = device.reset();
            match reset_result {
                Some((virtio_interrupt, mut _queue_evts)) => {
                    // Upon reset the device returns its interrupt EventFD
                    self.virtio_interrupt = Some(virtio_interrupt);
                    self.device_activated.store(false, Ordering::SeqCst);

                    // Reset queue readiness (changes queue_enable), queue sizes
                    // and selected_queue as per spec for reset
                    self.virtio_device().lock().unwrap().queues_mut().iter_mut().for_each(Queue::reset);
                    self.common_config.queue_select = 0;
                }
                None => {
                    error!("Attempt to reset device when not implemented in underlying device");
                    self.common_config.driver_status = DEVICE_FAILED as u8;
                }
            }
        }

        None
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }

    fn id(&self) -> Option<String> {
        Some(self.id.clone())
    }
}

impl VirtioPciDevice {
    pub fn bus_read(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        self.read_bar(base, offset, data)
    }

    pub fn bus_write(&mut self, base: u64, offset: u64, data: &[u8]) {
        self.write_bar(base, offset, data);
    }
}