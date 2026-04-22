// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::cmp;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::io::{ErrorKind, Write};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};

use kvm_ioctls::{IoEventAddress, NoDatamatch};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use vm_allocator::{AddressAllocator, AllocPolicy, RangeInclusive};
use vm_memory::{Address, ByteValued, GuestAddress, Le32};
use vmm_sys_util::errno;
use vmm_sys_util::eventfd::EventFd;
use zerocopy::IntoBytes;

use crate::devices::virtio::device::{VirtioDevice, VirtioDeviceType};
use crate::devices::virtio::generated::virtio_ids;
use crate::devices::virtio::queue::Queue;
use crate::devices::virtio::transport::pci::common_config::{
    VirtioPciCommonConfig, VirtioPciCommonConfigState,
};
use crate::devices::virtio::transport::pci::device_status::*;
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::logger::{debug, error, warn};
use crate::pci::configuration::{
    BAR0_REG_IDX, BarPrefetchable, Bars, NUM_BAR_REGS, PciCapability, PciConfiguration,
    PciConfigurationError, PciConfigurationState,
};
use crate::pci::msix::{MsixCap, MsixConfig, MsixConfigState};
use crate::pci::{
    BarReprogrammingParams, PciCapabilityId, PciClassCode, PciDevice, PciMassStorageSubclass,
    PciNetworkControllerSubclass, PciSBDF,
};
use crate::snapshot::Persist;
use crate::vstate::bus::BusDevice;
use crate::vstate::interrupts::{InterruptError, MsixVectorGroup};
use crate::vstate::memory::GuestMemoryMmap;
use crate::vstate::resources::ResourceAllocator;
use crate::vstate::vm::KvmVm;

/// Vector value used to disable MSI for a queue.
pub const VIRTQ_MSI_NO_VECTOR: u16 = 0xffff;

/// BAR index we are using for VirtIO configuration
const VIRTIO_BAR_INDEX: u8 = 0;

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
const VIRTIO_PCI_CAP_OFFSET: u16 = 2;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct VirtioPciCap {
    cap_len: u8,      // Generic PCI field: capability length
    cfg_type: u8,     // Identifies the structure.
    pci_bar: u8,      // Where to find it.
    id: u8,           // Multiple capabilities of the same type.
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
    pub fn new(cfg_type: PciCapabilityType, offset: u32, length: u32) -> Self {
        VirtioPciCap {
            cap_len: u8::try_from(std::mem::size_of::<VirtioPciCap>()).unwrap()
                + VIRTIO_PCI_CAP_LEN_OFFSET,
            cfg_type: cfg_type as u8,
            pci_bar: VIRTIO_BAR_INDEX,
            id: 0,
            padding: [0; 2],
            offset: Le32::from(offset),
            length: Le32::from(length),
        }
    }
}

#[repr(C, packed)]
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
    pub fn new(cfg_type: PciCapabilityType, offset: u32, length: u32, multiplier: Le32) -> Self {
        VirtioPciNotifyCap {
            cap: VirtioPciCap {
                cap_len: u8::try_from(std::mem::size_of::<VirtioPciNotifyCap>()).unwrap()
                    + VIRTIO_PCI_CAP_LEN_OFFSET,
                cfg_type: cfg_type as u8,
                pci_bar: VIRTIO_BAR_INDEX,
                id: 0,
                padding: [0; 2],
                offset: Le32::from(offset),
                length: Le32::from(length),
            },
            notify_off_multiplier: multiplier,
        }
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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
            cap: VirtioPciCap {
                cap_len: u8::try_from(size_of::<Self>()).unwrap() + VIRTIO_PCI_CAP_LEN_OFFSET,
                cfg_type: PciCapabilityType::Pci as u8,
                pci_bar: VIRTIO_BAR_INDEX,
                id: 0,
                padding: [0; 2],
                offset: Le32::from(0),
                length: Le32::from(0),
            },
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct VirtioPciCfgCapInfo {
    offset: u16,
    cap: VirtioPciCfgCap,
}

impl VirtioPciCfgCapInfo {
    fn in_range(&self, reg_idx: u16, offset: u8, data_len: usize) -> bool {
        let base = reg_idx * 4;
        let cap_start = self.offset;
        let cap_end = self.offset as usize + self.cap.bytes().len();
        let start = base + u16::from(offset);
        let end = (base + u16::from(offset)) as usize + data_len;
        cap_start <= start && end <= cap_end
    }
}

#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum PciVirtioSubclass {
    NonTransitionalBase = 0xff,
}

// Allocate one bar for the structs pointed to by the capability structures.
// As per the PCI specification, because the same BAR shares MSI-X and non
// MSI-X structures, it is recommended to use 8KiB alignment for all those
// structures.
const COMMON_CONFIG_BAR_OFFSET: u32 = 0x0000;
const COMMON_CONFIG_SIZE: u32 = 56;
const ISR_CONFIG_BAR_OFFSET: u32 = 0x2000;
const ISR_CONFIG_SIZE: u32 = 1;
const DEVICE_CONFIG_BAR_OFFSET: u32 = 0x4000;
const DEVICE_CONFIG_SIZE: u32 = 0x1000;
const NOTIFICATION_BAR_OFFSET: u32 = 0x6000;
const NOTIFICATION_SIZE: u32 = 0x1000;
const MSIX_TABLE_BAR_OFFSET: u32 = 0x8000;
// The size is 256KiB because the table can hold up to 2048 entries, with each
// entry being 128 bits (4 DWORDS).
const MSIX_TABLE_SIZE: u32 = 0x40000;
const MSIX_PBA_BAR_OFFSET: u32 = 0x48000;
// The size is 2KiB because the Pending Bit Array has one bit per vector and it
// can support up to 2048 vectors.
const MSIX_PBA_SIZE: u32 = 0x800;
/// The BAR size must be a power of 2.
pub const CAPABILITY_BAR_SIZE: u64 = 0x80000;

const NOTIFY_OFF_MULTIPLIER: u32 = 4; // A dword per notification address.

const VIRTIO_PCI_VENDOR_ID: u16 = 0x1af4;
const VIRTIO_PCI_DEVICE_ID_BASE: u16 = 0x1040; // Add to device type to get device ID.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtioPciDeviceState {
    pub sbdf: PciSBDF,
    pub device_activated: bool,
    pub cap_pci_cfg_offset: u16,
    pub cap_pci_cfg: Vec<u8>,
    pub pci_configuration_state: PciConfigurationState,
    pub pci_dev_state: VirtioPciCommonConfigState,
    pub msix_state: MsixConfigState,
    pub bars: Bars,
    pub msix_config_cap_offset: u16,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VirtioPciDeviceError {
    /// Error creating MSI configuration: {0}
    Msi(#[from] InterruptError),
    /// Invalid PCI configuration state: {0}
    PciConfiguration(#[from] PciConfigurationError),
}

pub struct VirtioPciDevice {
    id: String,

    // The subscriber ID returned by the EventManager
    pub sub_id: Option<event_manager::SubscriberId>,

    // SBDF assigned to the device
    pub sbdf: PciSBDF,

    // PCI configuration registers.
    configuration: PciConfiguration,
    // BARs region from configuration space handled separately
    bars: Bars,

    // virtio PCI common configuration
    common_config: VirtioPciCommonConfig,

    // Virtio device reference and status
    device: Arc<Mutex<dyn VirtioDevice>>,
    device_activated: Arc<AtomicBool>,

    // PCI interrupts.
    virtio_interrupt: Option<Arc<VirtioInterruptMsix>>,

    // Guest memory
    memory: GuestMemoryMmap,

    // Add a dedicated structure to hold information about the very specific
    // virtio-pci capability VIRTIO_PCI_CAP_PCI_CFG. This is needed to support
    // the legacy/backward compatible mechanism of letting the guest access the
    // other virtio capabilities without mapping the PCI BARs. This can be
    // needed when the guest tries to early access the virtio configuration of
    // a device.
    cap_pci_cfg_info: VirtioPciCfgCapInfo,
    msix_config_cap_offset: u16,
    msix_config: Arc<Mutex<MsixConfig>>,
}

impl Debug for VirtioPciDevice {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.debug_struct("VirtioPciDevice")
            .field("id", &self.id)
            .finish()
    }
}

impl VirtioPciDevice {
    fn pci_configuration(
        device_type: VirtioDeviceType,
        msix_config: &Arc<Mutex<MsixConfig>>,
    ) -> PciConfiguration {
        let pci_device_id = VIRTIO_PCI_DEVICE_ID_BASE + device_type as u16;
        let (class, subclass) = match device_type {
            VirtioDeviceType::Net => (
                PciClassCode::NetworkController,
                PciNetworkControllerSubclass::EthernetController as u8,
            ),
            VirtioDeviceType::Block => (
                PciClassCode::MassStorageController,
                PciMassStorageSubclass::MassStorage as u8,
            ),
            _ => (
                PciClassCode::UnassignedClass,
                PciVirtioSubclass::NonTransitionalBase as u8,
            ),
        };

        PciConfiguration::new_type0(
            VIRTIO_PCI_VENDOR_ID,
            pci_device_id,
            0x1, // For modern virtio-PCI devices
            class,
            subclass,
            VIRTIO_PCI_VENDOR_ID,
            pci_device_id,
        )
    }

    /// Allocate the PCI BAR for the VirtIO device and its associated capabilities.
    ///
    /// This must happen only during the creation of a brand new VM. When a VM is restored from a
    /// known state, the BARs are already created with the right content, therefore we don't need
    /// to go through this codepath.
    pub fn allocate_bars(&mut self, mmio64_allocator: &mut AddressAllocator) {
        let device_clone = self.device.clone();
        let device = device_clone.lock().unwrap();

        // Allocate the virtio-pci capability BAR.
        // See http://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html#x1-740004
        let virtio_pci_bar_addr = mmio64_allocator
            .allocate(
                CAPABILITY_BAR_SIZE,
                CAPABILITY_BAR_SIZE,
                AllocPolicy::FirstMatch,
            )
            .unwrap()
            .start();
        self.bars.set_bar_64(
            VIRTIO_BAR_INDEX,
            virtio_pci_bar_addr,
            CAPABILITY_BAR_SIZE,
            BarPrefetchable::No,
        );
        self.add_pci_capabilities();
    }

    /// Constructs a new PCI transport for the given virtio device.
    pub fn new(
        id: String,
        memory: GuestMemoryMmap,
        device: Arc<Mutex<dyn VirtioDevice>>,
        msix_vectors: Arc<MsixVectorGroup>,
        sbdf: PciSBDF,
    ) -> Result<Self, VirtioPciDeviceError> {
        let num_queues = device.lock().expect("Poisoned lock").queues().len();

        let msix_config = Arc::new(Mutex::new(MsixConfig::new(msix_vectors.clone(), sbdf)));
        let pci_config = Self::pci_configuration(
            device.lock().expect("Poisoned lock").device_type(),
            &msix_config,
        );

        let virtio_common_config = VirtioPciCommonConfig::new(VirtioPciCommonConfigState {
            driver_status: 0,
            config_generation: 0,
            device_feature_select: 0,
            driver_feature_select: 0,
            queue_select: 0,
            msix_config: VIRTQ_MSI_NO_VECTOR,
            msix_queues: vec![VIRTQ_MSI_NO_VECTOR; num_queues],
        });
        let interrupt = Arc::new(VirtioInterruptMsix::new(
            msix_config.clone(),
            virtio_common_config.msix_config.clone(),
            virtio_common_config.msix_queues.clone(),
            msix_vectors,
        ));

        let virtio_pci_device = VirtioPciDevice {
            id,
            sub_id: None,
            sbdf,
            configuration: pci_config,
            common_config: virtio_common_config,
            device,
            device_activated: Arc::new(AtomicBool::new(false)),
            virtio_interrupt: Some(interrupt),
            memory,
            cap_pci_cfg_info: VirtioPciCfgCapInfo::default(),
            bars: Bars::default(),
            msix_config,
            msix_config_cap_offset: 0,
        };

        Ok(virtio_pci_device)
    }

    pub fn new_from_state(
        id: String,
        vm: &Arc<KvmVm>,
        device: Arc<Mutex<dyn VirtioDevice>>,
        state: VirtioPciDeviceState,
    ) -> Result<Self, VirtioPciDeviceError> {
        let msix_config = MsixConfig::from_state(state.msix_state, vm.clone(), state.sbdf)?;
        let vectors = msix_config.vectors.clone();
        let msix_config = Arc::new(Mutex::new(msix_config));

        let pci_config = PciConfiguration::type0_from_state(state.pci_configuration_state)?;
        let virtio_common_config = VirtioPciCommonConfig::new(state.pci_dev_state);
        let cap_pci_cfg_info = VirtioPciCfgCapInfo {
            offset: state.cap_pci_cfg_offset,
            cap: *VirtioPciCfgCap::from_slice(&state.cap_pci_cfg).ok_or(
                PciConfigurationError::InvalidCapPciCfgLength(state.cap_pci_cfg.len()),
            )?,
        };

        let interrupt = Arc::new(VirtioInterruptMsix::new(
            msix_config.clone(),
            virtio_common_config.msix_config.clone(),
            virtio_common_config.msix_queues.clone(),
            vectors,
        ));

        let mut virtio_pci_device = VirtioPciDevice {
            id,
            sub_id: None,
            sbdf: state.sbdf,
            configuration: pci_config,
            common_config: virtio_common_config,
            device,
            device_activated: Arc::new(AtomicBool::new(state.device_activated)),
            virtio_interrupt: Some(interrupt),
            memory: vm.guest_memory().clone(),
            cap_pci_cfg_info,
            bars: state.bars,
            msix_config,
            msix_config_cap_offset: state.msix_config_cap_offset,
        };

        if state.device_activated {
            virtio_pci_device
                .device
                .lock()
                .expect("Poisoned lock")
                .activate(
                    virtio_pci_device.memory.clone(),
                    virtio_pci_device.virtio_interrupt.as_ref().unwrap().clone(),
                );
        }

        Ok(virtio_pci_device)
    }

    fn is_driver_ready(&self) -> bool {
        let ready_bits = (ACKNOWLEDGE | DRIVER | DRIVER_OK | FEATURES_OK);
        self.common_config.driver_status == ready_bits
    }

    /// Determines if the driver has requested the device (re)init / reset itself
    fn is_driver_init(&self) -> bool {
        self.common_config.driver_status == INIT
    }

    pub fn config_bar_addr(&self) -> u64 {
        self.bars.get_bar_addr_64(VIRTIO_BAR_INDEX)
    }

    fn add_pci_capabilities(&mut self) {
        // Add pointers to the different configuration structures from the PCI capabilities.
        let common_cap = VirtioPciCap::new(
            PciCapabilityType::Common,
            COMMON_CONFIG_BAR_OFFSET,
            COMMON_CONFIG_SIZE,
        );
        self.configuration.add_capability(&common_cap);

        let isr_cap = VirtioPciCap::new(
            PciCapabilityType::Isr,
            ISR_CONFIG_BAR_OFFSET,
            ISR_CONFIG_SIZE,
        );
        self.configuration.add_capability(&isr_cap);

        // TODO(dgreid) - set based on device's configuration size?
        let device_cap = VirtioPciCap::new(
            PciCapabilityType::Device,
            DEVICE_CONFIG_BAR_OFFSET,
            DEVICE_CONFIG_SIZE,
        );
        self.configuration.add_capability(&device_cap);

        let notify_cap = VirtioPciNotifyCap::new(
            PciCapabilityType::Notify,
            NOTIFICATION_BAR_OFFSET,
            NOTIFICATION_SIZE,
            Le32::from(NOTIFY_OFF_MULTIPLIER),
        );
        self.configuration.add_capability(&notify_cap);

        let configuration_cap = VirtioPciCfgCap::new();
        self.cap_pci_cfg_info.offset =
            u16::from(self.configuration.add_capability(&configuration_cap))
                + VIRTIO_PCI_CAP_OFFSET;
        self.cap_pci_cfg_info.cap = configuration_cap;

        if let Some(interrupt) = &self.virtio_interrupt {
            let msix_cap = MsixCap::new(
                VIRTIO_BAR_INDEX,
                interrupt
                    .msix_config
                    .lock()
                    .expect("Poisoned lock")
                    .vectors
                    .num_vectors(),
                MSIX_TABLE_BAR_OFFSET,
                VIRTIO_BAR_INDEX,
                MSIX_PBA_BAR_OFFSET,
            );
            // The whole Configuration region is 4K, so u16 can address it all
            #[allow(clippy::cast_possible_truncation)]
            let offset = self.configuration.add_capability(&msix_cap) as u16;
            self.msix_config_cap_offset = offset;
        }
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
            let bar_offset: u32 = self.cap_pci_cfg_info.cap.cap.offset.into();
            let len = u32::from(self.cap_pci_cfg_info.cap.cap.length) as usize;
            // BAR reads expect that the buffer has the exact size of the field that
            // offset is pointing to. So, do some check that the `length` has a meaningful value
            // and only use the part of the buffer we actually need.
            if len <= 4 {
                self.read_bar(0, bar_offset as u64, &mut data[..len]);
            }
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
            let bar_offset: u32 = self.cap_pci_cfg_info.cap.cap.offset.into();
            let len = u32::from(self.cap_pci_cfg_info.cap.cap.length) as usize;
            // BAR writes expect that the buffer has the exact size of the field that
            // offset is pointing to. So, do some check that the `length` has a meaningful value
            // and only use the part of the buffer we actually need.
            if len <= 4 {
                let len = len.min(data.len());
                self.write_bar(0, bar_offset as u64, &data[..len])
            } else {
                None
            }
        }
    }

    pub fn virtio_device(&self) -> Arc<Mutex<dyn VirtioDevice>> {
        self.device.clone()
    }

    fn needs_activation(&self) -> bool {
        !self.device_activated.load(Ordering::SeqCst) && self.is_driver_ready()
    }

    /// Register the IoEvent notification for a VirtIO device
    pub fn register_notification_ioevent(&self, vm: &KvmVm) -> Result<(), errno::Error> {
        let bar_addr = self.config_bar_addr();
        for (i, queue_evt) in self
            .device
            .lock()
            .expect("Poisoned lock")
            .queue_events()
            .iter()
            .enumerate()
        {
            let notify_base = bar_addr + u64::from(NOTIFICATION_BAR_OFFSET);
            let io_addr =
                IoEventAddress::Mmio(notify_base + i as u64 * u64::from(NOTIFY_OFF_MULTIPLIER));
            vm.fd().register_ioevent(queue_evt, &io_addr, NoDatamatch)?;
        }
        Ok(())
    }

    pub fn state(&self) -> VirtioPciDeviceState {
        VirtioPciDeviceState {
            sbdf: self.sbdf,
            device_activated: self.device_activated.load(Ordering::Acquire),
            cap_pci_cfg_offset: self.cap_pci_cfg_info.offset,
            cap_pci_cfg: self.cap_pci_cfg_info.cap.bytes().to_vec(),
            pci_configuration_state: self.configuration.state(),
            pci_dev_state: self.common_config.state(),
            msix_state: self
                .virtio_interrupt
                .as_ref()
                .unwrap()
                .msix_config
                .lock()
                .expect("Poisoned lock")
                .state(),
            bars: self.bars,
            msix_config_cap_offset: self.msix_config_cap_offset,
        }
    }
}

pub struct VirtioInterruptMsix {
    msix_config: Arc<Mutex<MsixConfig>>,
    config_vector: Arc<AtomicU16>,
    queues_vectors: Arc<Mutex<Vec<u16>>>,
    vectors: Arc<MsixVectorGroup>,
}

impl std::fmt::Debug for VirtioInterruptMsix {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtioInterruptMsix")
            .field("msix_config", &self.msix_config)
            .field("config_vector", &self.config_vector)
            .field("queues_vectors", &self.queues_vectors)
            .finish()
    }
}

impl VirtioInterruptMsix {
    pub fn new(
        msix_config: Arc<Mutex<MsixConfig>>,
        config_vector: Arc<AtomicU16>,
        queues_vectors: Arc<Mutex<Vec<u16>>>,
        vectors: Arc<MsixVectorGroup>,
    ) -> Self {
        VirtioInterruptMsix {
            msix_config,
            config_vector,
            queues_vectors,
            vectors,
        }
    }
}

impl VirtioInterrupt for VirtioInterruptMsix {
    fn trigger(&self, int_type: VirtioInterruptType) -> Result<(), InterruptError> {
        let vector = match int_type {
            VirtioInterruptType::Config => self.config_vector.load(Ordering::Acquire),
            VirtioInterruptType::Queue(queue_index) => *self
                .queues_vectors
                .lock()
                .unwrap()
                .get(queue_index as usize)
                .ok_or(InterruptError::InvalidVectorIndex(queue_index as usize))?,
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
        if config.masked || entry.masked() {
            config.set_pba_bit(vector, false);
            return Ok(());
        }

        self.vectors.trigger(vector as usize)
    }

    fn notifier(&self, int_type: VirtioInterruptType) -> Option<&EventFd> {
        let vector = match int_type {
            VirtioInterruptType::Config => self.config_vector.load(Ordering::Acquire),
            VirtioInterruptType::Queue(queue_index) => *self
                .queues_vectors
                .lock()
                .unwrap()
                .get(queue_index as usize)?,
        };

        self.vectors.notifier(vector as usize)
    }

    fn status(&self) -> Arc<AtomicU32> {
        Arc::new(AtomicU32::new(0))
    }

    #[cfg(test)]
    fn has_pending_interrupt(&self, interrupt_type: VirtioInterruptType) -> bool {
        false
    }

    #[cfg(test)]
    fn ack_interrupt(&self, interrupt_type: VirtioInterruptType) {
        // Do nothing here
    }
}

impl PciDevice for VirtioPciDevice {
    fn write_config_register(
        &mut self,
        reg_idx: u16,
        offset: u8,
        data: &[u8],
    ) -> Option<Arc<Barrier>> {
        let in_bars = BAR0_REG_IDX <= reg_idx && reg_idx < BAR0_REG_IDX + u16::from(NUM_BAR_REGS);
        let in_msix_cap_header = reg_idx * 4 == self.msix_config_cap_offset;
        let in_pci_cfg = self.cap_pci_cfg_info.in_range(reg_idx, offset, data.len());
        if in_bars {
            // reg_idx is in [BAR0_REG_IDX, BAR0_REG_IDX+NUM_BAR_REGS), so the difference is 0..5.
            #[allow(clippy::cast_possible_truncation)]
            let bar_idx = (reg_idx - BAR0_REG_IDX) as u8;
            self.bars.write(bar_idx, offset, data);
            None
        } else if in_msix_cap_header {
            // For the MsixCap structure, we need to capture writes to the second 2 bytes
            // of the capability header where Function Mask and MSI-X Enable bits are present.
            // Everything else can be served from `self.configuration`.
            self.msix_config
                .lock()
                .unwrap()
                .write_msg_ctl_register(offset, data);
            self.configuration
                .write_config_register(reg_idx, offset, data);
            None
        } else if in_pci_cfg {
            let offset = (reg_idx * 4 + u16::from(offset) - self.cap_pci_cfg_info.offset) as usize;
            self.write_cap_pci_cfg(offset, data)
        } else {
            self.configuration
                .write_config_register(reg_idx, offset, data);
            None
        }
    }

    fn read_config_register(&mut self, reg_idx: u16) -> u32 {
        let in_bars = BAR0_REG_IDX <= reg_idx && reg_idx < BAR0_REG_IDX + u16::from(NUM_BAR_REGS);
        let in_pci_cfg = self.cap_pci_cfg_info.in_range(reg_idx, 0, 4);

        if in_bars {
            // reg_idx is in [BAR0_REG_IDX, BAR0_REG_IDX+NUM_BAR_REGS), so the difference is 0..5.
            #[allow(clippy::cast_possible_truncation)]
            let bar_idx = (reg_idx - BAR0_REG_IDX) as u8;
            let mut value: u32 = 0;
            self.bars.read(bar_idx, 0, value.as_mut_bytes());
            value
        } else if in_pci_cfg {
            // Handle the special case where the capability VIRTIO_PCI_CAP_PCI_CFG
            // is accessed. This capability has a special meaning as it allows the
            // guest to access other capabilities without mapping the PCI BAR.
            let offset = (reg_idx * 4 - self.cap_pci_cfg_info.offset) as usize;
            let mut data = [0u8; 4];
            let len = u32::from(self.cap_pci_cfg_info.cap.cap.length) as usize;
            if len <= 4 {
                self.read_cap_pci_cfg(offset, &mut data[..len]);
                u32::from_le_bytes(data)
            } else {
                0
            }
        } else {
            self.configuration.read_reg(reg_idx)
        }
    }

    fn read_bar(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        match offset {
            o if o < u64::from(COMMON_CONFIG_BAR_OFFSET + COMMON_CONFIG_SIZE) => {
                self.common_config.read(
                    o - u64::from(COMMON_CONFIG_BAR_OFFSET),
                    data,
                    self.device.clone(),
                )
            }
            o if (u64::from(ISR_CONFIG_BAR_OFFSET)
                ..u64::from(ISR_CONFIG_BAR_OFFSET + ISR_CONFIG_SIZE))
                .contains(&o) =>
            {
                // We don't actually support legacy INT#x interrupts for VirtIO PCI devices
                warn!("pci: read access to unsupported ISR status field");
                data.fill(0);
            }
            o if (u64::from(DEVICE_CONFIG_BAR_OFFSET)
                ..u64::from(DEVICE_CONFIG_BAR_OFFSET + DEVICE_CONFIG_SIZE))
                .contains(&o) =>
            {
                let device = self.device.lock().unwrap();
                device.read_config(o - u64::from(DEVICE_CONFIG_BAR_OFFSET), data);
            }
            o if (u64::from(NOTIFICATION_BAR_OFFSET)
                ..u64::from(NOTIFICATION_BAR_OFFSET + NOTIFICATION_SIZE))
                .contains(&o) =>
            {
                // Handled with ioeventfds.
                warn!("pci: unexpected read to notification BAR. Offset {o:#x}");
            }
            o if (u64::from(MSIX_TABLE_BAR_OFFSET)
                ..u64::from(MSIX_TABLE_BAR_OFFSET + MSIX_TABLE_SIZE))
                .contains(&o) =>
            {
                if let Some(interrupt) = &self.virtio_interrupt {
                    interrupt
                        .msix_config
                        .lock()
                        .unwrap()
                        .read_table(o - u64::from(MSIX_TABLE_BAR_OFFSET), data);
                }
            }
            o if (u64::from(MSIX_PBA_BAR_OFFSET)
                ..u64::from(MSIX_PBA_BAR_OFFSET + MSIX_PBA_SIZE))
                .contains(&o) =>
            {
                if let Some(interrupt) = &self.virtio_interrupt {
                    interrupt
                        .msix_config
                        .lock()
                        .unwrap()
                        .read_pba(o - u64::from(MSIX_PBA_BAR_OFFSET), data);
                }
            }
            _ => (),
        }
    }

    fn write_bar(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        match offset {
            o if o < u64::from(COMMON_CONFIG_BAR_OFFSET + COMMON_CONFIG_SIZE) => {
                self.common_config.write(
                    o - u64::from(COMMON_CONFIG_BAR_OFFSET),
                    data,
                    self.device.clone(),
                    self.device_activated.load(Ordering::SeqCst),
                )
            }
            o if (u64::from(ISR_CONFIG_BAR_OFFSET)
                ..u64::from(ISR_CONFIG_BAR_OFFSET + ISR_CONFIG_SIZE))
                .contains(&o) =>
            {
                // We don't actually support legacy INT#x interrupts for VirtIO PCI devices
                warn!("pci: access to unsupported ISR status field");
            }
            o if (u64::from(DEVICE_CONFIG_BAR_OFFSET)
                ..u64::from(DEVICE_CONFIG_BAR_OFFSET + DEVICE_CONFIG_SIZE))
                .contains(&o) =>
            {
                let mut device = self.device.lock().unwrap();
                device.write_config(o - u64::from(DEVICE_CONFIG_BAR_OFFSET), data);
            }
            o if (u64::from(NOTIFICATION_BAR_OFFSET)
                ..u64::from(NOTIFICATION_BAR_OFFSET + NOTIFICATION_SIZE))
                .contains(&o) =>
            {
                // Handled with ioeventfds.
                warn!("pci: unexpected write to notification BAR. Offset {o:#x}");
            }
            o if (u64::from(MSIX_TABLE_BAR_OFFSET)
                ..u64::from(MSIX_TABLE_BAR_OFFSET + MSIX_TABLE_SIZE))
                .contains(&o) =>
            {
                if let Some(interrupt) = &self.virtio_interrupt {
                    interrupt
                        .msix_config
                        .lock()
                        .unwrap()
                        .write_table(o - u64::from(MSIX_TABLE_BAR_OFFSET), data);
                }
            }
            o if (u64::from(MSIX_PBA_BAR_OFFSET)
                ..u64::from(MSIX_PBA_BAR_OFFSET + MSIX_PBA_SIZE))
                .contains(&o) =>
            {
                if let Some(interrupt) = &self.virtio_interrupt {
                    interrupt
                        .msix_config
                        .lock()
                        .unwrap()
                        .write_pba(o - u64::from(MSIX_PBA_BAR_OFFSET), data);
                }
            }
            _ => (),
        };

        // Try and activate the device if the driver status has changed
        if self.needs_activation() {
            debug!("Activating device");
            let interrupt = Arc::clone(self.virtio_interrupt.as_ref().unwrap());
            match self
                .virtio_device()
                .lock()
                .unwrap()
                .activate(self.memory.clone(), interrupt.clone())
            {
                Ok(()) => self.device_activated.store(true, Ordering::SeqCst),
                Err(err) => {
                    self.common_config.driver_status |= DEVICE_NEEDS_RESET;
                    error!("Error activating device: {err:?}");

                    // Section 2.1.2 of the specification states that we need to send a device
                    // configuration change interrupt
                    let _ = interrupt.trigger(VirtioInterruptType::Config);
                }
            }
        }

        // Device has been reset by the driver
        if self.device_activated.load(Ordering::SeqCst) && self.is_driver_init() {
            let mut device = self.device.lock().unwrap();
            let reset_result = device.reset();
            match reset_result {
                Some(_) => {
                    // Upon reset the device returns its interrupt EventFD
                    self.virtio_interrupt = None;
                    self.device_activated.store(false, Ordering::SeqCst);

                    // Reset queue readiness (changes queue_enable), queue sizes
                    // and selected_queue as per spec for reset
                    self.virtio_device()
                        .lock()
                        .unwrap()
                        .queues_mut()
                        .iter_mut()
                        .for_each(Queue::reset);
                    self.common_config.queue_select = 0;
                }
                None => {
                    error!("Attempt to reset device when not implemented in underlying device");
                    // The virtio spec does not specify what to do if reset fails.
                    //
                    // Our MMIO transport sets FAILED in this case, but we must NOT do that for PCI.
                    // During shutdown, the Linux kernel issues a reset to each virtio device.  The
                    // virtio PCI driver then polls device_status until it reads back 0, unlike the
                    // virtio MMIO driver which simply writes 0 and returns.  Setting FAILED would
                    // cause the poll to spin forever, breaking reboot command and Ctrl-Alt-Del.
                    // - PCI: https://elixir.bootlin.com/linux/v6.19.8/source/drivers/virtio/virtio_pci_modern.c#L546-L565
                    // - MMIO: https://elixir.bootlin.com/linux/v6.19.8/source/drivers/virtio/virtio_mmio.c#L251-L258
                    //
                    // Since device_status was already set to INIT by set_device_status(), we don't
                    // need to set it again here.  However, the backend device is still active since
                    // reset() is unimplemented.  The combination of device_activated == true and
                    // device_status == INIT will cause set_device_status() to block any
                    // re-initialization attempts.
                }
            }
        }
        None
    }
}

impl BusDevice for VirtioPciDevice {
    fn read(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        self.read_bar(base, offset, data)
    }

    fn write(&mut self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        self.write_bar(base, offset, data)
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex};

    use event_manager::MutEventSubscriber;
    use linux_loader::loader::Cmdline;
    use vm_memory::{ByteValued, Le32};

    use super::{PciCapabilityType, VirtioPciDevice};
    use crate::Vmm;
    use crate::arch::MEM_64BIT_DEVICES_START;
    use crate::builder::tests::default_vmm;
    use crate::devices::virtio::device::{VirtioDevice, VirtioDeviceType};
    use crate::devices::virtio::generated::virtio_config::VIRTIO_F_VERSION_1;
    use crate::devices::virtio::rng::Entropy;
    use crate::devices::virtio::transport::pci::common_config_offset::*;
    use crate::devices::virtio::transport::pci::device::{
        COMMON_CONFIG_BAR_OFFSET, COMMON_CONFIG_SIZE, DEVICE_CONFIG_BAR_OFFSET, DEVICE_CONFIG_SIZE,
        ISR_CONFIG_BAR_OFFSET, ISR_CONFIG_SIZE, NOTIFICATION_BAR_OFFSET, NOTIFICATION_SIZE,
        NOTIFY_OFF_MULTIPLIER, PciVirtioSubclass, VirtioPciCap, VirtioPciCfgCap,
        VirtioPciNotifyCap,
    };
    use crate::devices::virtio::transport::pci::device_status::{
        ACKNOWLEDGE, DRIVER, DRIVER_OK, FEATURES_OK,
    };
    use crate::pci::msix::MsixCap;
    use crate::pci::{PciCapabilityId, PciClassCode, PciDevice};
    use crate::rate_limiter::RateLimiter;

    fn create_vmm_with_virtio_pci_device() -> Vmm {
        let mut vmm = default_vmm();
        vmm.device_manager.enable_pci(&vmm.vm);
        let entropy = Arc::new(Mutex::new(Entropy::new(RateLimiter::default()).unwrap()));
        let mut event_manager = crate::EventManager::new().unwrap();
        vmm.device_manager
            .attach_virtio_device(
                &vmm.vm,
                "rng".to_string(),
                entropy.clone(),
                &mut Cmdline::new(1024).unwrap(),
                &mut event_manager,
                false,
            )
            .unwrap();
        vmm
    }

    fn get_virtio_device(vmm: &Vmm) -> Arc<Mutex<VirtioPciDevice>> {
        vmm.device_manager
            .pci_devices
            .get_virtio_device(VirtioDeviceType::Rng, "rng")
            .unwrap()
            .clone()
    }

    #[test]
    fn test_pci_device_config() {
        let mut vmm = create_vmm_with_virtio_pci_device();
        let device = get_virtio_device(&vmm);
        let mut locked_virtio_pci_device = device.lock().unwrap();

        // For more information for the values we are checking here look into the VirtIO spec here:
        // https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-1220007
        // and PCI Header type 0 layout here: https://wiki.osdev.org/PCI#Configuration_Space

        //              |  16 bits  |  16 bits  |
        //              |-----------|-----------|
        // regiger 0x0: | Device ID | Vendor ID |
        //
        // Vendor ID of VirtIO devices is 0x1af4
        let reg0 = locked_virtio_pci_device.read_config_register(0);
        assert_eq!(reg0 & 0xffff, 0x1af4);
        // VirtIO PCI device IDs are in the range [0x1000, 0x107f]. (We are not using transitional
        // device IDs).
        let devid = reg0 >> 16;
        assert!(
            (0x1000..=0x107f).contains(&devid),
            "Device ID check: {:#x} >= 0x1000 && {:#x} <= 0x107f",
            devid,
            devid
        );

        //              |   16 bits  |  16 bits  |
        //              |------------|-----------|
        // regiger 0x1: |   Status   |  Command  |
        // We offer the capabilities list (bit 4 of status register) at offset 0x34
        let reg1 = locked_virtio_pci_device.read_config_register(1);
        assert_eq!(reg1, 0x0010_0000);

        //               |   8 bits   |  8 bits  | 8 bits  |    8 bits   |
        // register 0x2: | Class code | Subclass | Prog IF | Revision ID |
        //
        // Class code: VIRTIO_PCI_VENDOR_ID for all VirtIO devices
        // Subclass: PciClassCode::NetworkController for net, PciClassCode::MassStorageController
        // for block           PciClassCode::UnassignedClass for everything else
        // Prog IF: A register defining some programmable interface register. 0 for VirtIO devices
        // Revision ID: 0x1 for modern VirtIO devices
        let reg2 = locked_virtio_pci_device.read_config_register(2);
        assert_eq!(reg2, 0xffff_0001);
        let class_code = ((reg2 >> 24) & 0xff) as u8;
        assert_eq!(class_code, PciClassCode::UnassignedClass as u8);
        let subclass = ((reg2 >> 16) & 0xff) as u8;
        assert_eq!(subclass, PciVirtioSubclass::NonTransitionalBase as u8);
        let prog_if = ((reg2 >> 8) & 0xff) as u8;
        assert_eq!(prog_if, 0);
        let revision_id = reg2 & 0xff;
        assert_eq!(revision_id, 0x1);

        //               |   8 bits   |    8 bits   |    8 bits     |      8 bits     |
        // register 0x3: |    BIST    | Header Type | Latency timer | Cache line size |
        //
        // BIST: status and control for self test of PCI devices. Always 0 for VirtIO devices
        // HeaderType: 0x0 for general devices
        // LatencyTimer: Latency timer in units of PCI bus clocks, 0 for VirtIO
        // Cache Line size: 0 for VirtIO devices
        let reg3 = locked_virtio_pci_device.read_config_register(3);
        assert_eq!(reg3, 0x0);

        // register 0xa: Cardbus CIS pointer
        //
        // We don't emulate CardBus
        let reg10 = locked_virtio_pci_device.read_config_register(0xa);
        assert_eq!(reg10, 0);

        //              |    16 bits   |       16 bits      |
        // regiger 0xb: | Subsystem ID | Subsystem vendor ID|
        //
        // For us Subsystem ID is same as device ID and subsystem vendor ID is same as vendor ID
        // (reg 0x0)
        let reg11 = locked_virtio_pci_device.read_config_register(0xb);
        assert_eq!(reg11, reg0);

        // register 0xc: Expansion ROM base address: 0x0 for us
        let reg12 = locked_virtio_pci_device.read_config_register(0xc);
        assert_eq!(reg12, 0);

        //               |  24 bits |        8 bits        |
        // register 0xd: | Reserved | Capabilities pointer |
        let reg13 = locked_virtio_pci_device.read_config_register(0xd);
        assert_eq!(reg13 >> 24, 0);

        // register 0xe: Reserved
        let reg14 = locked_virtio_pci_device.read_config_register(0xe);
        assert_eq!(reg14, 0);

        //               |    8 bits   |   8 bits  |    8 bits     |     8 bits     |
        // register 0xf: | max latency | min grant | Interrupt pin | Interrupt line |
        //
        // We don't specify any of those
        let reg15 = locked_virtio_pci_device.read_config_register(0xf);
        assert_eq!(reg15, 0);
    }

    #[test]
    fn test_reading_bars() {
        let mut vmm = create_vmm_with_virtio_pci_device();
        let device = get_virtio_device(&vmm);
        let mut locked_virtio_pci_device = device.lock().unwrap();

        // According to OSdev wiki (https://wiki.osdev.org/PCI#Configuration_Space):
        //
        // When you want to retrieve the actual base address of a BAR, be sure to mask the lower
        // bits. For 16-bit Memory Space BARs, you calculate (BAR[x] & 0xFFF0). For 32-bit Memory
        // Space BARs, you calculate (BAR[x] & 0xFFFFFFF0). For 64-bit Memory Space BARs, you
        // calculate ((BAR[x] & 0xFFFFFFF0) + ((BAR[x + 1] & 0xFFFFFFFF) << 32)) For I/O Space
        // BARs, you calculate (BAR[x] & 0xFFFFFFFC).

        // We are allocating a single 64-bit MMIO bar for VirtIO capabilities list. As a result, we
        // are using the first two BAR registers from the configuration space.
        //
        // The BAR address layout is as follows:
        //
        // |          Bits 31-4           |     Bit 3    | Bits 2-1 |   Bit 0  |
        // | 16-Byte Aligned Base Address | Prefetchable |   Type   | Always 0 |
        //
        // For 64-bit addresses though a second BAR is used to hold the upper 32 bits
        // of the address. Prefetchable and type will be help in the lower bits of the
        // first bar along with the lower 32-bits of the address which is always 16-bytes
        // aligned.
        let bar_addr_lo = locked_virtio_pci_device.read_config_register(0x4);
        let bar_addr_hi = locked_virtio_pci_device.read_config_register(0x5);
        let bar_addr = bar_addr_lo as u64 + ((bar_addr_hi as u64) << 32);

        // Bit 0 always 0
        assert_eq!(bar_addr & 0x1, 0);
        // Type is 0x2 meaning 64-bit BAR
        assert_eq!((bar_addr & 0x6) >> 1, 2);
        // The actual address of the BAR should be the first available address of our 64-bit MMIO
        // region
        assert_eq!(bar_addr & 0xffff_ffff_ffff_fff0, MEM_64BIT_DEVICES_START);

        // Reading the BAR size is a bit more convoluted. According to OSDev wiki:
        //
        // To determine the amount of address space needed by a PCI device, you must save the
        // original value of the BAR, write a value of all 1's to the register, then read it back.
        // The amount of memory can then be determined by masking the information bits, performing
        // a bitwise NOT ('~' in C), and incrementing the value by 1.

        locked_virtio_pci_device.write_config_register(0x4, 0, &[0xff, 0xff, 0xff, 0xff]);
        // Read the lower size bits and mask out the last 4 bits include Prefetchable, Type and
        // hardwired-0
        let bar_size_lo = locked_virtio_pci_device.read_config_register(0x4) as u64 & 0xfffffff0;
        locked_virtio_pci_device.write_config_register(0x5, 0, &[0xff, 0xff, 0xff, 0xff]);
        let bar_size_hi = locked_virtio_pci_device.read_config_register(0x5) as u64;
        let bar_size = !((bar_size_hi << 32) | bar_size_lo) + 1;

        // We create a capabilities BAR region of 0x80000 bytes
        assert_eq!(bar_size, 0x80000);
    }

    fn read_virtio_pci_cap(
        device: &mut VirtioPciDevice,
        offset: u32,
    ) -> (PciCapabilityId, u8, VirtioPciCap) {
        let word1 = device.read_config_register((offset >> 2) as u16);
        let word2 = device.read_config_register((offset >> 2) as u16 + 1);
        let word3 = device.read_config_register((offset >> 2) as u16 + 2);
        let word4 = device.read_config_register((offset >> 2) as u16 + 3);

        let id = PciCapabilityId::from((word1 & 0xff) as u8);
        let next = ((word1 >> 8) & 0xff) as u8;

        let cap = VirtioPciCap {
            cap_len: ((word1 >> 16) & 0xff) as u8,
            cfg_type: ((word1 >> 24) & 0xff) as u8,
            pci_bar: (word2 & 0xff) as u8,
            id: ((word2 >> 8) & 0xff) as u8,
            padding: [0u8; 2],
            offset: Le32::from(word3),
            length: Le32::from(word4),
        };

        // We only ever set a single capability of a type. It's ID is 0.
        assert_eq!(cap.id, 0);

        (id, next, cap)
    }

    fn read_virtio_notification_cap(
        device: &mut VirtioPciDevice,
        offset: u32,
    ) -> (PciCapabilityId, u8, VirtioPciNotifyCap) {
        let (id, next, cap) = read_virtio_pci_cap(device, offset);
        let word5 = device.read_config_register((offset >> 2) as u16 + 4);

        let notification_cap = VirtioPciNotifyCap {
            cap,
            notify_off_multiplier: Le32::from(word5),
        };

        (id, next, notification_cap)
    }

    fn read_virtio_pci_config_cap(
        device: &mut VirtioPciDevice,
        offset: u32,
    ) -> (PciCapabilityId, u8, VirtioPciCfgCap) {
        let (id, next, cap) = read_virtio_pci_cap(device, offset);
        let word5 = device.read_config_register((offset >> 2) as u16 + 4);

        let pci_cfg_cap = VirtioPciCfgCap {
            cap,
            pci_cfg_data: word5.as_slice().try_into().unwrap(),
        };

        (id, next, pci_cfg_cap)
    }

    fn read_msix_cap(device: &mut VirtioPciDevice, offset: u32) -> (PciCapabilityId, u8, MsixCap) {
        let word1 = device.read_config_register((offset >> 2) as u16);
        let table = device.read_config_register((offset >> 2) as u16 + 1);
        let pba = device.read_config_register((offset >> 2) as u16 + 2);

        let id = PciCapabilityId::from((word1 & 0xff) as u8);
        let next = ((word1 >> 8) & 0xff) as u8;

        let cap = MsixCap {
            msg_ctl: (word1 & 0xffff) as u16,
            table,
            pba,
        };

        (id, next, cap)
    }

    fn capabilities_start(device: &mut VirtioPciDevice) -> u32 {
        device.read_config_register(0xd) & 0xfc
    }

    #[test]
    fn test_capabilities() {
        let mut vmm = create_vmm_with_virtio_pci_device();
        let device = get_virtio_device(&vmm);
        let mut locked_virtio_pci_device = device.lock().unwrap();

        // VirtIO devices need to expose a set of mandatory capabilities:
        // * Common configuration
        // * Notifications
        // * ISR status
        // * PCI configuration access
        //
        // and, optionally, a device-specific configuration area for those devices that need it.
        //
        // We always expose all 5 capabilities, so check that the capabilities are present

        // Common config
        let common_config_cap_offset = capabilities_start(&mut locked_virtio_pci_device);
        let (id, next, cap) =
            read_virtio_pci_cap(&mut locked_virtio_pci_device, common_config_cap_offset);
        assert_eq!(id, PciCapabilityId::VendorSpecific);
        assert_eq!(cap.cap_len as usize, size_of::<VirtioPciCap>() + 2);
        assert_eq!(cap.cfg_type, PciCapabilityType::Common as u8);
        assert_eq!(cap.pci_bar, 0);
        assert_eq!(u32::from(cap.offset), COMMON_CONFIG_BAR_OFFSET);
        assert_eq!(u32::from(cap.length), COMMON_CONFIG_SIZE);
        assert_eq!(next as u32, common_config_cap_offset + cap.cap_len as u32);

        // ISR
        let isr_cap_offset = next as u32;
        let (id, next, cap) = read_virtio_pci_cap(&mut locked_virtio_pci_device, isr_cap_offset);
        assert_eq!(id, PciCapabilityId::VendorSpecific);
        assert_eq!(cap.cap_len as usize, size_of::<VirtioPciCap>() + 2);
        assert_eq!(cap.cfg_type, PciCapabilityType::Isr as u8);
        assert_eq!(cap.pci_bar, 0);
        assert_eq!(u32::from(cap.offset), ISR_CONFIG_BAR_OFFSET);
        assert_eq!(u32::from(cap.length), ISR_CONFIG_SIZE);
        assert_eq!(next as u32, isr_cap_offset + cap.cap_len as u32);

        // Device config
        let device_config_cap_offset = next as u32;
        let (id, next, cap) =
            read_virtio_pci_cap(&mut locked_virtio_pci_device, device_config_cap_offset);
        assert_eq!(id, PciCapabilityId::VendorSpecific);
        assert_eq!(cap.cap_len as usize, size_of::<VirtioPciCap>() + 2);
        assert_eq!(cap.cfg_type, PciCapabilityType::Device as u8);
        assert_eq!(cap.pci_bar, 0);
        assert_eq!(u32::from(cap.offset), DEVICE_CONFIG_BAR_OFFSET);
        assert_eq!(u32::from(cap.length), DEVICE_CONFIG_SIZE);
        assert_eq!(next as u32, device_config_cap_offset + cap.cap_len as u32);

        let notification_cap_offset = next as u32;
        let (id, next, cap) =
            read_virtio_notification_cap(&mut locked_virtio_pci_device, notification_cap_offset);
        assert_eq!(id, PciCapabilityId::VendorSpecific);
        assert_eq!(
            cap.cap.cap_len as usize,
            size_of::<VirtioPciNotifyCap>() + 2
        );
        assert_eq!(cap.cap.cfg_type, PciCapabilityType::Notify as u8);
        assert_eq!(cap.cap.pci_bar, 0);
        assert_eq!(u32::from(cap.cap.offset), NOTIFICATION_BAR_OFFSET);
        assert_eq!(u32::from(cap.cap.length), NOTIFICATION_SIZE);
        assert_eq!(
            next as u32,
            notification_cap_offset + cap.cap.cap_len as u32
        );
        assert_eq!(u32::from(cap.notify_off_multiplier), NOTIFY_OFF_MULTIPLIER);

        let pci_config_cap_offset = next as u32;
        let (id, next, cap) =
            read_virtio_pci_config_cap(&mut locked_virtio_pci_device, pci_config_cap_offset);
        assert_eq!(id, PciCapabilityId::VendorSpecific);
        assert_eq!(cap.cap.cap_len as usize, size_of::<VirtioPciCfgCap>() + 2);
        assert_eq!(cap.cap.cfg_type, PciCapabilityType::Pci as u8);
        assert_eq!(cap.cap.pci_bar, 0);
        assert_eq!(u32::from(cap.cap.offset), 0);
        assert_eq!(u32::from(cap.cap.length), 0);
        assert_eq!(
            locked_virtio_pci_device.cap_pci_cfg_info.offset,
            pci_config_cap_offset as u16 + 2
        );
        assert_eq!(locked_virtio_pci_device.cap_pci_cfg_info.cap, cap);
        assert_eq!(next as u32, pci_config_cap_offset + cap.cap.cap_len as u32);

        let msix_cap_offset = next as u32;
        let (id, next, cap) = read_msix_cap(&mut locked_virtio_pci_device, msix_cap_offset);
        assert_eq!(id, PciCapabilityId::MsiX);
        assert_eq!(next, 0);
    }

    fn cap_pci_cfg_read(device: &mut VirtioPciDevice, bar_offset: u32, length: u32) -> u32 {
        let pci_config_cap_offset = capabilities_start(device) as usize
            + 3 * (size_of::<VirtioPciCap>() + 2)
            + (size_of::<VirtioPciNotifyCap>() + 2);

        // To program the access through the PCI config capability mechanism, we need to write the
        // bar offset and read length in the `VirtioPciCfgCap::cap.offset` and
        // `VirtioPciCfgCap::length` fields. These are the third and fourth word respectively
        // within the capability. The fifth word of the capability should contain the data
        let offset_register = ((pci_config_cap_offset + 8) >> 2) as u16;
        let length_register = ((pci_config_cap_offset + 12) >> 2) as u16;
        let data_register = ((pci_config_cap_offset + 16) >> 2) as u16;

        device.write_config_register(offset_register, 0, bar_offset.as_slice());
        device.write_config_register(length_register, 0, length.as_slice());
        device.read_config_register(data_register)
    }

    fn cap_pci_cfg_write(device: &mut VirtioPciDevice, bar_offset: u32, length: u32, data: &[u8]) {
        let pci_config_cap_offset = capabilities_start(device) as usize
            + 3 * (size_of::<VirtioPciCap>() + 2)
            + (size_of::<VirtioPciNotifyCap>() + 2);

        // To program the access through the PCI config capability mechanism, we need to write the
        // bar offset and read length in the `VirtioPciCfgCap::cap.offset` and
        // `VirtioPciCfgCap::length` fields. These are the third and fourth word respectively
        // within the capability. The fifth word of the capability should contain the data
        let offset_register = ((pci_config_cap_offset + 8) >> 2) as u16;
        let length_register = ((pci_config_cap_offset + 12) >> 2) as u16;
        let data_register = ((pci_config_cap_offset + 16) >> 2) as u16;

        device.write_config_register(offset_register, 0, bar_offset.as_slice());
        device.write_config_register(length_register, 0, length.as_slice());
        device.write_config_register(data_register, 0, data);
    }

    #[test]
    fn test_pci_configuration_cap() {
        let mut vmm = create_vmm_with_virtio_pci_device();
        let device = get_virtio_device(&vmm);
        let mut locked_virtio_pci_device = device.lock().unwrap();

        // Let's read the number of queues of the entropy device
        // That information is located at NUM_QUEUES offset past the BAR region belonging to the
        // common config capability.
        let bar_offset = COMMON_CONFIG_BAR_OFFSET + u32::try_from(NUM_QUEUES).unwrap();
        let len = 2u32;
        let num_queues = cap_pci_cfg_read(&mut locked_virtio_pci_device, bar_offset, len);
        assert_eq!(num_queues, 1);

        // Use queue_select to test read/write through the PCI Configuration Access Capability.
        // This register is freely read-writable with no side effects, making it ideal for testing
        // the capability mechanism itself.
        let bar_offset = COMMON_CONFIG_BAR_OFFSET + QUEUE_SELECT as u32;
        let len = 2u32;
        let val = cap_pci_cfg_read(&mut locked_virtio_pci_device, bar_offset, len);
        assert_eq!(val, 0);

        cap_pci_cfg_write(
            &mut locked_virtio_pci_device,
            bar_offset,
            len,
            0x01u32.as_slice(),
        );
        let val = cap_pci_cfg_read(&mut locked_virtio_pci_device, bar_offset, len);
        assert_eq!(val, 0x01);

        // Reads with out-of-bounds lengths should return 0s
        assert_eq!(
            cap_pci_cfg_read(&mut locked_virtio_pci_device, bar_offset, 8),
            0
        );
        // Writes with out-of-bounds lengths should have no effect
        cap_pci_cfg_write(
            &mut locked_virtio_pci_device,
            bar_offset,
            8,
            0xDEADu32.as_slice(),
        );
        assert_eq!(
            cap_pci_cfg_read(&mut locked_virtio_pci_device, bar_offset, len),
            val
        );

        // When the capability's length is shorter than pci_cfg_data (4 bytes), only that many
        // bytes should be forwarded to the BAR write. Writing 0xDEAD_0000 with length=2 should
        // only write the lower 2 bytes (0x0000).
        cap_pci_cfg_write(
            &mut locked_virtio_pci_device,
            bar_offset,
            len,
            0xDEAD_0000u32.as_slice(),
        );
        assert_eq!(
            cap_pci_cfg_read(&mut locked_virtio_pci_device, bar_offset, len),
            0x0000
        );
    }

    fn isr_status_read(device: &mut VirtioPciDevice) -> u32 {
        let mut data = 0u32;
        device.read_bar(0, u64::from(ISR_CONFIG_BAR_OFFSET), data.as_mut_slice());
        data
    }

    fn isr_status_write(device: &mut VirtioPciDevice, data: u32) {
        device.write_bar(0, u64::from(ISR_CONFIG_BAR_OFFSET), data.as_slice());
    }

    #[test]
    fn test_isr_capability() {
        let mut vmm = create_vmm_with_virtio_pci_device();
        let device = get_virtio_device(&vmm);
        let mut locked_virtio_pci_device = device.lock().unwrap();

        // We don't support legacy interrupts so reads to ISR BAR should always return 0s and
        // writes to it should not have any effect
        assert_eq!(isr_status_read(&mut locked_virtio_pci_device), 0);
        isr_status_write(&mut locked_virtio_pci_device, 0x1312);
        assert_eq!(isr_status_read(&mut locked_virtio_pci_device), 0);
    }

    #[test]
    fn test_notification_capability() {
        let mut vmm = create_vmm_with_virtio_pci_device();
        let device = get_virtio_device(&vmm);
        let mut locked_virtio_pci_device = device.lock().unwrap();

        let notification_cap_offset = (capabilities_start(&mut locked_virtio_pci_device) as usize
            + 3 * (size_of::<VirtioPciCap>() + 2))
            .try_into()
            .unwrap();

        let (_, _, notify_cap) =
            read_virtio_notification_cap(&mut locked_virtio_pci_device, notification_cap_offset);

        // We do not offer `VIRTIO_F_NOTIFICATION_DATA` so:
        // * `cap.offset` MUST by 2-byte aligned
        assert_eq!(u32::from(notify_cap.cap.offset) & 0x3, 0);
        // * The device MUST either present notify_off_multiplier as an even power of 2, or present
        //   notify_off_multiplier as 0.
        let multiplier = u32::from(notify_cap.notify_off_multiplier);
        assert!(multiplier.is_power_of_two() && multiplier.trailing_zeros() % 2 == 0);
        // * For all queues, the value cap.length presented by the device MUST satisfy:
        //
        //   `cap.length >= queue_notify_off * notify_off_multiplier + 2`
        //
        // The spec allows for up to 65536 queues, but in reality the device we are using with most
        // queues is vsock (3). Let's check here for 16, projecting for future devices and
        // use-cases such as multiple queue pairs in network devices
        assert!(u32::from(notify_cap.cap.length) >= 15 * multiplier + 2);

        // Reads and writes to the notification region of the BAR are handled by IoEvent file
        // descriptors. Any such accesses should have no effects.
        let data = [0x42u8; NOTIFICATION_SIZE as usize];
        locked_virtio_pci_device.write_bar(0, u64::from(NOTIFICATION_BAR_OFFSET), &data);
        let mut buffer = [0x0; NOTIFICATION_SIZE as usize];
        locked_virtio_pci_device.read_bar(0, u64::from(NOTIFICATION_BAR_OFFSET), &mut buffer);
        assert_eq!(buffer, [0u8; NOTIFICATION_SIZE as usize]);
    }

    const COMMON_CFG: u64 = COMMON_CONFIG_BAR_OFFSET as u64;

    fn write_driver_status(device: &mut VirtioPciDevice, status: u8) {
        device.write_bar(0, COMMON_CFG + DEVICE_STATUS, status.as_slice());
    }

    fn read_driver_status(device: &mut VirtioPciDevice) -> u8 {
        let mut status = 0u8;
        device.read_bar(0, COMMON_CFG + DEVICE_STATUS, status.as_mut_slice());
        status
    }

    fn read_device_features(device: &mut VirtioPciDevice) -> u64 {
        let mut features_lo = 0u32;
        device.write_bar(0, COMMON_CFG + DEVICE_FEATURE_SELECT, 0u32.as_slice());
        device.read_bar(0, COMMON_CFG + DEVICE_FEATURE, features_lo.as_mut_slice());
        let mut features_hi = 0u32;
        device.write_bar(0, COMMON_CFG + DEVICE_FEATURE_SELECT, 1u32.as_slice());
        device.read_bar(0, COMMON_CFG + DEVICE_FEATURE, features_hi.as_mut_slice());

        features_lo as u64 | ((features_hi as u64) << 32)
    }

    fn write_driver_features(device: &mut VirtioPciDevice, features: u64) {
        device.write_bar(0, COMMON_CFG + DRIVER_FEATURE_SELECT, 0u32.as_slice());
        device.write_bar(
            0,
            COMMON_CFG + DRIVER_FEATURE,
            ((features & 0xffff_ffff) as u32).as_slice(),
        );
        device.write_bar(0, COMMON_CFG + DRIVER_FEATURE_SELECT, 1u32.as_slice());
        device.write_bar(
            0,
            COMMON_CFG + DRIVER_FEATURE,
            (((features >> 32) & 0xffff_ffff) as u32).as_slice(),
        );
    }

    fn setup_queues(device: &mut VirtioPciDevice) {
        device.write_bar(0, COMMON_CFG + QUEUE_DESC_LO, 0x8000_0000u64.as_slice());
        device.write_bar(0, COMMON_CFG + QUEUE_AVAIL_LO, 0x8000_1000u64.as_slice());
        device.write_bar(0, COMMON_CFG + QUEUE_USED_LO, 0x8000_2000u64.as_slice());
        device.write_bar(0, COMMON_CFG + QUEUE_ENABLE, 1u16.as_slice());
    }

    #[test]
    fn test_device_initialization() {
        let mut vmm = create_vmm_with_virtio_pci_device();
        let device = get_virtio_device(&vmm);
        let mut locked_virtio_pci_device = device.lock().unwrap();

        assert!(locked_virtio_pci_device.is_driver_init());
        assert!(!locked_virtio_pci_device.is_driver_ready());
        assert!(
            !locked_virtio_pci_device
                .device_activated
                .load(Ordering::SeqCst)
        );

        write_driver_status(&mut locked_virtio_pci_device, ACKNOWLEDGE);
        write_driver_status(&mut locked_virtio_pci_device, ACKNOWLEDGE | DRIVER);
        assert!(!locked_virtio_pci_device.is_driver_init());
        assert!(!locked_virtio_pci_device.is_driver_ready());
        assert!(
            !locked_virtio_pci_device
                .device_activated
                .load(Ordering::SeqCst)
        );

        let status = read_driver_status(&mut locked_virtio_pci_device);
        assert_eq!(status, ACKNOWLEDGE | DRIVER);

        // Entropy device just offers VIRTIO_F_VERSION_1
        let offered_features = read_device_features(&mut locked_virtio_pci_device);
        assert_eq!(offered_features, 1 << VIRTIO_F_VERSION_1);
        // ACK features
        write_driver_features(&mut locked_virtio_pci_device, offered_features);
        write_driver_status(
            &mut locked_virtio_pci_device,
            ACKNOWLEDGE | DRIVER | FEATURES_OK,
        );
        let status = read_driver_status(&mut locked_virtio_pci_device);
        assert!((status & FEATURES_OK) != 0);

        assert!(!locked_virtio_pci_device.is_driver_init());
        assert!(!locked_virtio_pci_device.is_driver_ready());
        assert!(
            !locked_virtio_pci_device
                .device_activated
                .load(Ordering::SeqCst)
        );

        setup_queues(&mut locked_virtio_pci_device);

        write_driver_status(
            &mut locked_virtio_pci_device,
            ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK,
        );

        assert!(!locked_virtio_pci_device.is_driver_init());
        assert!(locked_virtio_pci_device.is_driver_ready());
        assert!(
            locked_virtio_pci_device
                .device_activated
                .load(Ordering::SeqCst)
        );
    }

    #[test]
    fn test_activate_failure_sets_needs_reset() {
        // Verify that DEVICE_NEEDS_RESET is set in driver_status when device activation fails.
        use crate::devices::virtio::transport::pci::device_status::DEVICE_NEEDS_RESET;

        let mut vmm = create_vmm_with_virtio_pci_device();
        let device = get_virtio_device(&vmm);
        let mut locked = device.lock().unwrap();

        // Drive through init without setting up queues, so activate() fails.
        write_driver_status(&mut locked, ACKNOWLEDGE);
        write_driver_status(&mut locked, ACKNOWLEDGE | DRIVER);
        let features = read_device_features(&mut locked);
        write_driver_features(&mut locked, features);
        write_driver_status(&mut locked, ACKNOWLEDGE | DRIVER | FEATURES_OK);
        // Skip setup_queues() -- queues are not ready, so activate() will fail.
        write_driver_status(&mut locked, ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK);

        assert!(!locked.device_activated.load(Ordering::SeqCst));
        let status = read_driver_status(&mut locked);
        assert_eq!(status & DEVICE_NEEDS_RESET, DEVICE_NEEDS_RESET);
    }

    #[test]
    fn test_failed_reset_blocks_reinitialization() {
        let mut vmm = create_vmm_with_virtio_pci_device();
        let device = get_virtio_device(&vmm);
        let mut locked = device.lock().unwrap();

        // Full initialization sequence.
        write_driver_status(&mut locked, ACKNOWLEDGE);
        write_driver_status(&mut locked, ACKNOWLEDGE | DRIVER);
        let features = read_device_features(&mut locked);
        write_driver_features(&mut locked, features);
        write_driver_status(&mut locked, ACKNOWLEDGE | DRIVER | FEATURES_OK);
        setup_queues(&mut locked);
        write_driver_status(&mut locked, ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK);
        assert!(locked.device_activated.load(Ordering::SeqCst));

        // Write 0 to device_status to request a reset.
        // Entropy's reset() returns None (unimplemented), so the reset fails.
        write_driver_status(&mut locked, 0);
        assert_eq!(read_driver_status(&mut locked), 0);
        // device_activated stays true because the backend was not actually reset.
        assert!(locked.device_activated.load(Ordering::SeqCst));

        // Attempt to re-initialize should be rejected because device_activated is
        // still true while driver_status is INIT.
        write_driver_status(&mut locked, ACKNOWLEDGE);
        assert_eq!(read_driver_status(&mut locked), 0);

        // Save state and restore into a new device -- the combination of
        // device_activated == true and driver_status == INIT is preserved in the
        // snapshot, so the blocking behavior survives restore.
        let saved_state = locked.state();
        drop(locked);

        let new_entropy = Arc::new(Mutex::new(Entropy::new(RateLimiter::default()).unwrap()));
        let restored =
            VirtioPciDevice::new_from_state("rng".to_string(), &vmm.vm, new_entropy, saved_state)
                .unwrap();

        assert!(restored.device_activated.load(Ordering::SeqCst));
        assert_eq!(restored.common_config.driver_status, 0);
    }
}
