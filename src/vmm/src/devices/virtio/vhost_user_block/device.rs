// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Portions Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::cmp;
use std::io::Write;
use std::sync::atomic::AtomicU32;
use std::sync::Arc;

use log::error;
use utils::eventfd::EventFd;
use utils::u64_to_usize;
use vhost::vhost_user::message::*;
use vhost::vhost_user::VhostUserFrontend;

use super::{VhostUserBlockError, NUM_QUEUES, QUEUE_SIZE};
use crate::devices::virtio::block::device::FileEngineType;
use crate::devices::virtio::gen::virtio_blk::{
    VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_RO, VIRTIO_F_VERSION_1,
};
use crate::devices::virtio::gen::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use crate::devices::virtio::queue::Queue;
use crate::devices::virtio::vhost_user::VhostUserHandle;
use crate::devices::virtio::{
    ActivateError, CacheType, DeviceState, IrqTrigger, VirtioDevice, TYPE_BLOCK,
};
use crate::vmm_config::drive::BlockDeviceConfig;
use crate::vstate::memory::GuestMemoryMmap;

/// Block device config space size in bytes.
const BLOCK_CONFIG_SPACE_SIZE: u32 = 60;

/// Use this structure to set up the Block Device before booting the kernel.
#[derive(Debug, PartialEq, Eq)]
pub struct VhostUserBlockConfig {
    /// Unique identifier of the drive.
    pub drive_id: String,
    /// Part-UUID. Represents the unique id of the boot partition of this device. It is
    /// optional and it will be used only if the `is_root_device` field is true.
    pub partuuid: Option<String>,
    /// If set to true, it makes the current device the root block device.
    /// Setting this flag to true will mount the block device in the
    /// guest under /dev/vda unless the partuuid is present.
    pub is_root_device: bool,
    /// If set to true, the drive will ignore flush requests coming from
    /// the guest driver.
    pub cache_type: CacheType,
    /// Socket path of the vhost-user process
    pub socket: String,
}

impl From<BlockDeviceConfig> for VhostUserBlockConfig {
    fn from(value: BlockDeviceConfig) -> Self {
        Self {
            drive_id: value.drive_id,
            is_root_device: value.is_root_device,
            partuuid: value.partuuid,
            cache_type: value.cache_type,
            socket: Default::default(),
        }
    }
}

impl From<VhostUserBlockConfig> for BlockDeviceConfig {
    fn from(value: VhostUserBlockConfig) -> Self {
        Self {
            drive_id: value.drive_id,
            path_on_host: Default::default(),
            is_root_device: value.is_root_device,
            partuuid: value.partuuid,
            is_read_only: false,
            cache_type: value.cache_type,
            rate_limiter: None,
            file_engine_type: FileEngineType::default(),
        }
    }
}

/// vhost-user block device.
#[derive(Debug)]
pub struct VhostUserBlock {
    // Virtio fields.
    pub avail_features: u64,
    pub acked_features: u64,
    pub config_space: Vec<u8>,
    pub activate_evt: EventFd,

    // Transport related fields.
    pub queues: Vec<Queue>,
    pub queue_evts: [EventFd; u64_to_usize(NUM_QUEUES)],
    pub device_state: DeviceState,
    pub irq_trigger: IrqTrigger,

    // Implementation specific fields.
    pub id: String,
    pub partuuid: Option<String>,
    pub cache_type: CacheType,
    pub root_device: bool,
    pub read_only: bool,

    // Vhost user protocol handle
    pub vu_handle: VhostUserHandle,
    pub vu_acked_protocol_features: u64,
}

impl VhostUserBlock {
    pub fn new(config: VhostUserBlockConfig) -> Result<Self, VhostUserBlockError> {
        let mut requested_features = (1 << VIRTIO_F_VERSION_1)
            | (1 << VIRTIO_RING_F_EVENT_IDX)
            // vhost-user specific bit. Not defined in standart virtio spec.
            // Specifies ability of frontend to negotiate protocol features.
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
            // We always try to negotiate readonly with the backend.
            // If the backend is configured as readonly, we will accept it.
            | (1 << VIRTIO_BLK_F_RO);

        if config.cache_type == CacheType::Writeback {
            requested_features |= 1 << VIRTIO_BLK_F_FLUSH;
        }

        let requested_protocol_features = VhostUserProtocolFeatures::CONFIG;

        let mut vu_handle = VhostUserHandle::new(&config.socket, NUM_QUEUES)
            .map_err(VhostUserBlockError::VhostUser)?;
        let (acked_features, acked_protocol_features) = vu_handle
            .negotiate_features(requested_features, requested_protocol_features)
            .map_err(VhostUserBlockError::VhostUser)?;

        // Get config from backend if CONFIG is acked or use empty buffer.
        let config_space =
            if acked_protocol_features & VhostUserProtocolFeatures::CONFIG.bits() != 0 {
                // This buffer is read only. Ask vhost implementation why.
                let buffer = [0u8; BLOCK_CONFIG_SPACE_SIZE as usize];
                let (_, new_config_space) = vu_handle
                    .vu
                    .get_config(
                        VHOST_USER_CONFIG_OFFSET,
                        BLOCK_CONFIG_SPACE_SIZE,
                        VhostUserConfigFlags::WRITABLE,
                        &buffer,
                    )
                    .map_err(VhostUserBlockError::Vhost)?;
                new_config_space
            } else {
                vec![]
            };

        let activate_evt =
            EventFd::new(libc::EFD_NONBLOCK).map_err(VhostUserBlockError::EventFd)?;

        let queues = vec![Queue::new(QUEUE_SIZE)];
        let queue_evts = [EventFd::new(libc::EFD_NONBLOCK).map_err(VhostUserBlockError::EventFd)?;
            u64_to_usize(NUM_QUEUES)];
        let device_state = DeviceState::Inactive;
        let irq_trigger = IrqTrigger::new().map_err(VhostUserBlockError::IrqTrigger)?;

        // We negotiated features with backend. Now these acked_features
        // are available for guest driver to choose from.
        let avail_features = acked_features;
        let acked_features = acked_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let read_only = acked_features & (1 << VIRTIO_BLK_F_RO) != 0;

        Ok(Self {
            avail_features,
            acked_features,
            config_space,
            activate_evt,

            queues,
            queue_evts,
            device_state,
            irq_trigger,

            id: config.drive_id,
            partuuid: config.partuuid,
            cache_type: config.cache_type,
            read_only,
            root_device: config.is_root_device,

            vu_handle,
            vu_acked_protocol_features: acked_protocol_features,
        })
    }

    /// Prepare device for being snapshotted.
    pub fn prepare_save(&mut self) {
        unimplemented!("VhostUserBlock does not support snapshotting yet");
    }

    pub fn config(&self) -> VhostUserBlockConfig {
        VhostUserBlockConfig {
            drive_id: self.id.clone(),
            partuuid: self.partuuid.clone(),
            is_root_device: self.root_device,
            cache_type: self.cache_type,
            socket: self.vu_handle.socket_path.clone(),
        }
    }
}

impl VirtioDevice for VhostUserBlock {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn device_type(&self) -> u32 {
        TYPE_BLOCK
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
        &self.irq_trigger.irq_evt
    }

    /// Returns the current device interrupt status.
    fn interrupt_status(&self) -> Arc<AtomicU32> {
        self.irq_trigger.irq_status.clone()
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_len = self.config_space.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(
                &self.config_space[u64_to_usize(offset)..u64_to_usize(cmp::min(end, config_len))],
            )
            .unwrap();
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        // We do not advertise VIRTIO_BLK_F_CONFIG_WCE
        // that would allow configuring the "writeback" field.
        // Other block config fields are immutable.
    }

    fn activate(&mut self, mem: GuestMemoryMmap) -> Result<(), ActivateError> {
        // Setting features again, because now we negotiated them
        // with guest driver as well.
        self.vu_handle
            .set_features(self.acked_features)
            .map_err(ActivateError::VhostUser)?;
        self.vu_handle
            .setup_backend(
                &mem,
                &[(0, &self.queues[0], &self.queue_evts[0])],
                &self.irq_trigger,
            )
            .map_err(ActivateError::VhostUser)?;
        self.device_state = DeviceState::Activated(mem);
        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }
}
