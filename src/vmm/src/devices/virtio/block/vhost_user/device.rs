// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Portions Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::cmp;
use std::io::Write;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use log::error;
use logger::{IncMetric, METRICS};
use utils::eventfd::EventFd;
use utils::vm_memory::GuestMemoryMmap;
use vhost::vhost_user::message::*;
use vhost::vhost_user::VhostUserMaster;
use virtio_gen::virtio_blk::{VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_RO, VIRTIO_F_VERSION_1};
use virtio_gen::virtio_ring::VIRTIO_RING_F_EVENT_IDX;

use super::{BlockVhostUserError, NUM_QUEUES, QUEUE_SIZE};
use crate::arch::DeviceSubtype;
use crate::devices::virtio::queue::Queue;
use crate::devices::virtio::vhost_user::VhostUserHandle;
use crate::devices::virtio::{
    ActivateError, CacheType, DeviceState, Disk, DiskAttributes, IrqTrigger, VirtioDevice,
    SUBTYPE_BLOCK_VHOST_USER, TYPE_BLOCK,
};

/// Block device config space size in bytes.
const BLOCK_CONFIG_SPACE_SIZE: usize = 60;

/// vhost-user block device.
#[derive(Debug)]
pub struct BlockVhostUser {
    // Virtio fields.
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) config_space: Vec<u8>,
    pub(crate) activate_evt: EventFd,

    // Transport related fields.
    pub(crate) queues: Vec<Queue>,
    pub(crate) queue_evts: [EventFd; NUM_QUEUES as usize],
    pub(crate) device_state: DeviceState,
    pub(crate) irq_trigger: IrqTrigger,

    // Disk attributes
    pub(crate) disk_attrs: DiskAttributes,

    // Vhost user protocol handle
    pub(crate) vu_handle: VhostUserHandle,
}

impl BlockVhostUser {
    pub fn new(
        id: String,
        partuuid: Option<String>,
        cache_type: CacheType,
        is_disk_root: bool,
        vhost_user_socket: &str,
    ) -> Result<Self, BlockVhostUserError> {
        let mut vu = VhostUserHandle::connect_vhost_user(vhost_user_socket, NUM_QUEUES)
            .map_err(BlockVhostUserError::VhostUser)?;

        let mut avail_features = (1 << VIRTIO_F_VERSION_1)
            | (1 << VIRTIO_RING_F_EVENT_IDX)
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

        if cache_type == CacheType::Writeback {
            avail_features |= 1u64 << VIRTIO_BLK_F_FLUSH;
        }

        // We always try to negotiate readonly with the backend.
        // If the backend is configured as readonly, we will accept it.
        avail_features |= 1u64 << VIRTIO_BLK_F_RO;

        let avail_protocol_features =
            VhostUserProtocolFeatures::CONFIG | VhostUserProtocolFeatures::REPLY_ACK;

        let (mut acked_features, acked_protocol_features) = vu
            .negotiate_features_vhost_user(avail_features, avail_protocol_features)
            .map_err(BlockVhostUserError::VhostUser)?;

        vu.acked_protocol_features = acked_protocol_features;

        let queue_evts = [EventFd::new(libc::EFD_NONBLOCK).map_err(BlockVhostUserError::EventFd)?;
            NUM_QUEUES as usize];

        let queue_sizes: &[u16] = &[QUEUE_SIZE];
        let queues = queue_sizes.iter().map(|&s| Queue::new(s)).collect();

        let config_space: Vec<u8> = vec![0u8; BLOCK_CONFIG_SPACE_SIZE];
        let (_, config_space) = vu
            .socket_handle()
            .get_config(
                VHOST_USER_CONFIG_OFFSET,
                config_space.len() as u32,
                VhostUserConfigFlags::WRITABLE,
                config_space.as_slice(),
            )
            .map_err(BlockVhostUserError::Vhost)?;

        let is_disk_read_only = acked_features & (1 << VIRTIO_BLK_F_RO) != 0;
        let disk_attrs =
            DiskAttributes::new(id, partuuid, cache_type, is_disk_read_only, is_disk_root);

        avail_features = acked_features;
        acked_features &= VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

        Ok(Self {
            avail_features,
            acked_features,
            config_space,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(BlockVhostUserError::EventFd)?,
            queues,
            queue_evts,
            device_state: DeviceState::Inactive,
            irq_trigger: IrqTrigger::new().map_err(BlockVhostUserError::IrqTrigger)?,
            disk_attrs,
            vu_handle: vu,
        })
    }

    /// Provides backing vhost user path of this block device.
    pub fn socket(&self) -> &String {
        &self.vu_handle.socket_path
    }

    /// Prepare device for being snapshotted.
    pub fn prepare_save(&mut self) {}

    /// Set up vhost-user connection.
    pub fn setup_vhost_user(&mut self, mem: &GuestMemoryMmap) -> Result<(), BlockVhostUserError> {
        self.vu_handle
            .setup_vhost_user(
                mem,
                [(0, &self.queues[0], &self.queue_evts[0])].to_vec(),
                &self.irq_trigger,
                self.acked_features,
            )
            .map_err(BlockVhostUserError::VhostUser)
    }

    /// Provides non-mutable reference to this device's block.
    pub fn block(&self) -> &DiskAttributes {
        &self.disk_attrs
    }
}

impl VirtioDevice for BlockVhostUser {
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

    fn device_subtype(&self) -> DeviceSubtype {
        SUBTYPE_BLOCK_VHOST_USER
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
    fn interrupt_status(&self) -> Arc<AtomicUsize> {
        self.irq_trigger.irq_status.clone()
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_len = self.config_space.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            METRICS.block.cfg_fails.inc();
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&self.config_space[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        // We do not advertise VIRTIO_BLK_F_CONFIG_WCE
        // that would allow configuring the "writeback" field.
        // Other block config fields are immutable.
    }

    fn activate(&mut self, mem: GuestMemoryMmap) -> Result<(), ActivateError> {
        self.vu_handle
            .setup_vhost_user(
                &mem,
                [(0, &self.queues[0], &self.queue_evts[0])].to_vec(),
                &self.irq_trigger,
                self.acked_features,
            )
            .map_err(|err| {
                METRICS.block.activate_fails.inc();
                ActivateError::VhostUser(err)
            })?;
        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn can_update_interrupt_status(&self) -> bool {
        false
    }
}

impl Disk for BlockVhostUser {
    /// Provides the ID of this block device.
    fn id(&self) -> &String {
        self.block().id()
    }

    /// Provides the PARTUUID of this block device.
    fn partuuid(&self) -> Option<&String> {
        self.block().partuuid()
    }

    /// Specifies if this block device is read only.
    fn is_read_only(&self) -> bool {
        self.block().is_read_only()
    }

    /// Specifies if this block device is read only.
    fn is_root_device(&self) -> bool {
        self.block().is_root_device()
    }

    /// Specifies block device cache type.
    fn cache_type(&self) -> CacheType {
        self.block().cache_type()
    }
}
