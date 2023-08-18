// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the structures needed for saving/restoring block devices.

use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use snapshot::Persist;
use utils::eventfd::EventFd;
use utils::vm_memory::GuestMemoryMmap;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
use virtio_gen::virtio_blk::VIRTIO_BLK_F_RO;

use super::{BlockVhostUser, BlockVhostUserError};
use crate::devices::virtio::block::vhost_user::{NUM_QUEUES, QUEUE_SIZE};
use crate::devices::virtio::block::CacheTypeState;
use crate::devices::virtio::persist::VirtioDeviceState;
use crate::devices::virtio::vhost_user::VhostUserHandle;
use crate::devices::virtio::{DeviceState, Disk, DiskAttributes, IrqTrigger, TYPE_BLOCK};

/// vhost-user block device state.
// NOTICE: Any changes to this structure require a snapshot version bump.
#[derive(Debug, Clone, Versionize)]
pub struct BlockVhostUserState {
    id: String,
    partuuid: Option<String>,
    cache_type: CacheTypeState,
    root_device: bool,
    socket_path: String,
    acked_protocol_features: u64,
    config_space: Vec<u8>,
    virtio_state: VirtioDeviceState,
}

/// Auxiliary structure for creating a device when resuming from a snapshot.
#[derive(Debug)]
pub struct BlockVhostUserConstructorArgs {
    pub mem: GuestMemoryMmap,
}

impl Persist<'_> for BlockVhostUser {
    type State = BlockVhostUserState;
    type ConstructorArgs = BlockVhostUserConstructorArgs;
    type Error = BlockVhostUserError;

    fn save(&self) -> Self::State {
        // Save device state.
        BlockVhostUserState {
            id: self.id().clone(),
            partuuid: self.partuuid().cloned(),
            cache_type: CacheTypeState::from(self.block().cache_type()),
            root_device: self.is_root_device(),
            socket_path: self.socket().clone(),
            acked_protocol_features: self.vu_handle.acked_protocol_features,
            config_space: self.config_space.clone(),
            virtio_state: VirtioDeviceState::from_device(self),
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        let is_disk_read_only = state.virtio_state.avail_features & (1u64 << VIRTIO_BLK_F_RO) != 0;

        let queue_evts = [EventFd::new(libc::EFD_NONBLOCK).map_err(BlockVhostUserError::EventFd)?;
            NUM_QUEUES as usize];

        let disk_attrs = DiskAttributes::new(
            state.id.clone(),
            state.partuuid.clone(),
            state.cache_type.into(),
            is_disk_read_only,
            state.root_device,
        );

        let vu = VhostUserHandle::connect_vhost_user(state.socket_path.as_str(), NUM_QUEUES)
            .map_err(BlockVhostUserError::VhostUser)?;

        let mut irq_trigger = IrqTrigger::new().map_err(BlockVhostUserError::IrqTrigger)?;
        irq_trigger.irq_status = Arc::new(AtomicUsize::new(state.virtio_state.interrupt_status));

        let mut block = Self {
            avail_features: state.virtio_state.avail_features,
            acked_features: state.virtio_state.acked_features,
            config_space: state.config_space.clone(),
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(BlockVhostUserError::EventFd)?,
            queues: state
                .virtio_state
                .build_queues_checked(
                    &constructor_args.mem,
                    TYPE_BLOCK,
                    NUM_QUEUES as usize,
                    QUEUE_SIZE,
                )
                .map_err(BlockVhostUserError::Persist)?,
            queue_evts,
            device_state: DeviceState::Inactive,
            irq_trigger,
            disk_attrs,
            vu_handle: vu,
        };

        if state.virtio_state.activated {
            block.device_state = DeviceState::Activated(constructor_args.mem.clone());
        }

        block
            .vu_handle
            .set_protocol_features_vhost_user(
                block.acked_features,
                block.vu_handle.acked_protocol_features,
            )
            .map_err(BlockVhostUserError::VhostUser)?;

        block.setup_vhost_user(&constructor_args.mem)?;

        Ok(block)
    }
}
