// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use event_manager::{EventOps, Events, MutEventSubscriber};
use utils::eventfd::EventFd;

use super::persist::{BlockConstructorArgs, BlockState};
use super::vhost_user::device::{VhostUserBlock, VhostUserBlockConfig};
use super::virtio::device::{VirtioBlock, VirtioBlockConfig};
use super::BlockError;
use crate::devices::virtio::device::{IrqTrigger, VirtioDevice};
use crate::devices::virtio::queue::Queue;
use crate::devices::virtio::{ActivateError, TYPE_BLOCK};
use crate::rate_limiter::BucketUpdate;
use crate::snapshot::Persist;
use crate::vmm_config::drive::BlockDeviceConfig;
use crate::vstate::memory::GuestMemoryMmap;

// Clippy thinks that values of the enum are too different in size.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Block {
    Virtio(VirtioBlock),
    VhostUser(VhostUserBlock),
}

impl Block {
    pub fn new(config: BlockDeviceConfig) -> Result<Block, BlockError> {
        if let Ok(config) = VirtioBlockConfig::try_from(&config) {
            Ok(Self::Virtio(
                VirtioBlock::new(config).map_err(BlockError::VirtioBackend)?,
            ))
        } else if let Ok(config) = VhostUserBlockConfig::try_from(&config) {
            Ok(Self::VhostUser(
                VhostUserBlock::new(config).map_err(BlockError::VhostUserBackend)?,
            ))
        } else {
            return Err(BlockError::InvalidBlockConfig);
        }
    }

    pub fn config(&self) -> BlockDeviceConfig {
        match self {
            Self::Virtio(b) => b.config().into(),
            Self::VhostUser(b) => b.config().into(),
        }
    }

    pub fn update_disk_image(&mut self, disk_image_path: String) -> Result<(), BlockError> {
        match self {
            Self::Virtio(b) => b
                .update_disk_image(disk_image_path)
                .map_err(BlockError::VirtioBackend),
            Self::VhostUser(_) => Err(BlockError::InvalidBlockBackend),
        }
    }

    pub fn update_rate_limiter(
        &mut self,
        bytes: BucketUpdate,
        ops: BucketUpdate,
    ) -> Result<(), BlockError> {
        match self {
            Self::Virtio(b) => {
                b.update_rate_limiter(bytes, ops);
                Ok(())
            }
            Self::VhostUser(_) => Err(BlockError::InvalidBlockBackend),
        }
    }

    pub fn update_config(&mut self) -> Result<(), BlockError> {
        match self {
            Self::Virtio(_) => Err(BlockError::InvalidBlockBackend),
            Self::VhostUser(b) => b.config_update().map_err(BlockError::VhostUserBackend),
        }
    }

    pub fn prepare_save(&mut self) {
        match self {
            Self::Virtio(b) => b.prepare_save(),
            Self::VhostUser(b) => b.prepare_save(),
        }
    }

    pub fn process_virtio_queues(&mut self) {
        match self {
            Self::Virtio(b) => b.process_virtio_queues(),
            Self::VhostUser(_) => {}
        }
    }

    pub fn id(&self) -> &str {
        match self {
            Self::Virtio(b) => &b.id,
            Self::VhostUser(b) => &b.id,
        }
    }

    pub fn root_device(&self) -> bool {
        match self {
            Self::Virtio(b) => b.root_device,
            Self::VhostUser(b) => b.root_device,
        }
    }

    pub fn read_only(&self) -> bool {
        match self {
            Self::Virtio(b) => b.read_only,
            Self::VhostUser(b) => b.read_only,
        }
    }

    pub fn partuuid(&self) -> &Option<String> {
        match self {
            Self::Virtio(b) => &b.partuuid,
            Self::VhostUser(b) => &b.partuuid,
        }
    }

    pub fn is_vhost_user(&self) -> bool {
        match self {
            Self::Virtio(_) => false,
            Self::VhostUser(_) => true,
        }
    }
}

impl VirtioDevice for Block {
    fn avail_features(&self) -> u64 {
        match self {
            Self::Virtio(b) => b.avail_features,
            Self::VhostUser(b) => b.avail_features,
        }
    }

    fn acked_features(&self) -> u64 {
        match self {
            Self::Virtio(b) => b.acked_features,
            Self::VhostUser(b) => b.acked_features,
        }
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        match self {
            Self::Virtio(b) => b.acked_features = acked_features,
            Self::VhostUser(b) => b.acked_features = acked_features,
        }
    }

    fn device_type(&self) -> u32 {
        TYPE_BLOCK
    }

    fn queues(&self) -> &[Queue] {
        match self {
            Self::Virtio(b) => &b.queues,
            Self::VhostUser(b) => &b.queues,
        }
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        match self {
            Self::Virtio(b) => &mut b.queues,
            Self::VhostUser(b) => &mut b.queues,
        }
    }

    fn queue_events(&self) -> &[EventFd] {
        match self {
            Self::Virtio(b) => &b.queue_evts,
            Self::VhostUser(b) => &b.queue_evts,
        }
    }

    fn interrupt_trigger(&self) -> &IrqTrigger {
        match self {
            Self::Virtio(b) => &b.irq_trigger,
            Self::VhostUser(b) => &b.irq_trigger,
        }
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        match self {
            Self::Virtio(b) => b.read_config(offset, data),
            Self::VhostUser(b) => b.read_config(offset, data),
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        match self {
            Self::Virtio(b) => b.write_config(offset, data),
            Self::VhostUser(b) => b.write_config(offset, data),
        }
    }

    fn activate(&mut self, mem: GuestMemoryMmap) -> Result<(), ActivateError> {
        match self {
            Self::Virtio(b) => b.activate(mem),
            Self::VhostUser(b) => b.activate(mem),
        }
    }

    fn is_activated(&self) -> bool {
        match self {
            Self::Virtio(b) => b.device_state.is_activated(),
            Self::VhostUser(b) => b.device_state.is_activated(),
        }
    }
}

impl MutEventSubscriber for Block {
    fn process(&mut self, event: Events, ops: &mut EventOps) {
        match self {
            Self::Virtio(b) => b.process(event, ops),
            Self::VhostUser(b) => b.process(event, ops),
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        match self {
            Self::Virtio(b) => b.init(ops),
            Self::VhostUser(b) => b.init(ops),
        }
    }
}

impl Persist<'_> for Block {
    type State = BlockState;
    type ConstructorArgs = BlockConstructorArgs;
    type Error = BlockError;

    fn save(&self) -> Self::State {
        match self {
            Self::Virtio(b) => BlockState::Virtio(b.save()),
            Self::VhostUser(b) => BlockState::VhostUser(b.save()),
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        match state {
            BlockState::Virtio(s) => Ok(Self::Virtio(
                VirtioBlock::restore(constructor_args, s).map_err(BlockError::VirtioBackend)?,
            )),
            BlockState::VhostUser(s) => Ok(Self::VhostUser(
                VhostUserBlock::restore(constructor_args, s)
                    .map_err(BlockError::VhostUserBackend)?,
            )),
        }
    }
}
