// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::AtomicU32;
use std::sync::Arc;

use event_manager::{EventOps, Events, MutEventSubscriber};
use utils::eventfd::EventFd;

use super::persist::{BlockConstructorArgs, BlockState};
use super::virtio::device::{VirtioBlock, VirtioBlockConfig};
use super::BlockError;
use crate::devices::virtio::device::VirtioDevice;
use crate::devices::virtio::queue::Queue;
use crate::devices::virtio::{ActivateError, TYPE_BLOCK};
use crate::rate_limiter::BucketUpdate;
use crate::snapshot::Persist;
use crate::vstate::memory::GuestMemoryMmap;

pub type BlockConfig = VirtioBlockConfig;

#[derive(Debug)]
pub enum Block {
    Virtio(VirtioBlock),
}

impl Block {
    pub fn new(config: BlockConfig) -> Result<Block, BlockError> {
        Ok(Self::Virtio(VirtioBlock::new(config)?))
    }

    pub fn config(&self) -> BlockConfig {
        match self {
            Self::Virtio(b) => b.config(),
        }
    }

    pub fn update_disk_image(&mut self, disk_image_path: String) -> Result<(), BlockError> {
        match self {
            Self::Virtio(b) => b.update_disk_image(disk_image_path),
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
        }
    }

    pub fn prepare_save(&mut self) {
        match self {
            Self::Virtio(b) => b.prepare_save(),
        }
    }

    pub fn process_virtio_queues(&mut self) {
        match self {
            Self::Virtio(b) => b.process_virtio_queues(),
        }
    }

    pub fn id(&self) -> &str {
        match self {
            Self::Virtio(b) => &b.id,
        }
    }

    pub fn root_device(&self) -> bool {
        match self {
            Self::Virtio(b) => b.root_device,
        }
    }

    pub fn read_only(&self) -> bool {
        match self {
            Self::Virtio(b) => b.read_only,
        }
    }

    pub fn partuuid(&self) -> &Option<String> {
        match self {
            Self::Virtio(b) => &b.partuuid,
        }
    }

    pub fn is_vhost_user(&self) -> bool {
        match self {
            Self::Virtio(_) => false,
        }
    }
}

impl VirtioDevice for Block {
    fn avail_features(&self) -> u64 {
        match self {
            Self::Virtio(b) => b.avail_features,
        }
    }

    fn acked_features(&self) -> u64 {
        match self {
            Self::Virtio(b) => b.acked_features,
        }
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        match self {
            Self::Virtio(b) => b.acked_features = acked_features,
        }
    }

    fn device_type(&self) -> u32 {
        TYPE_BLOCK
    }

    fn queues(&self) -> &[Queue] {
        match self {
            Self::Virtio(b) => &b.queues,
        }
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        match self {
            Self::Virtio(b) => &mut b.queues,
        }
    }

    fn queue_events(&self) -> &[EventFd] {
        match self {
            Self::Virtio(b) => &b.queue_evts,
        }
    }

    fn interrupt_evt(&self) -> &EventFd {
        match self {
            Self::Virtio(b) => &b.irq_trigger.irq_evt,
        }
    }

    fn interrupt_status(&self) -> Arc<AtomicU32> {
        match self {
            Self::Virtio(b) => b.irq_trigger.irq_status.clone(),
        }
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        match self {
            Self::Virtio(b) => b.read_config(offset, data),
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        match self {
            Self::Virtio(b) => b.write_config(offset, data),
        }
    }

    fn activate(&mut self, mem: GuestMemoryMmap) -> Result<(), ActivateError> {
        match self {
            Self::Virtio(b) => b.activate(mem),
        }
    }

    fn is_activated(&self) -> bool {
        match self {
            Self::Virtio(b) => b.device_state.is_activated(),
        }
    }
}

impl MutEventSubscriber for Block {
    fn process(&mut self, event: Events, ops: &mut EventOps) {
        match self {
            Self::Virtio(b) => b.process(event, ops),
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        match self {
            Self::Virtio(b) => b.init(ops),
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
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        match state {
            BlockState::Virtio(s) => Ok(Self::Virtio(VirtioBlock::restore(constructor_args, s)?)),
        }
    }
}
