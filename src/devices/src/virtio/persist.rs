// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the structures needed for saving/restoring Virtio primitives.

use super::device::*;
use super::queue::*;
use crate::vm_memory::Address;
use snapshot::Persist;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
use vm_memory::GuestAddress;

use std::num::Wrapping;
use std::sync::atomic::Ordering;

#[derive(Clone, Debug, PartialEq, Versionize)]
pub struct QueueState {
    /// The maximal size in elements offered by the device
    max_size: u16,

    /// The queue size in elements the driver selected
    size: u16,

    /// Indicates if the queue is finished with configuration
    ready: bool,

    /// Guest physical address of the descriptor table
    desc_table: u64,

    /// Guest physical address of the available ring
    avail_ring: u64,

    /// Guest physical address of the used ring
    used_ring: u64,

    next_avail: Wrapping<u16>,
    next_used: Wrapping<u16>,
}

impl Persist for Queue {
    type State = QueueState;
    type ConstructorArgs = ();
    type Error = ();

    fn save(&self) -> Self::State {
        QueueState {
            max_size: self.max_size,
            size: self.size,
            ready: self.ready,
            desc_table: self.desc_table.0,
            avail_ring: self.avail_ring.0,
            used_ring: self.used_ring.0,
            next_avail: self.next_avail,
            next_used: self.next_used,
        }
    }

    fn restore(
        _: Self::ConstructorArgs,
        state: &Self::State,
    ) -> std::result::Result<Self, Self::Error> {
        Ok(Queue {
            max_size: state.max_size,
            size: state.size,
            ready: state.ready,
            desc_table: GuestAddress::new(state.desc_table),
            avail_ring: GuestAddress::new(state.avail_ring),
            used_ring: GuestAddress::new(state.used_ring),
            next_avail: state.next_avail,
            next_used: state.next_used,
        })
    }
}

/// State of a VirtioDevice.
#[derive(Debug, PartialEq, Versionize)]
pub struct VirtioDeviceState {
    pub avail_features: u64,
    pub acked_features: u64,
    pub queues: Vec<QueueState>,
    pub interrupt_status: usize,
    pub activated: bool,
}

impl VirtioDeviceState {
    pub fn from_device(device: &dyn VirtioDevice) -> Self {
        VirtioDeviceState {
            avail_features: device.avail_features(),
            acked_features: device.acked_features(),
            queues: device.queues().iter().map(Persist::save).collect(),
            interrupt_status: device.interrupt_status().load(Ordering::Relaxed),
            activated: device.is_activated(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio::mmio::tests::DummyDevice;

    #[test]
    fn test_persistance() {
        let queue = Queue::new(128);

        let mut mem = vec![0; 4096];
        let version_map = VersionMap::new();

        queue
            .save()
            .serialize(&mut mem.as_mut_slice(), &version_map, 1)
            .unwrap();

        let restored_queue = Queue::restore(
            (),
            &QueueState::deserialize(&mut mem.as_slice(), &version_map, 1).unwrap(),
        )
        .unwrap();

        assert_eq!(restored_queue, queue);
    }

    #[test]
    fn test_virtio_device_state_versionize() {
        let dummy = DummyDevice::new();
        let mut mem = vec![0; 4096];
        let version_map = VersionMap::new();

        let state = VirtioDeviceState::from_device(&dummy);
        state
            .serialize(&mut mem.as_mut_slice(), &version_map, 1)
            .unwrap();

        let restored_state =
            VirtioDeviceState::deserialize(&mut mem.as_slice(), &version_map, 1).unwrap();
        assert_eq!(restored_state, state);
    }
}
