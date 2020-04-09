// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the structures needed for saving/restoring Virtio primitives.

use super::queue::*;
use crate::vm_memory::Address;
use snapshot::Persist;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
use vm_memory::GuestAddress;

use std::num::Wrapping;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_persistence() {
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
}
