// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the structures needed for saving/restoring virtio-mem devices.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::Vm;
use crate::devices::virtio::TYPE_MEM;
use crate::devices::virtio::mem::{MEM_NUM_QUEUES, VirtioMem, VirtioMemError};
use crate::devices::virtio::persist::{PersistError as VirtioStateError, VirtioDeviceState};
use crate::devices::virtio::queue::FIRECRACKER_MAX_QUEUE_SIZE;
use crate::snapshot::Persist;
use crate::vstate::memory::{GuestMemoryMmap, GuestRegionMmap};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtioMemState {
    virtio_state: VirtioDeviceState,
}

#[derive(Debug)]
pub struct VirtioMemConstructorArgs {
    vm: Arc<Vm>,
    size: usize,
}

impl VirtioMemConstructorArgs {
    pub fn new(vm: Arc<Vm>, size: usize) -> Self {
        Self { vm, size }
    }
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VirtioMemPersistError {
    /// Create virtio-mem: {0}
    CreateVirtioMem(#[from] VirtioMemError),
    /// Virtio state: {0}
    VirtioState(#[from] VirtioStateError),
}

impl Persist<'_> for VirtioMem {
    type State = VirtioMemState;
    type ConstructorArgs = VirtioMemConstructorArgs;
    type Error = VirtioMemPersistError;

    fn save(&self) -> Self::State {
        VirtioMemState {
            virtio_state: VirtioDeviceState::from_device(self),
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        let queues = state.virtio_state.build_queues_checked(
            constructor_args.vm.guest_memory(),
            TYPE_MEM,
            MEM_NUM_QUEUES,
            FIRECRACKER_MAX_QUEUE_SIZE,
        )?;

        let mut virtio_mem =
            VirtioMem::new_with_queues(queues, constructor_args.size, constructor_args.vm)?;
        virtio_mem.set_avail_features(state.virtio_state.avail_features);
        virtio_mem.set_acked_features(state.virtio_state.acked_features);

        Ok(virtio_mem)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::devices::virtio::device::VirtioDevice;
    use crate::devices::virtio::mem::device::VIRTIO_MEM_DEV_ID;
    use crate::devices::virtio::test_utils::test::create_virtio_mem;
    use crate::snapshot::Snapshot;

    #[test]
    fn test_persistence() {
        let mut mem = vec![0u8; 4096];
        let virtio_mem = VirtioMem::new(vm_memory::GuestAddress(0), 0).unwrap();

        Snapshot::serialize(&mut mem.as_mut_slice(), &virtio_mem.save()).unwrap();

        let guest_mem = create_virtio_mem();
        let restored = VirtioMem::restore(
            VirtioMemConstructorArgs(guest_mem),
            &Snapshot::deserialize(&mut mem.as_slice()).unwrap(),
        )
        .unwrap();

        assert_eq!(restored.device_type(), TYPE_MEM);
        assert_eq!(restored.id(), VIRTIO_MEM_DEV_ID);
        assert_eq!(restored.is_activated(), virtio_mem.is_activated());
        assert_eq!(restored.avail_features(), virtio_mem.avail_features());
        assert_eq!(restored.acked_features(), virtio_mem.acked_features());
        assert_eq!(
            restored.interrupt_status().load(Ordering::Relaxed),
            virtio_mem.interrupt_status().load(Ordering::Relaxed)
        );
    }
}
