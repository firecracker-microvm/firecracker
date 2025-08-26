// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the structures needed for saving/restoring virtio-mem devices.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use vm_memory::Address;

use crate::Vm;
use crate::devices::virtio::generated::virtio_ids::VIRTIO_ID_MEM;
use crate::devices::virtio::generated::virtio_mem::virtio_mem_config;
use crate::devices::virtio::mem::{
    MEM_NUM_QUEUES, VIRTIO_MEM_GUEST_ADDRESS, VirtioMem, VirtioMemError,
};
use crate::devices::virtio::persist::{PersistError as VirtioStateError, VirtioDeviceState};
use crate::devices::virtio::queue::FIRECRACKER_MAX_QUEUE_SIZE;
use crate::snapshot::Persist;
use crate::vstate::memory::{GuestMemoryMmap, GuestRegionMmap};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtioMemState {
    pub virtio_state: VirtioDeviceState,
    region_size: u64,
    block_size: u64,
    usable_region_size: u64,
    plugged_size: u64,
    requested_size: u64,
    slot_size: usize,
}

#[derive(Debug)]
pub struct VirtioMemConstructorArgs {
    vm: Arc<Vm>,
}

impl VirtioMemConstructorArgs {
    pub fn new(vm: Arc<Vm>) -> Self {
        Self { vm }
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
            region_size: self.config.region_size,
            block_size: self.config.block_size,
            usable_region_size: self.config.usable_region_size,
            plugged_size: self.config.plugged_size,
            requested_size: self.config.requested_size,
            slot_size: self.slot_size,
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        let queues = state.virtio_state.build_queues_checked(
            constructor_args.vm.guest_memory(),
            VIRTIO_ID_MEM,
            MEM_NUM_QUEUES,
            FIRECRACKER_MAX_QUEUE_SIZE,
        )?;

        let config = virtio_mem_config {
            addr: VIRTIO_MEM_GUEST_ADDRESS.raw_value(),
            region_size: state.region_size,
            block_size: state.block_size,
            usable_region_size: state.usable_region_size,
            plugged_size: state.plugged_size,
            requested_size: state.requested_size,
            ..Default::default()
        };

        let mut virtio_mem =
            VirtioMem::from_state(constructor_args.vm, queues, config, state.slot_size)?;
        virtio_mem.set_avail_features(state.virtio_state.avail_features);
        virtio_mem.set_acked_features(state.virtio_state.acked_features);

        Ok(virtio_mem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::virtio::device::VirtioDevice;
    use crate::devices::virtio::mem::device::test_utils::default_virtio_mem;
    use crate::vstate::vm::tests::setup_vm_with_memory;

    #[test]
    fn test_save_state() {
        let dev = default_virtio_mem();
        let state = dev.save();

        assert_eq!(state.region_size, dev.config.region_size);
        assert_eq!(state.block_size, dev.config.block_size);
        assert_eq!(state.usable_region_size, dev.config.usable_region_size);
        assert_eq!(state.plugged_size, dev.config.plugged_size);
        assert_eq!(state.requested_size, dev.config.requested_size);
        assert_eq!(state.slot_size, dev.slot_size);
    }

    #[test]
    fn test_save_restore_state() {
        let mut original_dev = default_virtio_mem();
        original_dev.set_acked_features(original_dev.avail_features());
        let state = original_dev.save();

        // Create a "new" VM for restore
        let (_, vm) = setup_vm_with_memory(0x1000);
        let vm = Arc::new(vm);
        let constructor_args = VirtioMemConstructorArgs::new(vm);
        let restored_dev = VirtioMem::restore(constructor_args, &state).unwrap();

        assert_eq!(original_dev.config, restored_dev.config);
        assert_eq!(original_dev.slot_size, restored_dev.slot_size);
        assert_eq!(original_dev.avail_features(), restored_dev.avail_features());
        assert_eq!(original_dev.acked_features(), restored_dev.acked_features());
    }
}
