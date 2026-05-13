// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use vm_memory::GuestAddress;

use super::device::{ConfigSpace, Pmem, PmemError};
use crate::devices::virtio::device::{DeviceState, VirtioDeviceType};
use crate::devices::virtio::persist::{PersistError as VirtioStateError, VirtioDeviceState};
use crate::devices::virtio::pmem::{PMEM_NUM_QUEUES, PMEM_QUEUE_SIZE};
use crate::rate_limiter::RateLimiter;
use crate::rate_limiter::persist::RateLimiterState;
use crate::snapshot::Persist;
use crate::vmm_config::pmem::PmemConfig;
use crate::vstate::memory::{GuestMemoryMmap, GuestRegionMmap};
use crate::vstate::vm::{KvmVm, VmError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PmemState {
    pub virtio_state: VirtioDeviceState,
    pub config_space: ConfigSpace,
    pub config: PmemConfig,
    pub rate_limiter_state: RateLimiterState,
}

#[derive(Debug)]
pub struct PmemConstructorArgs<'a> {
    pub mem: &'a GuestMemoryMmap,
    pub vm: Arc<KvmVm>,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum PmemPersistError {
    /// Error resetting VirtIO state: {0}
    VirtioState(#[from] VirtioStateError),
    /// Error creating Pmem devie: {0}
    Pmem(#[from] PmemError),
    /// Error registering memory region: {0}
    KvmVm(#[from] VmError),
    /// Error restoring rate limiter: {0}
    RateLimiter(std::io::Error),
}

impl<'a> Persist<'a> for Pmem {
    type State = PmemState;
    type ConstructorArgs = PmemConstructorArgs<'a>;
    type Error = PmemPersistError;

    fn save(&self) -> Self::State {
        PmemState {
            virtio_state: VirtioDeviceState::from_device(self),
            config_space: self.guest_region.config_space,
            config: self.config.clone(),
            rate_limiter_state: self.rate_limiter.save(),
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        let queues = state.virtio_state.build_queues_checked(
            constructor_args.mem,
            VirtioDeviceType::Pmem,
            PMEM_NUM_QUEUES,
            PMEM_QUEUE_SIZE,
        )?;

        let mut pmem = Pmem::new_with_queues(
            constructor_args.vm,
            state.config.clone(),
            queues,
            state.virtio_state.acked_features,
            Some(state.config_space),
        )?;
        pmem.rate_limiter = RateLimiter::restore((), &state.rate_limiter_state)
            .map_err(PmemPersistError::RateLimiter)?;

        Ok(pmem)
    }
}

#[cfg(test)]
mod tests {
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::devices::virtio::device::VirtioDevice;
    use crate::devices::virtio::test_utils::default_mem;
    use crate::vstate::vm::tests::setup_vm;

    #[test]
    fn test_persistence() {
        // We create the backing file here so that it exists for the whole lifetime of the test.
        let dummy_file = TempFile::new().unwrap();
        dummy_file.as_file().set_len(0x20_0000);
        let dummy_path = dummy_file.as_path().to_str().unwrap().to_string();
        let config = PmemConfig {
            id: "1".into(),
            path_on_host: dummy_path,
            root_device: true,
            read_only: false,
            ..Default::default()
        };
        let guest_mem = default_mem();
        let vm = Arc::new(setup_vm());
        let pmem = Pmem::new(vm.clone(), config).unwrap();

        // Save the block device.
        let pmem_state = pmem.save();
        let serialized_data = bitcode::serialize(&pmem_state).unwrap();
        drop(pmem);

        // Restore the block device.
        let restored_state = bitcode::deserialize(&serialized_data).unwrap();
        let restored_pmem = Pmem::restore(
            PmemConstructorArgs {
                mem: &guest_mem,
                vm: vm.clone(),
            },
            &restored_state,
        )
        .unwrap();

        // Test that virtio specific fields are the same.
        assert_eq!(restored_pmem.device_type(), VirtioDeviceType::Pmem);
        assert_eq!(
            restored_pmem.avail_features(),
            pmem_state.virtio_state.avail_features
        );
        assert_eq!(
            restored_pmem.acked_features(),
            pmem_state.virtio_state.acked_features
        );
        assert!(!restored_pmem.is_activated());
        assert_eq!(restored_pmem.config, pmem_state.config);
    }
}
