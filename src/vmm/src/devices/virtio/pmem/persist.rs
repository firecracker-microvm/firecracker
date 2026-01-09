// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use vm_memory::GuestAddress;

use super::device::{ConfigSpace, Pmem, PmemError};
use crate::Vm;
use crate::devices::virtio::device::{DeviceState, VirtioDeviceType};
use crate::devices::virtio::persist::{PersistError as VirtioStateError, VirtioDeviceState};
use crate::devices::virtio::pmem::{PMEM_NUM_QUEUES, PMEM_QUEUE_SIZE};
use crate::snapshot::Persist;
use crate::vmm_config::pmem::PmemConfig;
use crate::vstate::memory::{GuestMemoryMmap, GuestRegionMmap};
use crate::vstate::vm::VmError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PmemState {
    pub virtio_state: VirtioDeviceState,
    pub config_space: ConfigSpace,
    pub config: PmemConfig,
}

#[derive(Debug)]
pub struct PmemConstructorArgs<'a> {
    pub mem: &'a GuestMemoryMmap,
    pub vm: &'a Vm,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum PmemPersistError {
    /// Error resetting VirtIO state: {0}
    VirtioState(#[from] VirtioStateError),
    /// Error creating Pmem devie: {0}
    Pmem(#[from] PmemError),
    /// Error registering memory region: {0}
    Vm(#[from] VmError),
}

impl<'a> Persist<'a> for Pmem {
    type State = PmemState;
    type ConstructorArgs = PmemConstructorArgs<'a>;
    type Error = PmemPersistError;

    fn save(&self) -> Self::State {
        PmemState {
            virtio_state: VirtioDeviceState::from_device(self),
            config_space: self.config_space,
            config: self.config.clone(),
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

        let mut pmem = Pmem::new_with_queues(state.config.clone(), queues)?;
        pmem.config_space = state.config_space;
        pmem.avail_features = state.virtio_state.avail_features;
        pmem.acked_features = state.virtio_state.acked_features;

        pmem.set_mem_region(constructor_args.vm)?;

        Ok(pmem)
    }
}

#[cfg(test)]
mod tests {
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::arch::Kvm;
    use crate::devices::virtio::device::VirtioDevice;
    use crate::devices::virtio::test_utils::default_mem;

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
        };
        let pmem = Pmem::new(config).unwrap();
        let guest_mem = default_mem();
        let kvm = Kvm::new(vec![]).unwrap();
        let vm = Vm::new(&kvm).unwrap();

        // Save the block device.
        let pmem_state = pmem.save();
        let serialized_data = bitcode::serialize(&pmem_state).unwrap();

        // Restore the block device.
        let restored_state = bitcode::deserialize(&serialized_data).unwrap();
        let restored_pmem = Pmem::restore(
            PmemConstructorArgs {
                mem: &guest_mem,
                vm: &vm,
            },
            &restored_state,
        )
        .unwrap();

        // Test that virtio specific fields are the same.
        assert_eq!(restored_pmem.device_type(), VirtioDeviceType::Pmem);
        assert_eq!(restored_pmem.avail_features(), pmem.avail_features());
        assert_eq!(restored_pmem.acked_features(), pmem.acked_features());
        assert_eq!(restored_pmem.queues(), pmem.queues());
        assert!(!pmem.is_activated());
        assert!(!restored_pmem.is_activated());
        assert_eq!(restored_pmem.config, pmem.config);
    }
}
