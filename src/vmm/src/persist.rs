// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines state structures for saving/restoring a Firecracker microVM.

// Currently only supports x86_64.
#![cfg(target_arch = "x86_64")]

use crate::device_manager::persist::DeviceStates;
use crate::vstate::{VcpuState, VmState};

use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;

/// Holds information related to the VM that is not part of VmState.
#[derive(Debug, PartialEq, Versionize)]
pub struct VmInfo {
    /// Guest memory size.
    pub mem_size_mib: u64,
}

/// Contains the necesary state for saving/restoring a microVM.
#[derive(Versionize)]
pub struct MicrovmState {
    /// Miscellaneous VM info.
    pub vm_info: VmInfo,
    /// VM KVM state.
    pub vm_state: VmState,
    /// Vcpu states.
    pub vcpu_states: Vec<VcpuState>,
    /// Device states.
    pub device_states: DeviceStates,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::tests::{
        default_kernel_cmdline, default_vmm, insert_block_devices, insert_net_device,
        insert_vsock_device, CustomBlockConfig,
    };
    use crate::vstate::tests::default_vcpu_state;
    use crate::Vmm;
    use polly::event_manager::EventManager;
    use snapshot::Persist;
    use utils::tempfile::TempFile;
    use vmm_config::net::NetworkInterfaceConfig;
    use vmm_config::vsock::tests::{default_config, TempSockFile};

    fn default_vmm_with_devices(event_manager: &mut EventManager) -> Vmm {
        let mut vmm = default_vmm();
        let mut cmdline = default_kernel_cmdline();

        // Add a block device.
        let drive_id = String::from("root");
        let block_configs = vec![CustomBlockConfig::new(drive_id.clone(), true, None, true)];
        insert_block_devices(&mut vmm, &mut cmdline, event_manager, block_configs);

        // Add net device.
        let network_interface = NetworkInterfaceConfig {
            iface_id: String::from("netif"),
            host_dev_name: String::from("hostname"),
            guest_mac: None,
            rx_rate_limiter: None,
            tx_rate_limiter: None,
            allow_mmds_requests: true,
        };
        insert_net_device(&mut vmm, &mut cmdline, event_manager, network_interface);

        // Add vsock device.
        let tmp_sock_file = TempSockFile::new(TempFile::new().unwrap());
        let vsock_config = default_config(&tmp_sock_file);

        insert_vsock_device(&mut vmm, &mut cmdline, event_manager, vsock_config);

        vmm
    }

    #[test]
    fn test_microvmstate_versionize() {
        let mut event_manager = EventManager::new().expect("Unable to create EventManager");
        let vmm = default_vmm_with_devices(&mut event_manager);
        let states = vmm.mmio_device_manager.save();

        // Only checking that all devices are saved, actual device state
        // is tested by that device's tests.
        assert_eq!(states.block_devices.len(), 1);
        assert_eq!(states.net_devices.len(), 1);
        assert!(states.vsock_device.is_some());

        let microvm_state = MicrovmState {
            vm_info: VmInfo { mem_size_mib: 1u64 },
            vm_state: vmm.vm.save_state().unwrap(),
            vcpu_states: vec![default_vcpu_state()],
            device_states: states,
        };

        let mut buf = vec![0; 10000];
        let version_map = VersionMap::new();

        microvm_state
            .serialize(&mut buf.as_mut_slice(), &version_map, 1)
            .unwrap();

        let restored_microvm_state =
            MicrovmState::deserialize(&mut buf.as_slice(), &version_map, 1).unwrap();

        assert_eq!(restored_microvm_state.vm_info, microvm_state.vm_info);
        assert_eq!(
            restored_microvm_state.device_states,
            microvm_state.device_states
        )
    }
}
