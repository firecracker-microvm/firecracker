// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provides the VersionMap that deals with the microvm state versions.

use std::collections::HashMap;

use devices::virtio::block::persist::BlockState;
use devices::virtio::net::persist::NetConfigSpaceState;
use devices::virtio::QueueState;
use lazy_static::lazy_static;
use versionize::{VersionMap, Versionize};

use crate::device_manager::persist::DeviceStates;
use crate::persist::VmInfo;
#[cfg(target_arch = "x86_64")]
use crate::vstate::vcpu::VcpuState;

/// Snap version for Firecracker v0.23
#[cfg(target_arch = "x86_64")]
pub const FC_V0_23_SNAP_VERSION: u16 = 1;
/// Snap version for Firecracker v0.24
pub const FC_V0_24_SNAP_VERSION: u16 = 2;
/// Snap version for Firecracker v0.25
pub const FC_V0_25_SNAP_VERSION: u16 = 3;
/// Snap version for Firecracker v1.0
pub const FC_V1_0_SNAP_VERSION: u16 = 4;
/// Snap version for Firecracker v1.1
pub const FC_V1_1_SNAP_VERSION: u16 = 5;
/// Snap version for Firecracker v1.2
pub const FC_V1_2_SNAP_VERSION: u16 = 6;

lazy_static! {
    // Note: until we have a better design, this needs to be updated when the version changes.
    /// Static instance used for handling microVM state versions.
    pub static ref VERSION_MAP: VersionMap = {
        // v0.23 - all structs and root version are set to 1.
        let mut version_map = VersionMap::new();

        // v0.24 state change mappings.
        version_map.new_version().set_type_version(DeviceStates::type_id(), 2);

        // v0.25 state change mappings.
        version_map.new_version().set_type_version(BlockState::type_id(), 2);
        #[cfg(target_arch = "x86_64")]
        version_map.set_type_version(VcpuState::type_id(), 2);

        // v1.0 state change mappings.
        version_map.new_version().set_type_version(QueueState::type_id(), 2);
        version_map.set_type_version(BlockState::type_id(), 3);

        // v1.1 state change mappings.
        version_map.new_version().set_type_version(DeviceStates::type_id(), 3);

        // v1.2 state change mappings.
        version_map.new_version().set_type_version(VmInfo::type_id(), 2);
        version_map.set_type_version(NetConfigSpaceState::type_id(), 2);
        #[cfg(target_arch = "x86_64")]
        version_map.set_type_version(VcpuState::type_id(), 3);

        version_map
    };

    /// Static instance used for creating a 1:1 mapping between Firecracker release version
    /// and snapshot data format version.
    pub static ref FC_VERSION_TO_SNAP_VERSION: HashMap<String, u16> = {
        let mut mapping = HashMap::new();
        #[cfg(not(target_arch = "aarch64"))]
        mapping.insert(String::from("0.23.0"), FC_V0_23_SNAP_VERSION);

        mapping.insert(String::from("0.24.0"), FC_V0_24_SNAP_VERSION);
        mapping.insert(String::from("0.25.0"), FC_V0_25_SNAP_VERSION);
        mapping.insert(String::from("1.0.0"), FC_V1_0_SNAP_VERSION);
        mapping.insert(String::from("1.1.0"), FC_V1_1_SNAP_VERSION);
        mapping.insert(String::from("1.2.0"), FC_V1_2_SNAP_VERSION);

        mapping
    };
}
