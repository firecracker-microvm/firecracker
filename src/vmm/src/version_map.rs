// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provides the VersionMap that deals with the microvm state versions.

use std::collections::HashMap;

use crate::device_manager::persist::DeviceStates;
#[cfg(target_arch = "x86_64")]
use crate::vstate::vcpu::VcpuState;
use devices::virtio::block::persist::BlockState;

use lazy_static::lazy_static;
use versionize::VersionMap;
use versionize::Versionize;

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

        version_map
    };

    /// Static instance used for creating a 1:1 mapping between Firecracker release version
    /// and snapshot data format version.
    pub static ref FC_VERSION_TO_SNAP_VERSION: HashMap<String, u16> = {
        let mut mapping = HashMap::new();
        #[cfg(not(target_arch = "aarch64"))]
        mapping.insert(String::from("0.23.0"), 1);

        mapping.insert(String::from("0.24.0"), 2);
        mapping.insert(String::from("0.25.0"), 3);

        mapping
    };
}
