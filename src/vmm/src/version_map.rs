// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provides the VersionMap that deals with the microvm state versions.

use std::collections::HashMap;

use lazy_static::lazy_static;
use versionize::VersionMap;

lazy_static! {
    // Note: this needs to be updated when the version changes.
    /// Static instance used for handling microVM state versions.
    pub static ref VERSION_MAP: VersionMap = {
        VersionMap::new()
    };

    /// Static instance used for mapping Firecracker release version to
    /// snapshot data format version.
    pub static ref FC_VERSION_TO_SNAP_VERSION: HashMap<u16, u16> = {
        let mut hm = HashMap::new();
        hm.insert(23, 1);

        hm
    };
}
