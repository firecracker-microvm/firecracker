// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Configuration for VFIO based PCIe device passthrough.

use serde::{Deserialize, Serialize};

/// Errors associated with the operations allowed on a VFIO passthrough device.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VfioConfigError {
    /// A VFIO device with id {0} already exists
    DeviceIdAlreadyExists(String),
}

/// Use this structure to assign a host PCI device to the microVM through VFIO before booting the
/// kernel.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VfioDeviceConfig {
    /// Unique identifier of the device.
    pub id: String,
    /// Host sysfs path of the assigned PCI function, e.g.
    /// `/sys/bus/pci/devices/0000:01:00.0`. The device must already be bound to the `vfio-pci`
    /// driver on the host.
    pub path: String,
}

/// Wrapper for the collection that holds all the VFIO passthrough device configs.
#[derive(Debug, Default)]
pub struct VfioBuilder {
    /// The list of VFIO device configs.
    pub configs: Vec<VfioDeviceConfig>,
}

impl VfioBuilder {
    /// Create an empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a new VFIO device config, rejecting duplicate ids.
    pub fn insert(&mut self, config: VfioDeviceConfig) -> Result<(), VfioConfigError> {
        if self.configs.iter().any(|cfg| cfg.id == config.id) {
            return Err(VfioConfigError::DeviceIdAlreadyExists(config.id));
        }
        self.configs.push(config);
        Ok(())
    }
}
