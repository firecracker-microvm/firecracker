// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::devices::virtio::vhost_user_generic::VhostUserGenericError;
use crate::devices::virtio::vhost_user_generic::device::VhostUserGeneric;

/// Errors associated with operations on a generic vhost-user device.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VhostUserDeviceConfigError {
    /// Unable to create the generic vhost-user device: {0}
    CreateDevice(#[from] VhostUserGenericError),
}

/// Use this structure to set up a generic vhost-user device before booting the kernel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VhostUserDeviceConfig {
    /// Unique identifier of the device.
    pub id: String,
    /// The virtio device type ID as defined in the virtio specification.
    /// For example: 26 for virtio-fs, 8 for virtio-scsi.
    /// The backend is responsible for handling the corresponding device protocol.
    pub device_type: u8,
    /// Path to the vhost-user backend Unix domain socket.
    pub socket: String,
    /// Number of virtqueues to configure for this device.
    pub num_queues: u64,
    /// Queue size. Defaults to 256 if not specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_size: Option<u16>,
}

/// Wrapper for the collection that holds all generic vhost-user devices.
#[derive(Debug, Default)]
pub struct VhostUserDeviceBuilder {
    /// The list of generic vhost-user devices.
    pub devices: Vec<Arc<Mutex<VhostUserGeneric>>>,
}

impl VhostUserDeviceBuilder {
    /// Build a device from the config and add it to the collection.
    ///
    /// If a device with the same ID already exists, it is replaced.
    pub fn build(
        &mut self,
        config: VhostUserDeviceConfig,
    ) -> Result<(), VhostUserDeviceConfigError> {
        let position = self
            .devices
            .iter()
            .position(|d| d.lock().unwrap().id == config.id);

        let device = Arc::new(Mutex::new(VhostUserGeneric::new(config)?));

        if let Some(index) = position {
            self.devices[index] = device;
        } else {
            self.devices.push(device);
        }

        Ok(())
    }

    /// Returns a vec with the structures used to configure the devices.
    pub fn configs(&self) -> Vec<VhostUserDeviceConfig> {
        self.devices
            .iter()
            .map(|d| {
                let d = d.lock().unwrap();
                VhostUserDeviceConfig {
                    id: d.id.clone(),
                    device_type: d.device_type_id as u8,
                    socket: d.vu_handle.socket_path.clone(),
                    num_queues: d.queues.len() as u64,
                    queue_size: Some(d.queues[0].size),
                }
            })
            .collect()
    }
}
