// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::vhost_user::persist::VhostUserBlockState;
use super::virtio::persist::VirtioBlockState;
use crate::devices::virtio::transport::VirtioInterrupt;
use crate::vstate::memory::GuestMemoryMmap;

/// Block device state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockState {
    Virtio(VirtioBlockState),
    VhostUser(VhostUserBlockState),
}

impl BlockState {
    pub fn is_activated(&self) -> bool {
        match self {
            BlockState::Virtio(state) => state.virtio_state.activated,
            BlockState::VhostUser(_) => false,
        }
    }

    /// Returns the drive ID.
    pub fn id(&self) -> &str {
        match self {
            BlockState::Virtio(state) => &state.id,
            BlockState::VhostUser(state) => &state.id,
        }
    }

    /// Overrides the disk path of a virtio-block device.
    /// Returns false if this is not a virtio-block device.
    pub fn set_disk_path(&mut self, path: &str) -> bool {
        match self {
            BlockState::Virtio(state) => {
                state.disk_path = path.to_string();
                true
            }
            BlockState::VhostUser(_) => false,
        }
    }

    /// Overrides the socket path of a vhost-user-block device.
    /// Returns false if this is not a vhost-user-block device.
    pub fn set_socket_path(&mut self, path: &str) -> bool {
        match self {
            BlockState::VhostUser(state) => {
                state.socket_path = path.to_string();
                true
            }
            BlockState::Virtio(_) => false,
        }
    }
}

/// Auxiliary structure for creating a device when resuming from a snapshot.
#[derive(Debug)]
pub struct BlockConstructorArgs {
    pub mem: GuestMemoryMmap,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn virtio_block_state(id: &str, disk_path: &str, activated: bool) -> VirtioBlockState {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "partuuid": null,
            "cache_type": "Unsafe",
            "root_device": false,
            "disk_path": disk_path,
            "virtio_state": {
                "device_type": "Block",
                "avail_features": 0,
                "acked_features": 0,
                "queues": [],
                "activated": activated
            },
            "rate_limiter_state": {
                "ops": null,
                "bandwidth": null
            },
            "file_engine_type": "Sync"
        }))
        .unwrap()
    }

    fn vhost_user_block_state(id: &str, socket_path: &str) -> VhostUserBlockState {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "partuuid": null,
            "cache_type": "Unsafe",
            "root_device": false,
            "socket_path": socket_path,
            "vu_acked_protocol_features": 0,
            "config_space": [],
            "virtio_state": {
                "device_type": "Block",
                "avail_features": 0,
                "acked_features": 0,
                "queues": [],
                "activated": false
            }
        }))
        .unwrap()
    }

    #[test]
    fn test_block_state_id() {
        let virtio = BlockState::Virtio(virtio_block_state("rootfs", "/path", false));
        assert_eq!(virtio.id(), "rootfs");

        let vhost = BlockState::VhostUser(vhost_user_block_state("scratch", "/sock"));
        assert_eq!(vhost.id(), "scratch");
    }

    #[test]
    fn test_block_state_is_activated() {
        let active = BlockState::Virtio(virtio_block_state("rootfs", "/path", true));
        assert!(active.is_activated());

        let inactive = BlockState::Virtio(virtio_block_state("rootfs", "/path", false));
        assert!(!inactive.is_activated());

        // vhost-user always returns false
        let vhost = BlockState::VhostUser(vhost_user_block_state("rootfs", "/sock"));
        assert!(!vhost.is_activated());
    }

    #[test]
    fn test_block_state_set_disk_path() {
        let mut virtio = BlockState::Virtio(virtio_block_state("rootfs", "/old/path", false));
        assert!(virtio.set_disk_path("/new/path"));
        match &virtio {
            BlockState::Virtio(state) => assert_eq!(state.disk_path, "/new/path"),
            _ => panic!("expected Virtio variant"),
        }

        // set_disk_path on a vhost-user device should fail.
        let mut vhost = BlockState::VhostUser(vhost_user_block_state("rootfs", "/sock"));
        assert!(!vhost.set_disk_path("/new/path"));
    }

    #[test]
    fn test_block_state_set_socket_path() {
        let mut vhost = BlockState::VhostUser(vhost_user_block_state("rootfs", "/old/sock"));
        assert!(vhost.set_socket_path("/new/sock"));
        match &vhost {
            BlockState::VhostUser(state) => assert_eq!(state.socket_path, "/new/sock"),
            _ => panic!("expected VhostUser variant"),
        }

        // set_socket_path on a virtio device should fail.
        let mut virtio = BlockState::Virtio(virtio_block_state("rootfs", "/path", false));
        assert!(!virtio.set_socket_path("/new/sock"));
    }
}
