// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::vhost_user::persist::VhostUserBlockState;
use super::virtio::persist::VirtioBlockState;
use crate::devices::virtio::transport::VirtioInterrupt;
use crate::vmm_config::snapshot::DriveOverrideBacking;
use crate::vstate::memory::GuestMemoryMmap;

/// Errors associated with applying a drive override.
#[derive(Debug, PartialEq, Eq, thiserror::Error, displaydoc::Display)]
pub enum DriveOverrideError {
    /// Drive override for `{0}` does not match the device type.
    Mismatch(String),
}

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

    /// Apply a backing-path override to the block device.
    pub fn apply_override(
        &mut self,
        backing: &DriveOverrideBacking,
    ) -> Result<(), DriveOverrideError> {
        match (self, backing) {
            (BlockState::Virtio(state), DriveOverrideBacking::PathOnHost(path)) => {
                state.disk_path.clone_from(path);
                Ok(())
            }
            (BlockState::VhostUser(state), DriveOverrideBacking::Socket(path)) => {
                state.socket_path.clone_from(path);
                Ok(())
            }
            (state, _) => Err(DriveOverrideError::Mismatch(state.id().to_string())),
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
    use crate::devices::virtio::block::CacheType;
    use crate::devices::virtio::block::virtio::persist::FileEngineTypeState;
    use crate::devices::virtio::device::VirtioDeviceType;
    use crate::devices::virtio::persist::VirtioDeviceState;
    use crate::rate_limiter::RateLimiter;
    use crate::snapshot::Persist;

    fn virtio_block_state(id: &str, disk_path: &str) -> VirtioBlockState {
        VirtioBlockState {
            id: id.to_string(),
            partuuid: None,
            cache_type: CacheType::Unsafe,
            root_device: false,
            disk_path: disk_path.to_string(),
            virtio_state: VirtioDeviceState {
                device_type: VirtioDeviceType::Block,
                avail_features: 0,
                acked_features: 0,
                queues: vec![],
                activated: false,
            },
            rate_limiter_state: RateLimiter::default().save(),
            file_engine_type: FileEngineTypeState::Sync,
        }
    }

    fn vhost_user_block_state(id: &str, socket_path: &str) -> VhostUserBlockState {
        VhostUserBlockState {
            id: id.to_string(),
            partuuid: None,
            cache_type: CacheType::Unsafe,
            root_device: false,
            socket_path: socket_path.to_string(),
            vu_acked_protocol_features: 0,
            config_space: vec![],
            virtio_state: VirtioDeviceState {
                device_type: VirtioDeviceType::Block,
                avail_features: 0,
                acked_features: 0,
                queues: vec![],
                activated: false,
            },
        }
    }

    #[test]
    fn test_apply_override_virtio() {
        let mut virtio = BlockState::Virtio(virtio_block_state("rootfs", "/old/path"));
        virtio
            .apply_override(&DriveOverrideBacking::PathOnHost("/new/path".to_string()))
            .unwrap();
        match &virtio {
            BlockState::Virtio(state) => assert_eq!(state.disk_path, "/new/path"),
            _ => panic!("expected Virtio variant"),
        }
    }

    #[test]
    fn test_apply_override_vhost_user() {
        let mut vhost = BlockState::VhostUser(vhost_user_block_state("rootfs", "/old/sock"));
        vhost
            .apply_override(&DriveOverrideBacking::Socket("/new/sock".to_string()))
            .unwrap();
        match &vhost {
            BlockState::VhostUser(state) => assert_eq!(state.socket_path, "/new/sock"),
            _ => panic!("expected VhostUser variant"),
        }
    }

    #[test]
    fn test_apply_override_mismatch() {
        // path_on_host against a vhost-user-block device should be rejected.
        let mut vhost = BlockState::VhostUser(vhost_user_block_state("scratch", "/sock"));
        assert_eq!(
            vhost.apply_override(&DriveOverrideBacking::PathOnHost("/p".to_string())),
            Err(DriveOverrideError::Mismatch("scratch".to_string()))
        );

        // socket against a virtio-block device should be rejected.
        let mut virtio = BlockState::Virtio(virtio_block_state("rootfs", "/path"));
        assert_eq!(
            virtio.apply_override(&DriveOverrideBacking::Socket("/s".to_string())),
            Err(DriveOverrideError::Mismatch("rootfs".to_string()))
        );
    }
}
