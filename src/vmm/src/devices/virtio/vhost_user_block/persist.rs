// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the structures needed for saving/restoring block devices.

use snapshot::Persist;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;

use super::device::VhostUserBlock;
use super::VhostUserBlockError;
use crate::devices::virtio::block_common::CacheType;
use crate::devices::virtio::persist::VirtioDeviceState;
use crate::vstate::memory::GuestMemoryMmap;

/// vhost-user block device state.
// NOTICE: Any changes to this structure require a snapshot version bump.
#[derive(Debug, Clone, Versionize)]
pub struct VhostUserBlockState {
    id: String,
    partuuid: Option<String>,
    cache_type: CacheType,
    root_device: bool,
    socket_path: String,
    vu_acked_protocol_features: u64,
    config_space: Vec<u8>,
    virtio_state: VirtioDeviceState,
}

/// Auxiliary structure for creating a device when resuming from a snapshot.
#[derive(Debug)]
pub struct VhostUserBlockConstructorArgs {
    pub mem: GuestMemoryMmap,
}

impl Persist<'_> for VhostUserBlock {
    type State = VhostUserBlockState;
    type ConstructorArgs = VhostUserBlockConstructorArgs;
    type Error = VhostUserBlockError;

    fn save(&self) -> Self::State {
        unimplemented!("VhostUserBlock does not support snapshotting yet");
    }

    fn restore(
        _constructor_args: Self::ConstructorArgs,
        _state: &Self::State,
    ) -> Result<Self, Self::Error> {
        unimplemented!("VhostUserBlock does not support snapshotting yet");
    }
}
