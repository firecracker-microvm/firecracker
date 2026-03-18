// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the structures needed for saving/restoring generic vhost-user devices.

use serde::{Deserialize, Serialize};

use super::VhostUserGenericError;
use super::device::VhostUserGeneric;
use crate::snapshot::Persist;

/// Generic vhost-user device state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VhostUserGenericState {
    id: String,
    device_type_id: u32,
    socket_path: String,
    num_queues: u64,
    vu_acked_protocol_features: u64,
    config_space: Vec<u8>,
}

impl Persist<'_> for VhostUserGeneric {
    type State = VhostUserGenericState;
    type ConstructorArgs = ();
    type Error = VhostUserGenericError;

    fn save(&self) -> Self::State {
        unimplemented!("VhostUserGeneric does not support snapshotting yet");
    }

    fn restore(
        _constructor_args: Self::ConstructorArgs,
        _state: &Self::State,
    ) -> Result<Self, Self::Error> {
        Err(VhostUserGenericError::SnapshottingNotSupported)
    }
}
