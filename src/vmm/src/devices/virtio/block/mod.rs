// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};

use self::vhost_user::VhostUserBlockError;
use self::virtio::VirtioBlockError;

pub mod device;
pub mod persist;
pub mod vhost_user;
pub mod virtio;

/// Configuration options for disk caching.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub enum CacheType {
    /// Flushing mechanic not will be advertised to the guest driver
    #[default]
    Unsafe,
    /// Flushing mechanic will be advertised to the guest driver and
    /// flush requests coming from the guest will be performed using
    /// `fsync`.
    Writeback,
}

/// Errors the block device can trigger.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum BlockError {
    /// Invalid block config.
    InvalidBlockConfig,
    /// Running method expected different backend.
    InvalidBlockBackend,
    /// Can not restore any backend.
    BackendRestore,
    /// Virtio backend error: {0}
    VirtioBackend(VirtioBlockError),
    /// Vhost user backend error: {0}
    VhostUserBackend(VhostUserBlockError),
}
