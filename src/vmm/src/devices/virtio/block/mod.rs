// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Implements a virtio block device.

pub mod file;
pub mod vhost_user;

use serde::{Deserialize, Serialize};
use versionize::{VersionMap, Versionize, VersionizeError, VersionizeResult};
use versionize_derive::Versionize;

/// Configuration options for disk caching.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub enum CacheType {
    /// Flushing mechanic will be advertised to the guest driver, but
    /// the operation will be a noop.
    #[default]
    Unsafe,
    /// Flushing mechanic will be advertised to the guest driver and
    /// flush requests coming from the guest will be performed using
    /// `fsync`.
    Writeback,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Versionize)]
// NOTICE: Any changes to this structure require a snapshot version bump.
pub enum CacheTypeState {
    Unsafe,
    Writeback,
}

impl From<CacheType> for CacheTypeState {
    fn from(cache_type: CacheType) -> Self {
        match cache_type {
            CacheType::Unsafe => CacheTypeState::Unsafe,
            CacheType::Writeback => CacheTypeState::Writeback,
        }
    }
}

impl From<CacheTypeState> for CacheType {
    fn from(cache_type_state: CacheTypeState) -> Self {
        match cache_type_state {
            CacheTypeState::Unsafe => CacheType::Unsafe,
            CacheTypeState::Writeback => CacheType::Writeback,
        }
    }
}

/// Trait for block virtio devices.
pub trait Disk {
    /// Provides the ID of this block device.
    fn id(&self) -> &String;

    /// Provides the PARTUUID of this block device.
    fn partuuid(&self) -> Option<&String>;

    /// Specifies if this block device is read only.
    fn is_read_only(&self) -> bool;

    /// Specifies if this block device is read only.
    fn is_root_device(&self) -> bool;

    /// Specifies block device cache type.
    fn cache_type(&self) -> CacheType;
}

/// Common structure for all virtio block devices.
#[derive(Debug)]
pub struct DiskAttributes {
    id: String,
    partuuid: Option<String>,
    cache_type: CacheType,
    read_only: bool,
    root_device: bool,
}

impl DiskAttributes {
    /// Create a new virtio block device.
    pub fn new(
        id: String,
        partuuid: Option<String>,
        cache_type: CacheType,
        is_disk_read_only: bool,
        is_disk_root: bool,
    ) -> Self {
        Self {
            id,
            partuuid,
            cache_type,
            read_only: is_disk_read_only,
            root_device: is_disk_root,
        }
    }

    /// Provides the ID of this block device.
    pub fn id(&self) -> &String {
        &self.id
    }

    /// Provides the PARTUUID of this block device.
    pub fn partuuid(&self) -> Option<&String> {
        self.partuuid.as_ref()
    }

    /// Specifies if this block device is read only.
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Specifies if this block device is a root device.
    pub fn is_root_device(&self) -> bool {
        self.root_device
    }

    /// Specifies block device cache type.
    pub fn cache_type(&self) -> CacheType {
        self.cache_type
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "id";
    const PARTUUID: &str = "partuuid";
    const CACHE_TYPE: CacheType = CacheType::Writeback;
    const READ_ONLY: bool = true;
    const ROOT_DEVICE: bool = true;

    fn dummy_block() -> DiskAttributes {
        DiskAttributes::new(
            ID.to_string(),
            Some(PARTUUID.to_string()),
            CACHE_TYPE,
            READ_ONLY,
            ROOT_DEVICE,
        )
    }

    #[test]
    fn test_id() {
        assert_eq!(dummy_block().id(), &ID);
    }

    #[test]
    fn test_partuuid() {
        assert_eq!(dummy_block().partuuid(), Some(&PARTUUID.to_string()));
    }

    #[test]
    fn test_cache_type() {
        assert_eq!(dummy_block().cache_type(), CACHE_TYPE);
    }

    #[test]
    fn test_read_only() {
        assert_eq!(dummy_block().is_read_only(), READ_ONLY);
    }

    #[test]
    fn test_root_device() {
        assert_eq!(dummy_block().is_root_device(), ROOT_DEVICE);
    }
}
