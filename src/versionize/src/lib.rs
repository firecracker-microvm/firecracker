// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]

//! Provides version tolerant serialization and deserialization facilities and
//! implements a persistent storage format for Firecracker state snapshots.
//! The `Versionize` trait defines a generic interface that serializable state structures
//! need to implement.
//!
//! `VersionMap` exposes an API that maps the individual structure versions to
//! a root version (see above: the data version for example). This mapping is required
//! both when serializing or deserializing structures as we need to know which version of structure
//! to serialize for a given target **data version
//!
extern crate bincode;
extern crate crc64;
extern crate serde;
extern crate serde_derive;
extern crate versionize_derive;
extern crate vmm_sys_util;

pub mod crc;
mod primitives;
pub mod version_map;

use std::any::TypeId;
use std::io::{Read, Write};
pub use version_map::VersionMap;
use versionize_derive::Versionize;

/// Versioned serialization error definitions.
#[derive(Debug, PartialEq)]
pub enum Error {
    /// An IO error occured.
    Io(i32),
    /// A serialization error.
    Serialize(String),
    /// A deserialization error.
    Deserialize(String),
    /// A user generated semantic error.
    Semantic(String),
}

/// Versioned serialization/deserialization result.
pub type VersionizeResult<T> = std::result::Result<T, Error>;

/// Trait that provides an interface for version aware serialization and deserialization.
pub trait Versionize {
    /// Serializes `self` to `target_verion` using the specficifed `writer` and `version_map`.
    fn serialize<W: Write>(
        &self,
        writer: &mut W,
        version_map: &VersionMap,
        target_version: u16,
    ) -> VersionizeResult<()>;

    /// Returns a new instance of `Self` by deserialzing from `source_version` using the
    /// specficifed `reader` and `version_map`.
    fn deserialize<R: Read>(
        reader: &mut R,
        version_map: &VersionMap,
        source_version: u16,
    ) -> VersionizeResult<Self>
    where
        Self: Sized;

    /// Returns the `Self` type id.
    fn type_id() -> std::any::TypeId
    where
        Self: 'static,
    {
        TypeId::of::<Self>()
    }

    /// Returns latest `Self` version number.
    fn version() -> u16;
}
