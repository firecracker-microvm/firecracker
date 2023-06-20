// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Configurations used in the snapshotting context.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The snapshot type options that are available when
/// creating a new snapshot.
#[derive(Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub enum SnapshotType {
    /// Diff snapshot.
    Diff,
    /// Full snapshot.
    #[default]
    Full,
}

/// Specifies the method through which guest memory will get populated when
/// resuming from a snapshot:
/// 1) A file that contains the guest memory to be loaded,
/// 2) An UDS where a custom page-fault handler process is listening for
///    the UFFD set up by Firecracker to handle its guest memory page faults.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
pub enum MemBackendType {
    /// Guest memory contents will be loaded from a file.
    File,
    /// Guest memory will be served through UFFD by a separate process.
    Uffd,
}

/// Stores the configuration that will be used for creating a snapshot.
#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSnapshotParams {
    /// This marks the type of snapshot we want to create.
    /// The default value is `Full`, which means a full snapshot.
    #[serde(default = "SnapshotType::default")]
    pub snapshot_type: SnapshotType,
    /// Path to the file that will contain the microVM state.
    pub snapshot_path: PathBuf,
    /// Path to the file that will contain the guest memory.
    pub mem_file_path: PathBuf,
    /// Optional field for the microVM version. The default
    /// value is the current version.
    pub version: Option<String>,
}

/// Stores the configuration that will be used for loading a snapshot.
#[derive(Debug, PartialEq, Eq)]
pub struct LoadSnapshotParams {
    /// Path to the file that contains the microVM state to be loaded.
    pub snapshot_path: PathBuf,
    /// Specifies guest memory backend configuration.
    pub mem_backend: MemBackendConfig,
    /// Setting this flag will enable KVM dirty page tracking and will
    /// allow taking subsequent incremental snapshots.
    pub enable_diff_snapshots: bool,
    /// When set to true, the vm is also resumed if the snapshot load
    /// is successful.
    pub resume_vm: bool,
}

/// Stores the configuration for loading a snapshot that is provided by the user.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadSnapshotConfig {
    /// Path to the file that contains the microVM state to be loaded.
    pub snapshot_path: PathBuf,
    /// Path to the file that contains the guest memory to be loaded. To be used only if
    /// `mem_backend` is not specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_file_path: Option<PathBuf>,
    /// Guest memory backend configuration. Is not to be used in conjunction with `mem_file_path`.
    /// None value is allowed only if `mem_file_path` is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_backend: Option<MemBackendConfig>,
    /// Whether or not to enable KVM dirty page tracking.
    #[serde(default)]
    pub enable_diff_snapshots: bool,
    /// Whether or not to resume the vm post snapshot load.
    #[serde(default)]
    pub resume_vm: bool,
}

/// Stores the configuration used for managing snapshot memory.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MemBackendConfig {
    /// Path to the backend used to handle the guest memory.
    pub backend_path: PathBuf,
    /// Specifies the guest memory backend type.
    pub backend_type: MemBackendType,
}

/// The microVM state options.
#[derive(Debug, Deserialize, Serialize)]
pub enum VmState {
    /// The microVM is paused, which means that we can create a snapshot of it.
    Paused,
    /// The microVM is resumed; this state should be set after we load a snapshot.
    Resumed,
}

/// Keeps the microVM state necessary in the snapshotting context.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Vm {
    /// The microVM state, which can be `paused` or `resumed`.
    pub state: VmState,
}
