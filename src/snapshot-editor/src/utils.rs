// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::{File, OpenOptions};
use std::path::PathBuf;

use snapshot::Snapshot;
use vmm::persist::MicrovmState;
use vmm::version_map::VERSION_MAP;

// Some errors are only used in aarch64 code
#[allow(unused)]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum UtilsError {
    /// Can not open snapshot file: {0}
    VmStateFileOpen(std::io::Error),
    /// Can not retrieve metadata for snapshot file: {0}
    VmStateFileMeta(std::io::Error),
    /// Can not load snapshot: {0}
    VmStateLoad(snapshot::Error),
    /// Can not open output file: {0}
    OutputFileOpen(std::io::Error),
    /// Can not save snapshot: {0}
    VmStateSave(snapshot::Error),
}

#[allow(unused)]
pub fn open_vmstate(snapshot_path: &PathBuf) -> Result<(MicrovmState, u16), UtilsError> {
    let version_map = VERSION_MAP.clone();
    let mut snapshot_reader = File::open(snapshot_path).map_err(UtilsError::VmStateFileOpen)?;
    let metadata = std::fs::metadata(snapshot_path).map_err(UtilsError::VmStateFileMeta)?;
    let snapshot_len = metadata.len() as usize;
    Snapshot::load(&mut snapshot_reader, snapshot_len, version_map).map_err(UtilsError::VmStateLoad)
}

// This method is used only in aarch64 code so far
#[allow(unused)]
pub fn save_vmstate(
    microvm_state: MicrovmState,
    output_path: &PathBuf,
    version: u16,
) -> Result<(), UtilsError> {
    let version_map = VERSION_MAP.clone();
    let mut output_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(output_path)
        .map_err(UtilsError::OutputFileOpen)?;
    let mut snapshot = Snapshot::new(version_map, version);
    snapshot
        .save(&mut output_file, &microvm_state)
        .map_err(UtilsError::VmStateSave)?;
    Ok(())
}
