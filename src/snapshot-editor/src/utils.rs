// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::{File, OpenOptions};
use std::path::PathBuf;

use vmm::persist::MicrovmState;
use vmm::snapshot::Snapshot;

// Some errors are only used in aarch64 code
#[allow(unused)]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum UtilsError {
    /// Can not open snapshot file: {0}
    VmStateFileOpen(std::io::Error),
    /// Can not load snapshot: {0}
    VmStateLoad(vmm::snapshot::SnapshotError),
    /// Can not open output file: {0}
    OutputFileOpen(std::io::Error),
    /// Can not save snapshot: {0}
    VmStateSave(vmm::snapshot::SnapshotError),
}

#[allow(unused)]
pub fn open_vmstate(snapshot_path: &PathBuf) -> Result<Snapshot<MicrovmState>, UtilsError> {
    let mut snapshot_reader = File::open(snapshot_path).map_err(UtilsError::VmStateFileOpen)?;
    Snapshot::load(&mut snapshot_reader).map_err(UtilsError::VmStateLoad)
}

// This method is used only in aarch64 code so far
#[allow(unused)]
pub fn save_vmstate(microvm_state: MicrovmState, output_path: &PathBuf) -> Result<(), UtilsError> {
    let mut output_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(output_path)
        .map_err(UtilsError::OutputFileOpen)?;
    let mut snapshot = Snapshot::new(microvm_state);
    snapshot
        .save(&mut output_file)
        .map_err(UtilsError::VmStateSave)?;
    Ok(())
}
