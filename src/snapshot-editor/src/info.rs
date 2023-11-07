// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use clap::Subcommand;
use semver::Version;
use vmm::persist::MicrovmState;

use crate::utils::*;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum InfoVmStateError {
    /// {0}
    Utils(#[from] UtilsError),
}

#[derive(Debug, Subcommand)]
pub enum InfoVmStateSubCommand {
    /// Print snapshot version.
    Version {
        /// Path to the vmstate file.
        #[arg(short, long)]
        vmstate_path: PathBuf,
    },
    /// Print info about vcpu states.
    VcpuStates {
        /// Path to the vmstate file.
        #[arg(short, long)]
        vmstate_path: PathBuf,
    },
    /// Print readable MicroVM state.
    VmState {
        /// Path to the vmstate file.
        #[arg(short, long)]
        vmstate_path: PathBuf,
    },
}

pub fn info_vmstate_command(command: InfoVmStateSubCommand) -> Result<(), InfoVmStateError> {
    match command {
        InfoVmStateSubCommand::Version { vmstate_path } => info(&vmstate_path, info_version)?,
        InfoVmStateSubCommand::VcpuStates { vmstate_path } => {
            info(&vmstate_path, info_vcpu_states)?
        }
        InfoVmStateSubCommand::VmState { vmstate_path } => info(&vmstate_path, info_vmstate)?,
    }
    Ok(())
}

fn info(
    vmstate_path: &PathBuf,
    f: impl Fn(&MicrovmState, Version) -> Result<(), InfoVmStateError>,
) -> Result<(), InfoVmStateError> {
    let (vmstate, version) = open_vmstate(vmstate_path)?;
    f(&vmstate, version)?;
    Ok(())
}

fn info_version(_: &MicrovmState, version: Version) -> Result<(), InfoVmStateError> {
    println!("v{version}");
    Ok(())
}

fn info_vcpu_states(state: &MicrovmState, _: Version) -> Result<(), InfoVmStateError> {
    for (i, state) in state.vcpu_states.iter().enumerate() {
        println!("vcpu {i}:");
        println!("{state:#?}");
    }
    Ok(())
}

fn info_vmstate(vmstate: &MicrovmState, _version: Version) -> Result<(), InfoVmStateError> {
    println!("{vmstate:#?}");
    Ok(())
}
