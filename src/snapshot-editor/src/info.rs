// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use clap::Subcommand;
use vmm::persist::MicrovmState;
use vmm::version_map::FC_VERSION_TO_SNAP_VERSION;

use crate::utils::*;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum InfoVmStateError {
    /// Cannot translate snapshot data version {0} to Firecracker microVM version
    InvalidVersion(u16),
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
    #[cfg(target_arch = "aarch64")]
    VcpuStates {
        /// Path to the vmstate file.
        #[arg(short, long)]
        vmstate_path: PathBuf,
    },
}

pub fn info_vmstate_command(command: InfoVmStateSubCommand) -> Result<(), InfoVmStateError> {
    match command {
        InfoVmStateSubCommand::Version { vmstate_path } => info(&vmstate_path, info_version)?,
        #[cfg(target_arch = "aarch64")]
        InfoVmStateSubCommand::VcpuStates { vmstate_path } => {
            info(&vmstate_path, info_vcpu_states)?
        }
    }
    Ok(())
}

fn info(
    vmstate_path: &PathBuf,
    f: impl Fn(&MicrovmState, u16) -> Result<(), InfoVmStateError>,
) -> Result<(), InfoVmStateError> {
    let (vmstate, version) = open_vmstate(vmstate_path)?;
    f(&vmstate, version)?;
    Ok(())
}

fn info_version(_: &MicrovmState, version: u16) -> Result<(), InfoVmStateError> {
    match FC_VERSION_TO_SNAP_VERSION
        .iter()
        .find(|(_, &v)| v == version)
    {
        Some((key, _)) => {
            println!("v{key}");
            Ok(())
        }
        None => Err(InfoVmStateError::InvalidVersion(version)),
    }
}

#[cfg(target_arch = "aarch64")]
fn info_vcpu_states(state: &MicrovmState, _: u16) -> Result<(), InfoVmStateError> {
    for (i, state) in state.vcpu_states.iter().enumerate() {
        println!("vcpu {i}:");
        println!("kvm_mp_state: {:#x}", state.mp_state.mp_state);
        println!("mpidr: {:#x}", state.mpidr);
        for reg in state.regs.iter() {
            println!(
                "{:#x} 0x{}",
                reg.id,
                reg.as_slice()
                    .iter()
                    .rev()
                    .map(|b| format!("{b:x}"))
                    .collect::<String>()
            );
        }
    }
    Ok(())
}
