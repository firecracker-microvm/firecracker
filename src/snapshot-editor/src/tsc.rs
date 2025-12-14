// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::utils::{UtilsError, open_vmstate, save_vmstate};

#[derive(Debug, thiserror::Error)]
pub enum TscCommandError {
    #[error("{0}")]
    Utils(#[from] UtilsError),
    #[cfg_attr(target_arch = "x86_64", allow(dead_code))]
    #[error("Missing --tsc-khz value; provide a target frequency in kHz.")]
    MissingFrequency,
    #[cfg(target_arch = "x86_64")]
    #[error("Failed to open /dev/kvm: {0}")]
    DetectOpenKvm(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    #[error("Failed to create KVM VM: {0}")]
    DetectCreateVm(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    #[error("Failed to create KVM vCPU: {0}")]
    DetectCreateVcpu(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    #[error("Failed to query TSC frequency from KVM: {0}")]
    DetectQueryTsc(kvm_ioctls::Error),
}

#[derive(Debug, Subcommand)]
pub enum TscSubCommand {
    /// Set the saved TSC frequency (in kHz) for every vCPU in the vmstate file.
    Set(SetTscArgs),
    /// Remove the saved TSC frequency so Firecracker skips scaling on restore.
    Clear(ClearTscArgs),
}

#[derive(Debug, Args)]
pub struct SetTscArgs {
    /// Path to the vmstate file to update.
    #[arg(long)]
    pub vmstate_path: PathBuf,
    /// TSC frequency in kHz to embed in the vmstate snapshot.
    #[arg(long, value_parser = clap::value_parser!(u32))]
    pub tsc_khz: Option<u32>,
}

#[derive(Debug, Args)]
pub struct ClearTscArgs {
    /// Path to the vmstate file to update.
    #[arg(long)]
    pub vmstate_path: PathBuf,
}

pub fn tsc_command(command: TscSubCommand) -> Result<(), TscCommandError> {
    match command {
        TscSubCommand::Set(args) => set_tsc(args),
        TscSubCommand::Clear(args) => clear_tsc(args),
    }
}

fn set_tsc(args: SetTscArgs) -> Result<(), TscCommandError> {
    #[cfg(target_arch = "x86_64")]
    let freq = match args.tsc_khz {
        Some(freq) => freq,
        None => detect_host_tsc_khz()?,
    };
    #[cfg(not(target_arch = "x86_64"))]
    let freq = args.tsc_khz.ok_or(TscCommandError::MissingFrequency)?;

    let mut snapshot = open_vmstate(&args.vmstate_path)?;
    for vcpu in &mut snapshot.data.vcpu_states {
        vcpu.tsc_khz = Some(freq);
    }
    save_vmstate(&snapshot, &args.vmstate_path)?;
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn detect_host_tsc_khz() -> Result<u32, TscCommandError> {
    use kvm_ioctls::Kvm;

    let kvm = Kvm::new().map_err(TscCommandError::DetectOpenKvm)?;
    let vm = kvm.create_vm().map_err(TscCommandError::DetectCreateVm)?;
    let vcpu = vm
        .create_vcpu(0)
        .map_err(TscCommandError::DetectCreateVcpu)?;
    vcpu.get_tsc_khz().map_err(TscCommandError::DetectQueryTsc)
}

fn clear_tsc(args: ClearTscArgs) -> Result<(), TscCommandError> {
    let mut snapshot = open_vmstate(&args.vmstate_path)?;
    for vcpu in &mut snapshot.data.vcpu_states {
        vcpu.tsc_khz = None;
    }
    save_vmstate(&snapshot, &args.vmstate_path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use vmm::persist::MicrovmState;
    use vmm::snapshot::Snapshot;

    use super::*;
    use crate::utils::save_vmstate;

    fn temp_vmstate_path() -> PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!(
            "snapshot-editor-tsc-{}-{}.bin",
            std::process::id(),
            nanos
        ));
        path
    }

    #[test]
    fn test_tsc_set_and_clear_in_place() {
        let vmstate_path = temp_vmstate_path();

        // Start from a valid vmstate snapshot.
        let snapshot = Snapshot::new(MicrovmState::default());
        save_vmstate(&snapshot, &vmstate_path).expect("save initial vmstate");

        let set_freq = 123_456u32;
        set_tsc(SetTscArgs {
            vmstate_path: vmstate_path.clone(),
            tsc_khz: Some(set_freq),
        })
        .expect("tsc set should succeed");

        let snapshot = open_vmstate(&vmstate_path).expect("vmstate after set");
        assert!(
            snapshot
                .data
                .vcpu_states
                .iter()
                .all(|vcpu| vcpu.tsc_khz == Some(set_freq))
        );

        clear_tsc(ClearTscArgs {
            vmstate_path: vmstate_path.clone(),
        })
        .expect("tsc clear should succeed");

        let snapshot = open_vmstate(&vmstate_path).expect("vmstate after clear");
        assert!(
            snapshot
                .data
                .vcpu_states
                .iter()
                .all(|vcpu| vcpu.tsc_khz.is_none())
        );

        let _ = std::fs::remove_file(vmstate_path);
    }
}
