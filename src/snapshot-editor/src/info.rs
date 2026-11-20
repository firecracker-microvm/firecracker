// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use clap::Subcommand;
#[cfg(target_arch = "x86_64")]
use kvm_bindings::Msrs;
use vmm::arch::VcpuState;
use vmm::persist::MicrovmState;
use vmm::snapshot::Snapshot;

use crate::utils::*;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum InfoVmStateError {
    /// {0}
    Utils(#[from] UtilsError),
    /// vCPU registers are not pinned in {0:?}.
    NotPinned(PathBuf),
    /// Expected {0} vCPUs, found {1}.
    VcpuCountMismatch(usize, usize),
    /// Pinned register state differs on vCPU {0}.
    RegisterPinMismatch(usize),
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
    /// Check that two vmstates pin the same ordered register IDs and Arm Feature ID values.
    CheckVcpuRegisterPin {
        /// Path to the original pinned vmstate file.
        #[arg(long)]
        source_path: PathBuf,
        /// Path to the re-snapshotted vmstate file.
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
        InfoVmStateSubCommand::CheckVcpuRegisterPin {
            source_path,
            vmstate_path,
        } => check_vcpu_register_pin(source_path, vmstate_path)?,
        InfoVmStateSubCommand::VmState { vmstate_path } => info(&vmstate_path, info_vmstate)?,
    }
    Ok(())
}

fn info(
    vmstate_path: &PathBuf,
    f: impl Fn(&Snapshot<MicrovmState>) -> Result<(), InfoVmStateError>,
) -> Result<(), InfoVmStateError> {
    let snapshot = open_vmstate(vmstate_path)?;
    f(&snapshot)?;
    Ok(())
}

fn info_version(snapshot: &Snapshot<MicrovmState>) -> Result<(), InfoVmStateError> {
    println!("v{}", snapshot.version());
    Ok(())
}

fn info_vcpu_states(snapshot: &Snapshot<MicrovmState>) -> Result<(), InfoVmStateError> {
    for (i, state) in snapshot.data.vcpu_states.iter().enumerate() {
        println!("vcpu {i}:");
        println!("{state:#?}");
    }
    Ok(())
}

fn pinned_vcpu_states(path: PathBuf) -> Result<Vec<VcpuState>, InfoVmStateError> {
    let state = open_vmstate(&path)?.data;
    if !state.vcpu_registers_pinned {
        return Err(InfoVmStateError::NotPinned(path));
    }
    Ok(state.vcpu_states)
}

#[cfg(target_arch = "x86_64")]
fn pinned_registers(vcpu: &VcpuState) -> impl Iterator<Item = u32> {
    pinned_msr_indices(&vcpu.saved_msrs)
}

#[cfg(target_arch = "x86_64")]
fn pinned_msr_indices(chunks: &[Msrs]) -> impl Iterator<Item = u32> {
    chunks
        .iter()
        .flat_map(|chunk| chunk.as_slice())
        .map(|msr| msr.index)
}

#[cfg(target_arch = "aarch64")]
fn pinned_registers(vcpu: &VcpuState) -> impl Iterator<Item = (u64, Option<u64>)> {
    use vmm::arch::aarch64::regs::is_feature_id_reg;

    vcpu.regs.iter().map(|reg| {
        let value = is_feature_id_reg(reg.id).then(|| reg.value::<u64, 8>());
        (reg.id, value)
    })
}

fn check_vcpu_register_pin(
    source_path: PathBuf,
    vmstate_path: PathBuf,
) -> Result<(), InfoVmStateError> {
    let source = pinned_vcpu_states(source_path)?;
    let current = pinned_vcpu_states(vmstate_path)?;
    compare_pinned_registers(
        source.iter().map(pinned_registers),
        current.iter().map(pinned_registers),
    )
}

fn compare_pinned_registers<R>(
    source: impl ExactSizeIterator<Item = R>,
    current: impl ExactSizeIterator<Item = R>,
) -> Result<(), InfoVmStateError>
where
    R: IntoIterator,
    R::Item: PartialEq,
{
    if source.len() != current.len() {
        return Err(InfoVmStateError::VcpuCountMismatch(
            source.len(),
            current.len(),
        ));
    }
    for (i, (expected, actual)) in source.zip(current).enumerate() {
        if expected.into_iter().ne(actual) {
            return Err(InfoVmStateError::RegisterPinMismatch(i));
        }
    }
    Ok(())
}

fn info_vmstate(snapshot: &Snapshot<MicrovmState>) -> Result<(), InfoVmStateError> {
    println!("{:#?}", snapshot.data);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::iter::once;

    use super::*;

    #[test]
    fn test_pinned_vcpu_count_mismatch() {
        let source = [[1], [2]];
        let current = [[3]];
        assert!(matches!(
            compare_pinned_registers(source.into_iter(), current.into_iter()),
            Err(InfoVmStateError::VcpuCountMismatch(2, 1))
        ));
    }

    #[test]
    fn test_equal_pinned_registers() {
        let registers = [[1, 2], [3, 4]];
        compare_pinned_registers(registers.into_iter(), registers.into_iter()).unwrap();
    }

    #[test]
    fn test_pinned_register_mismatch_on_second_vcpu() {
        let source = [[1], [2], [3]];
        let current = [[1], [4], [5]];
        assert!(matches!(
            compare_pinned_registers(source.into_iter(), current.into_iter()),
            Err(InfoVmStateError::RegisterPinMismatch(1))
        ));
    }

    #[test]
    fn test_pinned_register_strict_prefix() {
        let registers = [1, 2];
        assert!(matches!(
            compare_pinned_registers(once(&registers[..]), once(&registers[..1])),
            Err(InfoVmStateError::RegisterPinMismatch(0))
        ));
    }

    #[cfg(target_arch = "x86_64")]
    mod x86_64 {
        use kvm_bindings::kvm_msr_entry;
        use vmm::arch::x86_64::generated::msr_index::{MSR_CSTAR, MSR_LSTAR, MSR_STAR};

        use super::*;

        fn msrs<const N: usize>(indices: [u32; N], data: u64) -> Msrs {
            Msrs::from_entries(&indices.map(|index| kvm_msr_entry {
                index,
                data,
                ..Default::default()
            }))
            .unwrap()
        }

        fn compare_msrs(source: &[Msrs], current: &[Msrs]) -> Result<(), InfoVmStateError> {
            compare_pinned_registers(
                once(pinned_msr_indices(source)),
                once(pinned_msr_indices(current)),
            )
        }

        #[test]
        fn test_msr_order_mismatch() {
            let source = [msrs([MSR_LSTAR, MSR_CSTAR], 0)];
            let current = [msrs([MSR_CSTAR, MSR_LSTAR], 0)];
            assert!(matches!(
                compare_msrs(&source, &current),
                Err(InfoVmStateError::RegisterPinMismatch(0))
            ));
        }

        #[test]
        fn test_dropped_msr_mismatch() {
            let source = [msrs([MSR_STAR, MSR_LSTAR], 0)];
            let current = [msrs([MSR_LSTAR], 0)];
            assert!(matches!(
                compare_msrs(&source, &current),
                Err(InfoVmStateError::RegisterPinMismatch(0))
            ));
        }

        #[test]
        fn test_msr_chunk_boundaries_ignored() {
            let source = [msrs([MSR_STAR, MSR_LSTAR], 0)];
            let current = [msrs([MSR_STAR], 0), msrs([MSR_LSTAR], 0), msrs([], 0)];
            compare_msrs(&source, &current).unwrap();
        }

        #[test]
        fn test_msr_data_ignored() {
            let source = [msrs([MSR_STAR], 0)];
            let current = [msrs([MSR_STAR], 1)];
            compare_msrs(&source, &current).unwrap();
        }
    }

    #[cfg(target_arch = "aarch64")]
    mod aarch64 {
        use vmm::arch::aarch64::regs::{Aarch64RegisterRef, ID_AA64PFR0_EL1, PC, TCR_EL1};

        use super::*;

        fn vcpu(registers: &[(u64, u64)]) -> VcpuState {
            let mut state = VcpuState::default();
            for &(id, value) in registers {
                state
                    .regs
                    .push(Aarch64RegisterRef::new(id, &value.to_le_bytes()));
            }
            state
        }

        #[test]
        fn test_pinned_register_order_mismatch_on_second_vcpu() {
            let registers = [(TCR_EL1, 0), (PC, 0)];
            let source = vcpu(&registers);
            let reordered = vcpu(&[registers[1], registers[0]]);
            assert!(matches!(
                compare_pinned_registers(
                    [&source, &source].into_iter().map(pinned_registers),
                    [&source, &reordered].into_iter().map(pinned_registers),
                ),
                Err(InfoVmStateError::RegisterPinMismatch(1))
            ));
        }

        #[test]
        fn test_pinned_feature_id_value_mismatch() {
            let source = vcpu(&[(ID_AA64PFR0_EL1, 0)]);
            let current = vcpu(&[(ID_AA64PFR0_EL1, 1)]);
            assert!(matches!(
                compare_pinned_registers(
                    once(pinned_registers(&source)),
                    once(pinned_registers(&current)),
                ),
                Err(InfoVmStateError::RegisterPinMismatch(0))
            ));
        }

        #[test]
        fn test_pinned_non_feature_id_value_ignored() {
            let source = vcpu(&[(PC, 0)]);
            let current = vcpu(&[(PC, 1)]);
            compare_pinned_registers(
                once(pinned_registers(&source)),
                once(pinned_registers(&current)),
            )
            .unwrap();
        }
    }
}
