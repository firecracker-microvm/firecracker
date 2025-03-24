// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use clap::Subcommand;
use clap_num::maybe_hex;
use vmm::arch::aarch64::regs::Aarch64RegisterVec;
use vmm::persist::MicrovmState;

use crate::utils::{UtilsError, open_vmstate, save_vmstate};

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum EditVmStateError {
    /// {0}
    Utils(#[from] UtilsError),
}

#[derive(Debug, Subcommand)]
pub enum EditVmStateSubCommand {
    /// Remove registers from vcpu states.
    RemoveRegs {
        /// Set of registers to remove.
        /// Values should be registers ids as the are defined in KVM.
        #[arg(value_parser=maybe_hex::<u64>, num_args = 1.., value_delimiter = ' ')]
        regs: Vec<u64>,
        /// Path to the vmstate file.
        #[arg(short, long)]
        vmstate_path: PathBuf,
        /// Path of output file.
        #[arg(short, long)]
        output_path: PathBuf,
    },
}

pub fn edit_vmstate_command(command: EditVmStateSubCommand) -> Result<(), EditVmStateError> {
    match command {
        EditVmStateSubCommand::RemoveRegs {
            regs,
            vmstate_path,
            output_path,
        } => edit(&vmstate_path, &output_path, |state| {
            remove_regs(state, &regs)
        })?,
    }
    Ok(())
}

fn edit(
    vmstate_path: &PathBuf,
    output_path: &PathBuf,
    f: impl Fn(MicrovmState) -> Result<MicrovmState, EditVmStateError>,
) -> Result<(), EditVmStateError> {
    let (microvm_state, version) = open_vmstate(vmstate_path)?;
    let microvm_state = f(microvm_state)?;
    save_vmstate(microvm_state, output_path, version)?;
    Ok(())
}

fn remove_regs(
    mut state: MicrovmState,
    remove_regs: &[u64],
) -> Result<MicrovmState, EditVmStateError> {
    for (i, vcpu_state) in state.vcpu_states.iter_mut().enumerate() {
        println!("Modifying state for vCPU {i}");

        let mut removed = vec![false; remove_regs.len()];
        let mut new_regs = Aarch64RegisterVec::default();
        for reg in vcpu_state.regs.iter().filter(|reg| {
            if let Some(pos) = remove_regs.iter().position(|r| r == &reg.id) {
                removed[pos] = true;
                false
            } else {
                true
            }
        }) {
            new_regs.push(reg);
        }
        vcpu_state.regs = new_regs;
        for (reg, removed) in remove_regs.iter().zip(removed.iter()) {
            print!("Regsiter {reg:#x}: ");
            match removed {
                true => println!("removed"),
                false => println!("not present"),
            }
        }
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remove_regs() {
        const KVM_REG_SIZE_U8: u64 = 0;
        const KVM_REG_SIZE_U16: u64 = 0x10000000000000;
        const KVM_REG_SIZE_U32: u64 = 0x20000000000000;

        use vmm::arch::aarch64::regs::Aarch64RegisterRef;
        use vmm::arch::aarch64::vcpu::VcpuState;

        let vcpu_state = VcpuState {
            regs: {
                let mut regs = Aarch64RegisterVec::default();
                let reg_data: u8 = 69;
                regs.push(Aarch64RegisterRef::new(
                    KVM_REG_SIZE_U8,
                    &reg_data.to_le_bytes(),
                ));
                let reg_data: u16 = 69;
                regs.push(Aarch64RegisterRef::new(
                    KVM_REG_SIZE_U16,
                    &reg_data.to_le_bytes(),
                ));
                let reg_data: u32 = 69;
                regs.push(Aarch64RegisterRef::new(
                    KVM_REG_SIZE_U32,
                    &reg_data.to_le_bytes(),
                ));
                regs
            },
            ..Default::default()
        };
        let state = MicrovmState {
            vcpu_states: vec![vcpu_state],
            ..Default::default()
        };

        let new_state = remove_regs(state, &[KVM_REG_SIZE_U32]).unwrap();

        let expected_vcpu_state = VcpuState {
            regs: {
                let mut regs = Aarch64RegisterVec::default();
                let reg_data: u8 = 69;
                regs.push(Aarch64RegisterRef::new(
                    KVM_REG_SIZE_U8,
                    &reg_data.to_le_bytes(),
                ));
                let reg_data: u16 = 69;
                regs.push(Aarch64RegisterRef::new(
                    KVM_REG_SIZE_U16,
                    &reg_data.to_le_bytes(),
                ));
                regs
            },
            ..Default::default()
        };

        assert_eq!(new_state.vcpu_states[0].regs, expected_vcpu_state.regs);
    }

    #[test]
    fn test_remove_non_existed_regs() {
        const KVM_REG_SIZE_U8: u64 = 0;
        const KVM_REG_SIZE_U16: u64 = 0x10000000000000;
        const KVM_REG_SIZE_U32: u64 = 0x20000000000000;

        use vmm::arch::aarch64::regs::Aarch64RegisterRef;
        use vmm::arch::aarch64::vcpu::VcpuState;

        let vcpu_state = VcpuState {
            regs: {
                let mut regs = Aarch64RegisterVec::default();
                let reg_data: u8 = 69;
                regs.push(Aarch64RegisterRef::new(
                    KVM_REG_SIZE_U8,
                    &reg_data.to_le_bytes(),
                ));
                let reg_data: u16 = 69;
                regs.push(Aarch64RegisterRef::new(
                    KVM_REG_SIZE_U16,
                    &reg_data.to_le_bytes(),
                ));
                regs
            },
            ..Default::default()
        };

        let state_clone = MicrovmState {
            vcpu_states: vec![vcpu_state.clone()],
            ..Default::default()
        };

        let state = MicrovmState {
            vcpu_states: vec![vcpu_state],
            ..Default::default()
        };

        let new_state = remove_regs(state_clone, &[KVM_REG_SIZE_U32]).unwrap();

        assert_eq!(new_state.vcpu_states[0].regs, state.vcpu_states[0].regs);
    }
}
