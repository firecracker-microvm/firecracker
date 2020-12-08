// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::aarch64::gic::{Error, Result};
use kvm_bindings::*;
use kvm_ioctls::DeviceFd;

const ICC_CTLR_EL1_PRIBITS_SHIFT: u32 = 8;
const ICC_CTLR_EL1_PRIBITS_MASK: u32 = 7 << ICC_CTLR_EL1_PRIBITS_SHIFT;

macro_rules! arm64_vgic_sys_reg {
    ($name: tt, $op0: tt, $op1: tt, $crn: tt, $crm: tt, $op2: expr) => {
        const $name: u64 = ((($op0 as u64) << KVM_REG_ARM64_SYSREG_OP0_SHIFT)
            & KVM_REG_ARM64_SYSREG_OP0_MASK as u64)
            | ((($op1 as u64) << KVM_REG_ARM64_SYSREG_OP1_SHIFT)
                & KVM_REG_ARM64_SYSREG_OP1_MASK as u64)
            | ((($crn as u64) << KVM_REG_ARM64_SYSREG_CRN_SHIFT)
                & KVM_REG_ARM64_SYSREG_CRN_MASK as u64)
            | ((($crm as u64) << KVM_REG_ARM64_SYSREG_CRM_SHIFT)
                & KVM_REG_ARM64_SYSREG_CRM_MASK as u64)
            | ((($op2 as u64) << KVM_REG_ARM64_SYSREG_OP2_SHIFT)
                & KVM_REG_ARM64_SYSREG_OP2_MASK as u64);
    };
}

macro_rules! SYS_ICC_AP0Rn_EL1 {
    ($name: tt, $n: tt) => {
        arm64_vgic_sys_reg!($name, 3, 0, 12, 8, (4 | $n));
    };
}

macro_rules! SYS_ICC_AP1Rn_EL1 {
    ($name: tt, $n: tt) => {
        arm64_vgic_sys_reg!($name, 3, 0, 12, 9, $n);
    };
}

arm64_vgic_sys_reg!(SYS_ICC_SRE_EL1, 3, 0, 12, 12, 5);
arm64_vgic_sys_reg!(SYS_ICC_CTLR_EL1, 3, 0, 12, 12, 4);
arm64_vgic_sys_reg!(SYS_ICC_IGRPEN0_EL1, 3, 0, 12, 12, 6);
arm64_vgic_sys_reg!(SYS_ICC_IGRPEN1_EL1, 3, 0, 12, 12, 7);
arm64_vgic_sys_reg!(SYS_ICC_PMR_EL1, 3, 0, 4, 6, 0);
arm64_vgic_sys_reg!(SYS_ICC_BPR0_EL1, 3, 0, 12, 8, 3);
arm64_vgic_sys_reg!(SYS_ICC_BPR1_EL1, 3, 0, 12, 12, 3);
SYS_ICC_AP0Rn_EL1!(SYS_ICC_AP0R0_EL1, 0);
SYS_ICC_AP0Rn_EL1!(SYS_ICC_AP0R1_EL1, 1);
SYS_ICC_AP0Rn_EL1!(SYS_ICC_AP0R2_EL1, 2);
SYS_ICC_AP0Rn_EL1!(SYS_ICC_AP0R3_EL1, 3);
SYS_ICC_AP1Rn_EL1!(SYS_ICC_AP1R0_EL1, 0);
SYS_ICC_AP1Rn_EL1!(SYS_ICC_AP1R1_EL1, 1);
SYS_ICC_AP1Rn_EL1!(SYS_ICC_AP1R2_EL1, 2);
SYS_ICC_AP1Rn_EL1!(SYS_ICC_AP1R3_EL1, 3);

static VGIC_ICC_REGS: &[u64] = &[
    SYS_ICC_SRE_EL1,
    SYS_ICC_CTLR_EL1,
    SYS_ICC_IGRPEN0_EL1,
    SYS_ICC_IGRPEN1_EL1,
    SYS_ICC_PMR_EL1,
    SYS_ICC_BPR0_EL1,
    SYS_ICC_BPR1_EL1,
    SYS_ICC_AP0R0_EL1,
    SYS_ICC_AP0R1_EL1,
    SYS_ICC_AP0R2_EL1,
    SYS_ICC_AP0R3_EL1,
    SYS_ICC_AP1R0_EL1,
    SYS_ICC_AP1R1_EL1,
    SYS_ICC_AP1R2_EL1,
    SYS_ICC_AP1R3_EL1,
];

// Helps with triggering either a register fetch or a store.
enum Action<'a> {
    Set(&'a [u64], usize),
    Get(&'a mut Vec<u64>),
}

fn access_icc_attr(fd: &DeviceFd, offset: u64, typer: u64, val: &mut u64, set: bool) -> Result<()> {
    let mut gic_icc_attr = kvm_bindings::kvm_device_attr {
        group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS,
        attr: ((typer & KVM_DEV_ARM_VGIC_V3_MPIDR_MASK as u64) | offset), // this needs the mpidr
        addr: val as *mut u64 as u64,
        flags: 0,
    };
    if set {
        fd.set_device_attr(&gic_icc_attr).map_err(|e| {
            Error::DeviceAttribute(e, true, kvm_bindings::KVM_DEV_ARM_VGIC_GRP_REDIST_REGS)
        })?;
    } else {
        fd.get_device_attr(&mut gic_icc_attr).map_err(|e| {
            Error::DeviceAttribute(e, false, kvm_bindings::KVM_DEV_ARM_VGIC_GRP_REDIST_REGS)
        })?;
    }
    Ok(())
}

/// Get ICC registers.
fn access_icc_reg_list(fd: &DeviceFd, gicr_typer: &[u64], action: &mut Action) -> Result<()> {
    // We need this for the ICC_AP<m>R<n>_EL1 registers.
    let mut num_priority_bits = 0;

    for i in gicr_typer {
        for icc_offset in VGIC_ICC_REGS {
            // As per ARMv8 documentation: https://static.docs.arm.com/ihi0069/c/IHI0069C_
            // gic_architecture_specification.pdf
            // page 178,
            // ICC_AP0R1_EL1 is only implemented in implementations that support 6 or more bits of
            // priority.
            // ICC_AP0R2_EL1 and ICC_AP0R3_EL1 are only implemented in implementations that support
            // 7 bits of priority.
            if (*icc_offset == SYS_ICC_AP0R1_EL1 || *icc_offset == SYS_ICC_AP1R1_EL1)
                && num_priority_bits < 6
            {
                continue;
            }
            if (*icc_offset == SYS_ICC_AP0R2_EL1
                || *icc_offset == SYS_ICC_AP0R3_EL1
                || *icc_offset == SYS_ICC_AP1R2_EL1
                || *icc_offset == SYS_ICC_AP1R3_EL1)
                && num_priority_bits != 7
            {
                continue;
            }
            let mut val;
            match action {
                Action::Set(state, idx) => {
                    val = state[*idx];
                    access_icc_attr(fd, *icc_offset, *i, &mut val, true)?;
                    *idx += 1;
                }
                Action::Get(state) => {
                    val = 0;
                    access_icc_attr(fd, *icc_offset, *i, &mut val, false)?;
                    state.push(val);
                }
            }

            if *icc_offset == SYS_ICC_CTLR_EL1 {
                // The priority bits are found in the ICC_CTLR_EL1 register (bits from  10:8).
                // See page 194 from https://static.docs.arm.com/ihi0069/c/IHI0069C_gic_
                // architecture_specification.pdf.
                // Citation:
                // "Priority bits. Read-only and writes are ignored. The number of priority bits
                // implemented, minus one."
                num_priority_bits =
                    ((val & ICC_CTLR_EL1_PRIBITS_MASK as u64) >> ICC_CTLR_EL1_PRIBITS_SHIFT) + 1;
            }
        }
    }
    Ok(())
}

/// Get ICC registers.
pub fn get_icc_regs(fd: &DeviceFd, gicr_typer: &[u64]) -> Result<Vec<u64>> {
    let mut state: Vec<u64> = Vec::new();
    let mut action = Action::Get(&mut state);
    access_icc_reg_list(fd, gicr_typer, &mut action)?;
    Ok(state)
}

/// Set ICC registers.
pub fn set_icc_regs(fd: &DeviceFd, gicr_typer: &[u64], state: &[u64]) -> Result<()> {
    let mut action = Action::Set(state, 0);
    access_icc_reg_list(fd, gicr_typer, &mut action)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::gic::create_gic;
    use kvm_ioctls::Kvm;
    use std::os::unix::io::AsRawFd;

    #[test]
    fn test_access_icc_regs_size() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let _ = vm.create_vcpu(0).unwrap();
        let gic_fd = create_gic(&vm, 1).expect("Cannot create gic");
        let fd = gic_fd.device_fd();

        let gicr_typer = 123;
        let icc_offset = SYS_ICC_SRE_EL1;

        let mut val = [0xdead_beef; 3];
        access_icc_attr(fd, icc_offset, gicr_typer, &mut val[1], false).unwrap();
        assert_eq!(val[0], 0xdead_beef);
        assert_ne!(val[1], 0xdead_beef);
        assert_eq!(val[2], 0xdead_beef);
    }

    #[test]
    fn test_access_icc_regs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let _ = vm.create_vcpu(0).unwrap();
        let gic_fd = create_gic(&vm, 1).expect("Cannot create gic");

        let mut gicr_typer = Vec::new();
        gicr_typer.push(123);
        let res = get_icc_regs(&gic_fd.device_fd(), &gicr_typer);
        assert!(res.is_ok());
        let state = res.unwrap();
        println!("{}", state.len());
        assert_eq!(state.len(), 9);

        assert!(set_icc_regs(&gic_fd.device_fd(), &gicr_typer, &state).is_ok());

        unsafe { libc::close(gic_fd.device_fd().as_raw_fd()) };

        let res = set_icc_regs(&gic_fd.device_fd(), &gicr_typer, &state);
        assert!(res.is_err());
        assert_eq!(
            format!("{:?}", res.unwrap_err()),
            "DeviceAttribute(Error(9), true, 5)"
        );

        let res = get_icc_regs(&gic_fd.device_fd(), &gicr_typer);
        assert!(res.is_err());
        assert_eq!(
            format!("{:?}", res.unwrap_err()),
            "DeviceAttribute(Error(9), false, 5)"
        );
    }
}
