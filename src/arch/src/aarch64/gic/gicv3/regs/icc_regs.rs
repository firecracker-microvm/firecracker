// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::aarch64::gic::regs::{GicRegState, SimpleReg, VgicRegEngine};
use crate::aarch64::gic::{Error, Result};
use kvm_bindings::*;
use kvm_ioctls::DeviceFd;

use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;

const ICC_CTLR_EL1_PRIBITS_SHIFT: u64 = 8;
const ICC_CTLR_EL1_PRIBITS_MASK: u64 = 7 << ICC_CTLR_EL1_PRIBITS_SHIFT;

const SYS_ICC_SRE_EL1: SimpleReg = SimpleReg::vgic_sys_reg(3, 0, 12, 12, 5);
const SYS_ICC_CTLR_EL1: SimpleReg = SimpleReg::vgic_sys_reg(3, 0, 12, 12, 4);
const SYS_ICC_IGRPEN0_EL1: SimpleReg = SimpleReg::vgic_sys_reg(3, 0, 12, 12, 6);
const SYS_ICC_IGRPEN1_EL1: SimpleReg = SimpleReg::vgic_sys_reg(3, 0, 12, 12, 7);
const SYS_ICC_PMR_EL1: SimpleReg = SimpleReg::vgic_sys_reg(3, 0, 4, 6, 0);
const SYS_ICC_BPR0_EL1: SimpleReg = SimpleReg::vgic_sys_reg(3, 0, 12, 8, 3);
const SYS_ICC_BPR1_EL1: SimpleReg = SimpleReg::vgic_sys_reg(3, 0, 12, 12, 3);

const SYS_ICC_AP0R0_EL1: SimpleReg = SimpleReg::sys_icc_ap0rn_el1(0);
const SYS_ICC_AP0R1_EL1: SimpleReg = SimpleReg::sys_icc_ap0rn_el1(1);
const SYS_ICC_AP0R2_EL1: SimpleReg = SimpleReg::sys_icc_ap0rn_el1(2);
const SYS_ICC_AP0R3_EL1: SimpleReg = SimpleReg::sys_icc_ap0rn_el1(3);

const SYS_ICC_AP1R0_EL1: SimpleReg = SimpleReg::sys_icc_ap1rn_el1(0);
const SYS_ICC_AP1R1_EL1: SimpleReg = SimpleReg::sys_icc_ap1rn_el1(1);
const SYS_ICC_AP1R2_EL1: SimpleReg = SimpleReg::sys_icc_ap1rn_el1(2);
const SYS_ICC_AP1R3_EL1: SimpleReg = SimpleReg::sys_icc_ap1rn_el1(3);

static MAIN_VGIC_ICC_REGS: &[SimpleReg] = &[
    SYS_ICC_SRE_EL1,
    SYS_ICC_CTLR_EL1,
    SYS_ICC_IGRPEN0_EL1,
    SYS_ICC_IGRPEN1_EL1,
    SYS_ICC_PMR_EL1,
    SYS_ICC_BPR0_EL1,
    SYS_ICC_BPR1_EL1,
];

static AP_VGIC_ICC_REGS: &[SimpleReg] = &[
    SYS_ICC_AP0R0_EL1,
    SYS_ICC_AP0R1_EL1,
    SYS_ICC_AP0R2_EL1,
    SYS_ICC_AP0R3_EL1,
    SYS_ICC_AP1R0_EL1,
    SYS_ICC_AP1R1_EL1,
    SYS_ICC_AP1R2_EL1,
    SYS_ICC_AP1R3_EL1,
];

impl SimpleReg {
    const fn vgic_sys_reg(op0: u64, op1: u64, crn: u64, crm: u64, op2: u64) -> SimpleReg {
        let offset = (((op0 as u64) << KVM_REG_ARM64_SYSREG_OP0_SHIFT)
            & KVM_REG_ARM64_SYSREG_OP0_MASK as u64)
            | (((op1 as u64) << KVM_REG_ARM64_SYSREG_OP1_SHIFT)
                & KVM_REG_ARM64_SYSREG_OP1_MASK as u64)
            | (((crn as u64) << KVM_REG_ARM64_SYSREG_CRN_SHIFT)
                & KVM_REG_ARM64_SYSREG_CRN_MASK as u64)
            | (((crm as u64) << KVM_REG_ARM64_SYSREG_CRM_SHIFT)
                & KVM_REG_ARM64_SYSREG_CRM_MASK as u64)
            | (((op2 as u64) << KVM_REG_ARM64_SYSREG_OP2_SHIFT)
                & KVM_REG_ARM64_SYSREG_OP2_MASK as u64);

        SimpleReg::new(offset, 8)
    }

    const fn sys_icc_ap0rn_el1(n: u64) -> SimpleReg {
        Self::vgic_sys_reg(3, 0, 12, 8, 4 | n)
    }

    const fn sys_icc_ap1rn_el1(n: u64) -> SimpleReg {
        Self::vgic_sys_reg(3, 0, 12, 9, n)
    }
}

/// Structure for serializing the state of the Vgic ICC regs
#[derive(Debug, Default, Versionize)]
pub struct VgicSysRegsState {
    main_icc_regs: Vec<GicRegState<u64>>,
    ap_icc_regs: Vec<Option<GicRegState<u64>>>,
}

struct VgicSysRegEngine {}

impl VgicRegEngine for VgicSysRegEngine {
    type Reg = SimpleReg;
    type RegChunk = u64;

    fn group() -> u32 {
        KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS
    }

    fn mpidr_mask() -> u64 {
        KVM_DEV_ARM_VGIC_V3_MPIDR_MASK as u64
    }
}

fn num_priority_bits(fd: &DeviceFd, mpidr: u64) -> Result<u64> {
    let reg_val = &VgicSysRegEngine::get_reg_data(fd, &SYS_ICC_CTLR_EL1, mpidr)?.chunks[0];

    Ok(((reg_val & ICC_CTLR_EL1_PRIBITS_MASK) >> ICC_CTLR_EL1_PRIBITS_SHIFT) + 1)
}

fn is_ap_reg_available(reg: &SimpleReg, num_priority_bits: u64) -> bool {
    // As per ARMv8 documentation:
    // https://static.docs.arm.com/ihi0069/c/IHI0069C_gic_architecture_specification.pdf
    // page 178,
    // ICC_AP0R1_EL1 is only implemented in implementations that support 6 or more bits of
    // priority.
    // ICC_AP0R2_EL1 and ICC_AP0R3_EL1 are only implemented in implementations that support
    // 7 bits of priority.
    if (reg == &SYS_ICC_AP0R1_EL1 || reg == &SYS_ICC_AP1R1_EL1) && num_priority_bits < 6 {
        return false;
    }
    if (reg == &SYS_ICC_AP0R2_EL1
        || reg == &SYS_ICC_AP0R3_EL1
        || reg == &SYS_ICC_AP1R2_EL1
        || reg == &SYS_ICC_AP1R3_EL1)
        && num_priority_bits != 7
    {
        return false;
    }

    true
}

pub(crate) fn get_icc_regs(fd: &DeviceFd, mpidr: u64) -> Result<VgicSysRegsState> {
    let main_icc_regs =
        VgicSysRegEngine::get_regs_data(fd, Box::new(MAIN_VGIC_ICC_REGS.iter()), mpidr)?;
    let num_priority_bits = num_priority_bits(fd, mpidr)?;

    let mut ap_icc_regs = Vec::with_capacity(AP_VGIC_ICC_REGS.len());
    for reg in AP_VGIC_ICC_REGS {
        if is_ap_reg_available(reg, num_priority_bits) {
            ap_icc_regs.push(Some(VgicSysRegEngine::get_reg_data(fd, reg, mpidr)?));
        } else {
            ap_icc_regs.push(None);
        }
    }

    Ok(VgicSysRegsState {
        main_icc_regs,
        ap_icc_regs,
    })
}

pub(crate) fn set_icc_regs(fd: &DeviceFd, mpidr: u64, state: &VgicSysRegsState) -> Result<()> {
    VgicSysRegEngine::set_regs_data(
        fd,
        Box::new(MAIN_VGIC_ICC_REGS.iter()),
        &state.main_icc_regs,
        mpidr,
    )?;
    let num_priority_bits = num_priority_bits(fd, mpidr)?;

    for (reg, maybe_reg_data) in AP_VGIC_ICC_REGS.iter().zip(&state.ap_icc_regs) {
        if is_ap_reg_available(reg, num_priority_bits) != maybe_reg_data.is_some() {
            return Err(Error::InvalidVgicSysRegState);
        }

        if let Some(reg_data) = maybe_reg_data {
            VgicSysRegEngine::set_reg_data(fd, reg, reg_data, mpidr)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::gic::create_gic;
    use kvm_ioctls::Kvm;
    use std::os::unix::io::AsRawFd;

    #[test]
    fn test_access_icc_regs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let _ = vm.create_vcpu(0).unwrap();
        let gic_fd = create_gic(&vm, 1).expect("Cannot create gic");

        let gicr_typer = 123;
        let res = get_icc_regs(&gic_fd.device_fd(), gicr_typer);
        assert!(res.is_ok());
        let mut state = res.unwrap();
        assert_eq!(state.main_icc_regs.len(), 7);
        assert_eq!(state.ap_icc_regs.len(), 8);

        assert!(set_icc_regs(&gic_fd.device_fd(), gicr_typer, &state).is_ok());

        for reg in state.ap_icc_regs.iter_mut() {
            *reg = None;
        }
        let res = set_icc_regs(&gic_fd.device_fd(), gicr_typer, &state);
        assert!(res.is_err());
        assert_eq!(format!("{:?}", res.unwrap_err()), "InvalidVgicSysRegState");

        unsafe { libc::close(gic_fd.device_fd().as_raw_fd()) };

        let res = set_icc_regs(&gic_fd.device_fd(), gicr_typer, &state);
        assert!(res.is_err());
        assert_eq!(
            format!("{:?}", res.unwrap_err()),
            "DeviceAttribute(Error(9), true, 6)"
        );

        let res = get_icc_regs(&gic_fd.device_fd(), gicr_typer);
        assert!(res.is_err());
        assert_eq!(
            format!("{:?}", res.unwrap_err()),
            "DeviceAttribute(Error(9), false, 6)"
        );
    }
}
