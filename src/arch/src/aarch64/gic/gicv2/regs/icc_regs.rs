// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use kvm_bindings::*;
use kvm_ioctls::DeviceFd;

use crate::aarch64::gic::{
    regs::{SimpleReg, VgicRegEngine, VgicSysRegsState},
    Result,
};

// CPU interface registers as detailed at page 76 from
// https://developer.arm.com/documentation/ihi0048/latest/.
// Address offsets are relative to the cpu interface base address defined
// by the system memory map.
// Criteria for the present list of registers: only R/W registers, optional registers are not saved.
// GICC_NSAPR are not saved since they are only present in GICv2 implementations that include the GIC
// security extensions so it might crash on some systems.
const GICC_CTLR: SimpleReg = SimpleReg::new(0x0, 4);
const GICC_PMR: SimpleReg = SimpleReg::new(0x04, 4);
const GICC_BPR: SimpleReg = SimpleReg::new(0x08, 4);
const GICC_APBR: SimpleReg = SimpleReg::new(0x001C, 4);
const GICC_APR1: SimpleReg = SimpleReg::new(0x00D0, 4);
const GICC_APR2: SimpleReg = SimpleReg::new(0x00D4, 4);
const GICC_APR3: SimpleReg = SimpleReg::new(0x00D8, 4);
const GICC_APR4: SimpleReg = SimpleReg::new(0x00DC, 4);

// NOTICE: Any changes to this structure require a snapshot version bump.
static MAIN_VGIC_ICC_REGS: &[SimpleReg] = &[
    GICC_CTLR, GICC_PMR, GICC_BPR, GICC_APBR, GICC_APR1, GICC_APR2, GICC_APR3, GICC_APR4,
];

const KVM_DEV_ARM_VGIC_CPUID_SHIFT: u32 = 32;
const KVM_DEV_ARM_VGIC_OFFSET_SHIFT: u32 = 0;

struct VgicSysRegEngine {}

impl VgicRegEngine for VgicSysRegEngine {
    type Reg = SimpleReg;
    type RegChunk = u64;

    fn group() -> u32 {
        KVM_DEV_ARM_VGIC_GRP_CPU_REGS
    }

    fn kvm_device_attr(offset: u64, val: &mut Self::RegChunk, cpuid: u64) -> kvm_device_attr {
        kvm_device_attr {
            group: Self::group(),
            attr: ((cpuid << KVM_DEV_ARM_VGIC_CPUID_SHIFT)
                & (0xff << KVM_DEV_ARM_VGIC_CPUID_SHIFT))
                | ((offset << KVM_DEV_ARM_VGIC_OFFSET_SHIFT)
                    & (0xffffffff << KVM_DEV_ARM_VGIC_OFFSET_SHIFT)),
            addr: val as *mut Self::RegChunk as u64,
            flags: 0,
        }
    }
}

pub(crate) fn get_icc_regs(fd: &DeviceFd, mpidr: u64) -> Result<VgicSysRegsState> {
    let main_icc_regs =
        VgicSysRegEngine::get_regs_data(fd, Box::new(MAIN_VGIC_ICC_REGS.iter()), mpidr)?;

    Ok(VgicSysRegsState {
        main_icc_regs,
        ap_icc_regs: Vec::new(),
    })
}

pub(crate) fn set_icc_regs(fd: &DeviceFd, mpidr: u64, state: &VgicSysRegsState) -> Result<()> {
    VgicSysRegEngine::set_regs_data(
        fd,
        Box::new(MAIN_VGIC_ICC_REGS.iter()),
        &state.main_icc_regs,
        mpidr,
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::gic::{create_gic, Error, GICVersion};
    use kvm_ioctls::Kvm;
    use std::os::unix::io::AsRawFd;

    #[test]
    fn test_access_icc_regs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let _ = vm.create_vcpu(0).unwrap();
        let gic_fd = match create_gic(&vm, 1, Some(GICVersion::GICV2)) {
            Ok(gic_fd) => gic_fd,
            Err(Error::CreateGIC(_)) => return,
            _ => panic!("Failed to open setup GICv2"),
        };

        let cpu_id = 0;
        let res = get_icc_regs(&gic_fd.device_fd(), cpu_id);
        assert!(res.is_ok());

        let state = res.unwrap();
        assert_eq!(state.main_icc_regs.len(), 8);
        assert_eq!(state.ap_icc_regs.len(), 0);

        assert!(set_icc_regs(&gic_fd.device_fd(), cpu_id, &state).is_ok());

        unsafe { libc::close(gic_fd.device_fd().as_raw_fd()) };

        let res = set_icc_regs(&gic_fd.device_fd(), cpu_id, &state);
        assert!(res.is_err());
        assert_eq!(
            format!("{:?}", res.unwrap_err()),
            "DeviceAttribute(Error(9), true, 2)"
        );

        let res = get_icc_regs(&gic_fd.device_fd(), cpu_id);
        assert!(res.is_err());
        assert_eq!(
            format!("{:?}", res.unwrap_err()),
            "DeviceAttribute(Error(9), false, 2)"
        );
    }
}
