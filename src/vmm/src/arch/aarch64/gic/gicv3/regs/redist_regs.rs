// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use kvm_bindings::*;
use kvm_ioctls::DeviceFd;

use crate::arch::aarch64::gic::GicError;
use crate::arch::aarch64::gic::regs::{GicRegState, SimpleReg, VgicRegEngine};

// Relevant PPI redistributor registers that we want to save/restore.
const GICR_CTLR: SimpleReg = SimpleReg::new(0x0000, 4);
const GICR_STATUSR: SimpleReg = SimpleReg::new(0x0010, 4);
const GICR_WAKER: SimpleReg = SimpleReg::new(0x0014, 4);
const GICR_PROPBASER: SimpleReg = SimpleReg::new(0x0070, 8);
const GICR_PENDBASER: SimpleReg = SimpleReg::new(0x0078, 8);

// Relevant SGI redistributor registers that we want to save/restore.
const GICR_SGI_OFFSET: u64 = 0x0001_0000;
const GICR_IGROUPR0: SimpleReg = SimpleReg::new(GICR_SGI_OFFSET + 0x0080, 4);
const GICR_ISENABLER0: SimpleReg = SimpleReg::new(GICR_SGI_OFFSET + 0x0100, 4);
const GICR_ICENABLER0: SimpleReg = SimpleReg::new(GICR_SGI_OFFSET + 0x0180, 4);
const GICR_ISPENDR0: SimpleReg = SimpleReg::new(GICR_SGI_OFFSET + 0x0200, 4);
const GICR_ICPENDR0: SimpleReg = SimpleReg::new(GICR_SGI_OFFSET + 0x0280, 4);
const GICR_ISACTIVER0: SimpleReg = SimpleReg::new(GICR_SGI_OFFSET + 0x0300, 4);
const GICR_ICACTIVER0: SimpleReg = SimpleReg::new(GICR_SGI_OFFSET + 0x0380, 4);
const GICR_IPRIORITYR0: SimpleReg = SimpleReg::new(GICR_SGI_OFFSET + 0x0400, 32);
const GICR_ICFGR0: SimpleReg = SimpleReg::new(GICR_SGI_OFFSET + 0x0C00, 8);

// List with relevant redistributor registers that we will be restoring.
static VGIC_RDIST_REGS: &[SimpleReg] = &[
    GICR_CTLR,
    GICR_STATUSR,
    GICR_WAKER,
    GICR_PROPBASER,
    GICR_PENDBASER,
];

// List with relevant SGI associated redistributor registers that we will be restoring.
static VGIC_SGI_REGS: &[SimpleReg] = &[
    GICR_IGROUPR0,
    GICR_ICENABLER0,
    GICR_ISENABLER0,
    GICR_ICFGR0,
    GICR_ICPENDR0,
    GICR_ISPENDR0,
    GICR_ICACTIVER0,
    GICR_ISACTIVER0,
    GICR_IPRIORITYR0,
];

struct RedistRegEngine {}

impl VgicRegEngine for RedistRegEngine {
    type Reg = SimpleReg;
    type RegChunk = u32;

    fn group() -> u32 {
        KVM_DEV_ARM_VGIC_GRP_REDIST_REGS
    }

    #[allow(clippy::cast_sign_loss)] // bit mask
    fn mpidr_mask() -> u64 {
        KVM_DEV_ARM_VGIC_V3_MPIDR_MASK as u64
    }
}

fn redist_regs() -> Box<dyn Iterator<Item = &'static SimpleReg>> {
    Box::new(VGIC_RDIST_REGS.iter().chain(VGIC_SGI_REGS))
}

pub(crate) fn get_redist_regs(
    fd: &DeviceFd,
    mpidr: u64,
) -> Result<Vec<GicRegState<u32>>, GicError> {
    RedistRegEngine::get_regs_data(fd, redist_regs(), mpidr)
}

pub(crate) fn set_redist_regs(
    fd: &DeviceFd,
    mpidr: u64,
    data: &[GicRegState<u32>],
) -> Result<(), GicError> {
    RedistRegEngine::set_regs_data(fd, redist_regs(), data, mpidr)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]
    use std::os::unix::io::AsRawFd;

    use kvm_ioctls::Kvm;

    use super::*;
    use crate::arch::aarch64::gic::{GICVersion, create_gic};

    #[test]
    fn test_access_redist_regs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let _ = vm.create_vcpu(0).unwrap();
        let gic_fd = create_gic(&vm, 1, Some(GICVersion::GICV3)).expect("Cannot create gic");

        let gicr_typer = 123;
        let res = get_redist_regs(gic_fd.device_fd(), gicr_typer);
        let state = res.unwrap();
        assert_eq!(state.len(), 14);

        set_redist_regs(gic_fd.device_fd(), gicr_typer, &state).unwrap();

        unsafe { libc::close(gic_fd.device_fd().as_raw_fd()) };

        let res = set_redist_regs(gic_fd.device_fd(), gicr_typer, &state);
        assert_eq!(
            format!("{:?}", res.unwrap_err()),
            "DeviceAttribute(Error(9), true, 5)"
        );

        let res = get_redist_regs(gic_fd.device_fd(), gicr_typer);
        assert_eq!(
            format!("{:?}", res.unwrap_err()),
            "DeviceAttribute(Error(9), false, 5)"
        );

        // dropping gic_fd would double close the gic fd, so leak it
        std::mem::forget(gic_fd);
    }
}
