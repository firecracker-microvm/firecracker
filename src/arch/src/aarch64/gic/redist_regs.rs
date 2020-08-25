// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::{Error, Result};
use kvm_bindings::*;
use kvm_ioctls::DeviceFd;

// Relevant PPI redistributor registers that we want to save/restore.
const GICR_CTLR: RedistReg = RedistReg::new(0x0000, 4);
const GICR_STATUSR: RedistReg = RedistReg::new(0x0010, 4);
const GICR_WAKER: RedistReg = RedistReg::new(0x0014, 4);
const GICR_PROPBASER: RedistReg = RedistReg::new(0x0070, 8);
const GICR_PENDBASER: RedistReg = RedistReg::new(0x0078, 8);

// Relevant SGI redistributor registers that we want to save/restore.
const GICR_SGI_OFFSET: u32 = 0x0001_0000;
const GICR_IGROUPR0: RedistReg = RedistReg::new(GICR_SGI_OFFSET + 0x0080, 4);
const GICR_ICENABLER0: RedistReg = RedistReg::new(GICR_SGI_OFFSET + 0x0180, 4);
const GICR_ISENABLER0: RedistReg = RedistReg::new(GICR_SGI_OFFSET + 0x0100, 4);
const GICR_ISPENDR0: RedistReg = RedistReg::new(GICR_SGI_OFFSET + 0x0200, 8);
const GICR_ICPENDR0: RedistReg = RedistReg::new(GICR_SGI_OFFSET + 0x0280, 4);
const GICR_ISACTIVER0: RedistReg = RedistReg::new(GICR_SGI_OFFSET + 0x0300, 4);
const GICR_ICACTIVER0: RedistReg = RedistReg::new(GICR_SGI_OFFSET + 0x0380, 4);
const GICR_IPRIORITYR0: RedistReg = RedistReg::new(GICR_SGI_OFFSET + 0x0400, 4);
const GICR_ICFGR0: RedistReg = RedistReg::new(GICR_SGI_OFFSET + 0x0C00, 32);

// List with relevant redistributor registers that we will be restoring.
static VGIC_RDIST_REGS: &[RedistReg] = &[
    GICR_CTLR,
    GICR_STATUSR,
    GICR_WAKER,
    GICR_PROPBASER,
    GICR_PENDBASER,
];

// List with relevant SGI associated redistributor registers that we will be restoring.
static VGIC_SGI_REGS: &[RedistReg] = &[
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

const KVM_DEV_ARM_VGIC_V3_MPIDR_SHIFT: u32 = 32;
const KVM_DEV_ARM_VGIC_V3_MPIDR_MASK: u64 = 0xffff_ffff << KVM_DEV_ARM_VGIC_V3_MPIDR_SHIFT as u64;

// All or at least the registers we are interested in are 32 bit, so
// we use a constant for size(u32).
const REG_SIZE: u8 = 4;

/// This is how we represent the registers of a redistributor.
/// It is relevant their offset from the base address of the redistributor.
/// Each register has a different number of bits_per_irq and is therefore variable length.
/// First 32 interrupts (0-32) are private to each CPU (SGIs and PPIs).
/// and so we save the first irq to identify between the type of the interrupt
/// that the respective register deals with.
struct RedistReg {
    /// Offset from redistributor address.
    base: u32,
    /// Length of the register.
    length: u8,
}

impl RedistReg {
    const fn new(base: u32, length: u8) -> RedistReg {
        RedistReg { base, length }
    }
}

// Helps with differentiating between register fetching or storing in functions.
enum Action<'a> {
    Set(&'a [u32], usize),
    Get(&'a mut Vec<u32>),
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn access_redist_attr(fd: &DeviceFd, offset: u32, typer: u64, val: &u32, set: bool) -> Result<()> {
    let mut gic_dist_attr = kvm_device_attr {
        group: KVM_DEV_ARM_VGIC_GRP_REDIST_REGS,
        attr: (typer & KVM_DEV_ARM_VGIC_V3_MPIDR_MASK) | (offset as u64), // this needs the mpidr
        addr: val as *const u32 as u64,
        flags: 0,
    };
    if set {
        fd.set_device_attr(&gic_dist_attr)
            .map_err(|e| Error::DeviceAttribute(e, true, KVM_DEV_ARM_VGIC_GRP_REDIST_REGS))?;
    } else {
        fd.get_device_attr(&mut gic_dist_attr)
            .map_err(|e| Error::DeviceAttribute(e, false, KVM_DEV_ARM_VGIC_GRP_REDIST_REGS))?;
    }
    Ok(())
}

fn access_redist_reg_list(
    fd: &DeviceFd,
    gicr_typer: &[u64],
    reg_list: &'static [RedistReg],
    action: &mut Action,
) -> Result<()> {
    for i in gicr_typer {
        for redist_reg in reg_list {
            let mut base = redist_reg.base;
            let end = base + redist_reg.length as u32;

            while base < end {
                match action {
                    Action::Set(state, idx) => {
                        access_redist_attr(fd, base, *i, &state[*idx], true)?;
                        *idx += 1;
                    }
                    Action::Get(state) => {
                        let val = 0;
                        access_redist_attr(fd, base, *i, &val, false)?;
                        state.push(val);
                    }
                }
                base += REG_SIZE as u32;
            }
        }
    }
    Ok(())
}

/// Get redistributor registers.
pub fn get_redist_regs(fd: &DeviceFd, gicr_typer: &[u64]) -> Result<Vec<u32>> {
    let mut state = Vec::new();
    let mut action = Action::Get(&mut state);
    access_redist_reg_list(fd, &gicr_typer, VGIC_RDIST_REGS, &mut action)?;
    access_redist_reg_list(fd, &gicr_typer, VGIC_SGI_REGS, &mut action)?;
    Ok(state)
}

/// Set redistributor registers.
pub fn set_redist_regs(fd: &DeviceFd, gicr_typer: &[u64], state: &[u32]) -> Result<()> {
    let mut action = Action::Set(state, 0);
    access_redist_reg_list(fd, gicr_typer, VGIC_RDIST_REGS, &mut action)?;
    access_redist_reg_list(fd, gicr_typer, VGIC_SGI_REGS, &mut action)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::gic::create_gic;
    use kvm_ioctls::Kvm;
    use std::os::unix::io::AsRawFd;

    #[test]
    fn test_access_redist_regs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let _ = vm.create_vcpu(0).unwrap();
        let gic_fd = create_gic(&vm, 1).expect("Cannot create gic");

        let mut gicr_typer = Vec::new();
        gicr_typer.push(123);
        let res = get_redist_regs(&gic_fd.device_fd(), &gicr_typer);
        assert!(res.is_ok());
        let state = res.unwrap();
        assert_eq!(state.len(), 24);

        assert!(set_redist_regs(&gic_fd.device_fd(), &gicr_typer, &state).is_ok());

        unsafe { libc::close(gic_fd.device_fd().as_raw_fd()) };

        let res = set_redist_regs(&gic_fd.device_fd(), &gicr_typer, &state);
        assert!(res.is_err());
        assert_eq!(
            format!("{:?}", res.unwrap_err()),
            "DeviceAttribute(Error(9), true, 5)"
        );

        let res = get_redist_regs(&gic_fd.device_fd(), &gicr_typer);
        assert!(res.is_err());
        assert_eq!(
            format!("{:?}", res.unwrap_err()),
            "DeviceAttribute(Error(9), false, 5)"
        );
    }
}
