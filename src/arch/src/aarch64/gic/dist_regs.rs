// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::{Error, Result};
use kvm_ioctls::DeviceFd;

// Distributor registers as detailed at page 456 from
// https://static.docs.arm.com/ihi0069/c/IHI0069C_gic_architecture_specification.pdf.
// Address offsets are relative to the Distributor base address defined
// by the system memory map. Unless otherwise stated in the register description,
// all GIC registers are 32-bits wide.
const GICD_CTLR: DistReg = DistReg::new(0x0, 0, 4);
const GICD_STATUSR: DistReg = DistReg::new(0x0010, 0, 4);
const GICD_IGROUPR: DistReg = DistReg::new(0x0080, 1, 0);
const GICD_ISENABLER: DistReg = DistReg::new(0x0100, 1, 0);
const GICD_ICENABLER: DistReg = DistReg::new(0x0180, 1, 0);
const GICD_ISPENDR: DistReg = DistReg::new(0x0200, 1, 0);
const GICD_ICPENDR: DistReg = DistReg::new(0x0280, 1, 0);
const GICD_ISACTIVER: DistReg = DistReg::new(0x0300, 1, 0);
const GICD_ICACTIVER: DistReg = DistReg::new(0x0380, 1, 0);
const GICD_IPRIORITYR: DistReg = DistReg::new(0x0400, 8, 0);
const GICD_ICFGR: DistReg = DistReg::new(0x0C00, 2, 0);
const GICD_IROUTER: DistReg = DistReg::new(0x6000, 64, 0);

// List with relevant distributor registers that we will be restoring.
// Order is taken from qemu.
static VGIC_DIST_REGS: &[DistReg] = &[
    GICD_CTLR,
    GICD_STATUSR,
    GICD_ICENABLER,
    GICD_ISENABLER,
    GICD_IGROUPR,
    GICD_IROUTER,
    GICD_ICFGR,
    GICD_ICPENDR,
    GICD_ISPENDR,
    GICD_ICACTIVER,
    GICD_ISACTIVER,
    GICD_IPRIORITYR,
];

// All or at least the registers we are interested in are 32 bit, so
// we use a constant for size(u32).
const REG_SIZE: u8 = 4;

// Helps with triggering either a register fetch or a store.
enum Action<'a> {
    Set(&'a [u32], usize),
    Get(&'a mut Vec<u32>),
}

/// This is how we represent the registers of the vgic's distributor.
/// Some of the distributor register (i.e GICD_STATUSR) are simple
/// registers (i.e they are associated to a 32 bit value).
/// However, there are other registers that have variable lengths since
/// they dedicate some of the 32 bits to some specific interrupt. So, their length
/// depends on the number of interrupts (i.e the ones that are represented as GICD_REG<n>)
/// in the documentation mentioned above.
struct DistReg {
    /// Offset from distributor address.
    base: u32,
    /// Bits per interrupt.
    /// Relevant for registers that DO share IRQs.
    bpi: u8,
    /// Length of the register.
    /// Relevant for registers that DO NOT share IRQs.
    length: u16,
}

impl DistReg {
    const fn new(base: u32, bpi: u8, length: u16) -> DistReg {
        DistReg { base, bpi, length }
    }

    fn compute_reg_range(&self, fd: &DeviceFd) -> Result<(u32, u32)> {
        // The ARM® TrustZone® implements a protection logic which contains a read-as-zero/write-ignore (RAZ/WI) policy
        // where:
        // * A blocked read operation will always return a zero value on the bus, preventing information leak
        // * A write operation to a forbidden region or peripheral will be ignored
        // The first part of a shared-irq type of register = (i.e GICD_<REG><0>) is RAZ/WI, so we compute the
        // base by shifting it with "REG_SIZE * self.bpi" bytes.
        let base = self.base + REG_SIZE as u32 * self.bpi as u32;
        let mut end = base;
        let num_irq = get_num_interrupts(fd)?;

        if self.length > 0 {
            // This is the single type register (i.e one that is not DIST_X<n>) and for which
            // the bpi is 0.
            // Look in the kernel for REGISTER_DESC_WITH_LENGTH.
            end = base + self.length as u32;
        }
        if self.bpi > 0 {
            // This is the type of register that takes into account the number of interrupts
            // that the model has. It is also the type of register where
            // a register relates to multiple interrupts.
            end = base + (self.bpi as u32 * (num_irq - super::super::layout::IRQ_BASE) / 8);
            if self.bpi as u32 * (num_irq - super::super::layout::IRQ_BASE) % 8 > 0 {
                end += REG_SIZE as u32;
            }
        }
        Ok((base, end))
    }

    #[allow(clippy::trivially_copy_pass_by_ref)]
    fn access_dist_attr(&self, fd: &DeviceFd, offset: u32, val: &u32, set: bool) -> Result<()> {
        let mut gic_dist_attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_DIST_REGS,
            attr: offset as u64,
            addr: val as *const u32 as u64,
            flags: 0,
        };
        if set {
            fd.set_device_attr(&gic_dist_attr).map_err(|e| {
                Error::DeviceAttribute(e, true, kvm_bindings::KVM_DEV_ARM_VGIC_GRP_DIST_REGS)
            })
        } else {
            fd.get_device_attr(&mut gic_dist_attr).map_err(|e| {
                Error::DeviceAttribute(e, false, kvm_bindings::KVM_DEV_ARM_VGIC_GRP_DIST_REGS)
            })
        }
    }
}

fn get_num_interrupts(fd: &DeviceFd) -> Result<u32> {
    let num_irqs = 0;

    let mut nr_irqs_attr = kvm_bindings::kvm_device_attr {
        group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
        attr: 0,
        addr: &num_irqs as *const u32 as u64,
        flags: 0,
    };
    fd.get_device_attr(&mut nr_irqs_attr).map_err(|e| {
        Error::DeviceAttribute(e, false, kvm_bindings::KVM_DEV_ARM_VGIC_GRP_NR_IRQS)
    })?;
    Ok(num_irqs)
}

fn access_dist_reg_list(fd: &DeviceFd, action: &mut Action) -> Result<()> {
    for dreg in VGIC_DIST_REGS {
        let (mut base, end) = dreg.compute_reg_range(fd)?;
        while base < end {
            match action {
                Action::Set(state, idx) => {
                    dreg.access_dist_attr(fd, base, &state[*idx], true)?;
                    *idx += 1;
                }
                Action::Get(state) => {
                    let val: u32 = 0;
                    dreg.access_dist_attr(fd, base, &val, false)?;
                    state.push(val);
                }
            }
            base += REG_SIZE as u32;
        }
    }
    Ok(())
}

/// Get distributor registers of the GIC.
pub fn get_dist_regs(fd: &DeviceFd) -> Result<Vec<u32>> {
    let mut state = Vec::new();
    let mut action = Action::Get(&mut state);
    access_dist_reg_list(fd, &mut action)?;
    Ok(state)
}

/// Set distributor registers of the GIC.
pub fn set_dist_regs(fd: &DeviceFd, state: &[u32]) -> Result<()> {
    let mut action = Action::Set(state, 0);
    access_dist_reg_list(fd, &mut action)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::gic::create_gic;
    use kvm_ioctls::Kvm;
    use std::os::unix::io::AsRawFd;

    #[test]
    fn test_access_dist_regs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let _ = vm.create_vcpu(0).unwrap();
        let gic_fd = create_gic(&vm, 1).expect("Cannot create gic");

        let res = get_dist_regs(&gic_fd.device_fd());
        assert!(res.is_ok());
        let state = res.unwrap();
        assert_eq!(state.len(), 245);

        let res = set_dist_regs(&gic_fd.device_fd(), &state);
        assert!(res.is_ok());

        unsafe { libc::close(gic_fd.device_fd().as_raw_fd()) };

        let res = get_dist_regs(&gic_fd.device_fd());
        assert!(res.is_err());
        assert_eq!(
            format!("{:?}", res.unwrap_err()),
            "DeviceAttribute(Error(9), false, 3)"
        );
    }
}
