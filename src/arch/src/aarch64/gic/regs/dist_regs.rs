// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::aarch64::gic::{Error, Result};
use crate::{IRQ_BASE, IRQ_MAX};
use kvm_ioctls::DeviceFd;

// Distributor registers as detailed at page 456 from
// https://static.docs.arm.com/ihi0069/c/IHI0069C_gic_architecture_specification.pdf.
// Address offsets are relative to the Distributor base address defined
// by the system memory map.
const GICD_CTLR: DistReg = DistReg::simple(0x0, 4);
const GICD_STATUSR: DistReg = DistReg::simple(0x0010, 4);
const GICD_IGROUPR: DistReg = DistReg::shared_irq(0x0080, 1);
const GICD_ISENABLER: DistReg = DistReg::shared_irq(0x0100, 1);
const GICD_ICENABLER: DistReg = DistReg::shared_irq(0x0180, 1);
const GICD_ISPENDR: DistReg = DistReg::shared_irq(0x0200, 1);
const GICD_ICPENDR: DistReg = DistReg::shared_irq(0x0280, 1);
const GICD_ISACTIVER: DistReg = DistReg::shared_irq(0x0300, 1);
const GICD_ICACTIVER: DistReg = DistReg::shared_irq(0x0380, 1);
const GICD_IPRIORITYR: DistReg = DistReg::shared_irq(0x0400, 8);
const GICD_ICFGR: DistReg = DistReg::shared_irq(0x0C00, 2);
const GICD_IROUTER: DistReg = DistReg::shared_irq(0x6000, 64);

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

// All or at least the registers we are interested in are multiples of 32 bits.
// So we access them in chunks of 4 bytes.
const U32_SIZE: u8 = 4;

// Helps with triggering either a register fetch or a store.
enum Action<'a> {
    Set(&'a [u32], usize),
    Get(&'a mut Vec<u32>),
}

enum DistRegSize {
    /// Some of the distributor register (i.e GICD_STATUSR) are simple
    /// registers (i.e they are associated to a 32 bit value).
    Simple { size: u16 },
    /// Other registers have variable lengths since they dedicate a specific number of bits to
    /// each interrupt. So, their length depends on the number of interrupts.
    /// (i.e the ones that are represented as GICD_REG<n>) in the documentation mentioned above.
    SharedIrq { bits_per_irq: u8 },
}

/// This is how we represent the registers of the vgic's distributor.
struct DistReg {
    /// Offset from distributor address.
    offset: u32,
    /// Distributor register size.
    size: DistRegSize,
}

impl DistReg {
    const fn simple(offset: u32, size: u16) -> DistReg {
        DistReg {
            offset,
            size: DistRegSize::Simple { size },
        }
    }

    const fn shared_irq(offset: u32, bits_per_irq: u8) -> DistReg {
        DistReg {
            offset,
            size: DistRegSize::SharedIrq { bits_per_irq },
        }
    }
}

impl DistReg {
    fn mem_iter(&self) -> impl Iterator<Item = u32> {
        let mut start = self.offset;
        let end = match self.size {
            DistRegSize::Simple { size } => start + u32::from(size),
            DistRegSize::SharedIrq { bits_per_irq } => {
                // The ARM® TrustZone® implements a protection logic which contains a
                // read-as-zero/write-ignore (RAZ/WI) policy.
                // The first part of a shared-irq register, the one corresponding to the
                // SGI and PPI IRQs (0-32) is RAZ/WI, so we skip it.
                start += IRQ_BASE * u32::from(bits_per_irq) / 8;

                let size_in_bits = u32::from(bits_per_irq) * (IRQ_MAX - IRQ_BASE);
                let mut size_in_bytes = size_in_bits / 8;
                if size_in_bits % 8 > 0 {
                    size_in_bytes += u32::from(U32_SIZE);
                }

                start + size_in_bytes
            }
        };

        (start..end).step_by(U32_SIZE as usize)
    }

    fn access_dist_attr(&self, fd: &DeviceFd, offset: u32, val: &mut u32, set: bool) -> Result<()> {
        let mut gic_dist_attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_DIST_REGS,
            attr: offset as u64,
            addr: val as *mut u32 as u64,
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

fn access_dist_reg_list(fd: &DeviceFd, action: &mut Action) -> Result<()> {
    for dreg in VGIC_DIST_REGS {
        for offset in dreg.mem_iter() {
            match action {
                Action::Set(state, idx) => {
                    let mut val = state[*idx];
                    dreg.access_dist_attr(fd, offset, &mut val, true)?;
                    *idx += 1;
                }
                Action::Get(state) => {
                    let mut val = 0;
                    dreg.access_dist_attr(fd, offset, &mut val, false)?;
                    state.push(val);
                }
            }
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
            "DeviceAttribute(Error(9), false, 1)"
        );
    }
}
