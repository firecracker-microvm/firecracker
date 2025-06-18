// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod dist_regs;
mod icc_regs;
mod redist_regs;

use kvm_ioctls::DeviceFd;

use crate::arch::aarch64::gic::GicError;
use crate::arch::aarch64::gic::regs::{GicState, GicVcpuState};
use log::error;

const GITS_CTLR: u32 = 0x0000;
const GITS_IIDR: u32 = 0x0004;
const GITS_CBASER: u32 = 0x0080;
const GITS_CWRITER: u32 = 0x0088;
const GITS_CREADR: u32 = 0x0090;
const GITS_BASER: u32 = 0x0100;

pub fn gicv3_its_attr_set(
    its_device: &DeviceFd,
    group: u32,
    attr: u32,
    val: u64,
) -> Result<(), GicError> {
    let gicv3_its_attr = kvm_bindings::kvm_device_attr {
        group,
        attr: attr as u64,
        addr: &val as *const u64 as u64,
        flags: 0,
    };

    its_device
        .set_device_attr(&gicv3_its_attr)
        .map_err(|err| GicError::DeviceAttribute(err, true, group))
}

pub fn gicv3_its_attr_get(its_device: &DeviceFd, group: u32, attr: u32) -> Result<u64, GicError> {
    let mut val = 0;

    let mut gicv3_its_attr = kvm_bindings::kvm_device_attr {
        group,
        attr: attr as u64,
        addr: &mut val as *mut u64 as u64,
        flags: 0,
    };

    // SAFETY: gicv3_its_attr.addr is safe to write to.
    unsafe { its_device.get_device_attr(&mut gicv3_its_attr) }
        .map_err(|err| GicError::DeviceAttribute(err, false, group))?;

    Ok(val)
}

/// Save the state of the GIC device.
pub fn save_state(
    gic_device: &DeviceFd,
    its_device: &DeviceFd,
    mpidrs: &[u64],
) -> Result<GicState, GicError> {
    // Flush redistributors pending tables to guest RAM.
    super::save_pending_tables(gic_device, its_device)?;

    let mut vcpu_states = Vec::with_capacity(mpidrs.len());
    for mpidr in mpidrs {
        vcpu_states.push(GicVcpuState {
            rdist: redist_regs::get_redist_regs(gic_device, *mpidr)?,
            icc: icc_regs::get_icc_regs(gic_device, *mpidr)?,
        })
    }

    let mut its_baser: [u64; 8] = [0; 8];
    for i in 0..8 {
        its_baser[i as usize] = gicv3_its_attr_get(
            its_device,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
            GITS_BASER + i * 8,
        )?;
    }

    let its_ctlr = gicv3_its_attr_get(
        its_device,
        kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
        GITS_CTLR,
    )?;

    let its_cbaser = gicv3_its_attr_get(
        its_device,
        kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
        GITS_CBASER,
    )?;

    let its_creadr = gicv3_its_attr_get(
        its_device,
        kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
        GITS_CREADR,
    )?;

    let its_cwriter = gicv3_its_attr_get(
        its_device,
        kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
        GITS_CWRITER,
    )?;

    let its_iidr = gicv3_its_attr_get(
        its_device,
        kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
        GITS_IIDR,
    )?;

    Ok(GicState {
        dist: dist_regs::get_dist_regs(gic_device)?,
        gic_vcpu_states: vcpu_states,
        its_ctlr,
        its_cbaser,
        its_creadr,
        its_cwriter,
        its_iidr,
        its_baser,
    })
}

/// Restore the state of the GIC device.
pub fn restore_state(
    gic_device: &DeviceFd,
    its_device: &DeviceFd,
    mpidrs: &[u64],
    state: &GicState,
) -> Result<(), GicError> {
    dist_regs::set_dist_regs(gic_device, &state.dist)?;

    if mpidrs.len() != state.gic_vcpu_states.len() {
        return Err(GicError::InconsistentVcpuCount);
    }
    for (mpidr, vcpu_state) in mpidrs.iter().zip(&state.gic_vcpu_states) {
        redist_regs::set_redist_regs(gic_device, *mpidr, &vcpu_state.rdist)?;
        icc_regs::set_icc_regs(gic_device, *mpidr, &vcpu_state.icc)?;
    }

    // Restore ITS registers
    gicv3_its_attr_set(
        its_device,
        kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
        GITS_IIDR,
        state.its_iidr,
    )?;

    gicv3_its_attr_set(
        its_device,
        kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
        GITS_CBASER,
        state.its_cbaser,
    )?;

    gicv3_its_attr_set(
        its_device,
        kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
        GITS_CREADR,
        state.its_creadr,
    )?;

    gicv3_its_attr_set(
        its_device,
        kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
        GITS_CWRITER,
        state.its_cwriter,
    )?;

    for i in 0..8 {
        gicv3_its_attr_set(
            its_device,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
            GITS_BASER + i * 8,
            state.its_baser[i as usize],
        )?;
    }

    gicv3_its_attr_set(
        its_device,
        kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
        kvm_bindings::KVM_DEV_ARM_ITS_RESTORE_TABLES,
        0,
    )
    .inspect_err(|err| error!("its: could not restore tables: {err:#?}"))?;

    gicv3_its_attr_set(
        its_device,
        kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
        GITS_CTLR,
        state.its_ctlr,
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]

    use kvm_ioctls::Kvm;

    use super::*;
    use crate::arch::aarch64::gic::{GICVersion, create_gic};

    #[test]
    fn test_vm_save_restore_state() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let gic = create_gic(&vm, 1, Some(GICVersion::GICV3)).expect("Cannot create gic");
        let gic_fd = gic.device_fd();
        let its_fd = gic.its_fd().unwrap();

        let mpidr = vec![1];
        let res = save_state(gic_fd, its_fd, &mpidr);
        // We will receive an error if trying to call before creating vcpu.
        assert_eq!(
            format!("{:?}", res.unwrap_err()),
            "DeviceAttribute(Error(22), false, 5)"
        );

        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let _vcpu = vm.create_vcpu(0).unwrap();
        let gic = create_gic(&vm, 1, Some(GICVersion::GICV3)).expect("Cannot create gic");
        let gic_fd = gic.device_fd();
        let its_fd = gic.its_fd().unwrap();

        let vm_state = save_state(gic_fd, its_fd, &mpidr).unwrap();
        let val: u32 = 0;
        let gicd_statusr_off = 0x0010u64;
        let mut gic_dist_attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_DIST_REGS,
            attr: gicd_statusr_off,
            addr: &val as *const u32 as u64,
            flags: 0,
        };
        unsafe {
            gic_fd.get_device_attr(&mut gic_dist_attr).unwrap();
        }

        // The second value from the list of distributor registers is the value of the GICD_STATUSR
        // register. We assert that the one saved in the bitmap is the same with the one we
        // obtain with KVM_GET_DEVICE_ATTR.
        let gicd_statusr = &vm_state.dist[1];

        assert_eq!(gicd_statusr.chunks[0], val);
        assert_eq!(vm_state.dist.len(), 12);
        restore_state(gic_fd, its_fd, &mpidr, &vm_state).unwrap();
        restore_state(gic_fd, its_fd, &[1, 2], &vm_state).unwrap_err();
    }
}
