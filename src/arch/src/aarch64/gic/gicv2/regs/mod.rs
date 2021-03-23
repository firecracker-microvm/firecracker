// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod dist_regs;
mod icc_regs;

use kvm_ioctls::DeviceFd;

use crate::aarch64::gic::{
    regs::{GicState, GicVcpuState},
    Error, Result,
};

/// Save the state of the GIC device.
pub fn save_state(fd: &DeviceFd, mpidrs: &[u64]) -> Result<GicState> {
    let mut vcpu_states = Vec::with_capacity(mpidrs.len());
    for mpidr in mpidrs {
        vcpu_states.push(GicVcpuState {
            rdist: Vec::new(),
            icc: icc_regs::get_icc_regs(fd, *mpidr)?,
        })
    }

    Ok(GicState {
        dist: dist_regs::get_dist_regs(fd)?,
        gic_vcpu_states: vcpu_states,
    })
}

/// Restore the state of the GIC device.
pub fn restore_state(fd: &DeviceFd, mpidrs: &[u64], state: &GicState) -> Result<()> {
    dist_regs::set_dist_regs(fd, &state.dist)?;

    if mpidrs.len() != state.gic_vcpu_states.len() {
        return Err(Error::InconsistentVcpuCount);
    }
    for (mpidr, vcpu_state) in mpidrs.iter().zip(&state.gic_vcpu_states) {
        icc_regs::set_icc_regs(fd, *mpidr, &vcpu_state.icc)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::gic::{create_gic, GICVersion};
    use kvm_ioctls::Kvm;

    #[test]
    fn test_vm_save_restore_state() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let gic_fd = match create_gic(&vm, 1, Some(GICVersion::GICV2)) {
            Ok(gic_fd) => gic_fd,
            Err(Error::CreateGIC(_)) => return,
            _ => panic!("Failed to open setup GICv2"),
        };

        let mpidr = vec![0];
        let res = save_state(&gic_fd.device_fd(), &mpidr);
        // We will receive an error if trying to call before creating vcpu.
        assert!(res.is_err());
        assert_eq!(
            format!("{:?}", res.unwrap_err()),
            "DeviceAttribute(Error(22), false, 2)"
        );

        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let _vcpu = vm.create_vcpu(0).unwrap();
        let gic = create_gic(&vm, 1, Some(GICVersion::GICV2)).expect("Cannot create gic");
        let gic_fd = gic.device_fd();

        let vm_state = save_state(gic_fd, &mpidr).unwrap();
        let val: u32 = 0;
        let gicd_statusr_off = 0x0010;
        let mut gic_dist_attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_DIST_REGS,
            attr: gicd_statusr_off as u64,
            addr: &val as *const u32 as u64,
            flags: 0,
        };
        gic_fd.get_device_attr(&mut gic_dist_attr).unwrap();

        // The second value from the list of distributor registers is the value of the GICD_STATUSR register.
        // We assert that the one saved in the bitmap is the same with the one we obtain
        // with KVM_GET_DEVICE_ATTR.
        let gicd_statusr = &vm_state.dist[1];

        assert_eq!(gicd_statusr.chunks[0], val);
        assert_eq!(vm_state.dist.len(), 7);
        assert!(restore_state(gic_fd, &mpidr, &vm_state).is_ok());
    }
}
