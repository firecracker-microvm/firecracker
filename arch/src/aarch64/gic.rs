// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{io, result};

use kvm_ioctls::{DeviceFd, VmFd};

// Unfortunately bindgen omits defines that are based on other defines.
// See arch/arm64/include/uapi/asm/kvm.h file from the linux kernel.
const SZ_64K: u64 = 0x0001_0000;
const KVM_VGIC_V3_DIST_SIZE: u64 = SZ_64K;
const KVM_VGIC_V3_REDIST_SIZE: u64 = (2 * SZ_64K);

#[derive(Debug)]
pub enum Error {
    /// Error while calling KVM ioctl for setting up the global interrupt controller.
    CreateGIC(io::Error),
    /// Error while setting device attributes for the GIC.
    SetDeviceAttribute(io::Error),
}

pub type Result<T> = result::Result<T, Error>;

/// Create a GICv3 device.
///
/// Logic from this function is based on virt/kvm/arm/vgic/vgic-kvm-device.c from linux kernel.
pub fn create_gicv3(vm: &VmFd, vcpu_count: u8) -> Result<DeviceFd> {
    /* We are creating a V3 GIC.
     As per https://static.docs.arm.com/dai0492/b/GICv3_Software_Overview_Official_Release_B.pdf,
     section 3.5 Programmers' model, the register interface of a GICv3 interrupt controller is split
     into three groups: distributor, redistributor, CPU.
     As per Figure 9 from same section, there is 1 Distributor and multiple redistributors (one per
     each CPU).
    */
    let mut gic_device = kvm_bindings::kvm_create_device {
        type_: kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
        fd: 0,
        flags: 0,
    };

    let vgic_fd = vm
        .create_device(&mut gic_device)
        .map_err(Error::CreateGIC)?;

    /* Setting up the distributor attribute.
     We are placing the GIC below 1GB so we need to substract the size of the distributor.
    */
    let dist_attr = kvm_bindings::kvm_device_attr {
        group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
        attr: u64::from(kvm_bindings::KVM_VGIC_V3_ADDR_TYPE_DIST),
        addr: &get_dist_addr() as *const u64 as u64,
        flags: 0,
    };
    vgic_fd
        .set_device_attr(&dist_attr)
        .map_err(Error::SetDeviceAttribute)?;

    /* Setting up the redistributors' attribute.
    We are calculating here the start of the redistributors address. We have one per CPU.
    */
    let redists_attr = kvm_bindings::kvm_device_attr {
        group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
        attr: u64::from(kvm_bindings::KVM_VGIC_V3_ADDR_TYPE_REDIST),
        addr: &get_redists_addr(u64::from(vcpu_count)) as *const u64 as u64,
        flags: 0,
    };
    vgic_fd
        .set_device_attr(&redists_attr)
        .map_err(Error::SetDeviceAttribute)?;

    /* We need to tell the kernel how many irqs to support with this vgic.
    See the `layout` module for details.
    */
    let nr_irqs: u32 = super::layout::IRQ_MAX - super::layout::IRQ_BASE + 1;
    let nr_irqs_ptr = &nr_irqs as *const u32;
    let nr_irqs_attr = kvm_bindings::kvm_device_attr {
        group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
        attr: 0,
        addr: nr_irqs_ptr as u64,
        flags: 0,
    };
    vgic_fd
        .set_device_attr(&nr_irqs_attr)
        .map_err(Error::SetDeviceAttribute)?;

    /* Finalize the GIC.
         See https://code.woboq.org/linux/linux/virt/kvm/arm/vgic/vgic-kvm-device.c.html#211.
    */
    let init_gic_attr = kvm_bindings::kvm_device_attr {
        group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
        attr: u64::from(kvm_bindings::KVM_DEV_ARM_VGIC_CTRL_INIT),
        addr: 0,
        flags: 0,
    };
    vgic_fd
        .set_device_attr(&init_gic_attr)
        .map_err(Error::SetDeviceAttribute)?;

    Ok(vgic_fd)
}

// Auxiliary functions for getting addresses and size of where the distributor and redistributor
// are placed.
/// Get the address of the GIC distributor.
pub fn get_dist_addr() -> u64 {
    super::layout::MAPPED_IO_START - KVM_VGIC_V3_DIST_SIZE
}

/// Get the size of the GIC distributor.
pub fn get_dist_size() -> u64 {
    KVM_VGIC_V3_DIST_SIZE
}

/// Get the address of the GIC redistributors.
pub fn get_redists_addr(vcpu_count: u64) -> u64 {
    get_dist_addr() - get_redists_size(vcpu_count)
}

/// Get the size of the GIC redistributors.
pub fn get_redists_size(vcpu_count: u64) -> u64 {
    vcpu_count * KVM_VGIC_V3_REDIST_SIZE
}

#[cfg(test)]
mod tests {

    use super::*;
    use kvm_ioctls::Kvm;

    #[test]
    fn test_create_gicv3() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        assert!(create_gicv3(&vm, 1).is_ok());
    }
}
