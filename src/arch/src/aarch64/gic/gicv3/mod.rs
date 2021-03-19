// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod regs;
use std::{boxed::Box, result};

use crate::aarch64::gic::{Error, GICDevice};
use kvm_ioctls::DeviceFd;
pub use regs::{restore_state, save_state, GicState};

type Result<T> = result::Result<T, Error>;

pub(crate) struct GICv3 {
    /// The file descriptor for the KVM device
    fd: DeviceFd,

    /// GIC device properties, to be used for setting up the fdt entry
    properties: [u64; 4],

    /// Number of CPUs handled by the device
    vcpu_count: u64,
}

impl GICv3 {
    // Unfortunately bindgen omits defines that are based on other defines.
    // See arch/arm64/include/uapi/asm/kvm.h file from the linux kernel.
    const SZ_64K: u64 = 0x0001_0000;
    const KVM_VGIC_V3_DIST_SIZE: u64 = GICv3::SZ_64K;
    const KVM_VGIC_V3_REDIST_SIZE: u64 = (2 * GICv3::SZ_64K);

    // Device trees specific constants
    const ARCH_GIC_V3_MAINT_IRQ: u32 = 9;

    /// Get the address of the GIC distributor.
    fn get_dist_addr() -> u64 {
        super::layout::MAPPED_IO_START - GICv3::KVM_VGIC_V3_DIST_SIZE
    }

    /// Get the size of the GIC distributor.
    fn get_dist_size() -> u64 {
        GICv3::KVM_VGIC_V3_DIST_SIZE
    }

    /// Get the address of the GIC redistributors.
    fn get_redists_addr(vcpu_count: u64) -> u64 {
        GICv3::get_dist_addr() - GICv3::get_redists_size(vcpu_count)
    }

    /// Get the size of the GIC redistributors.
    fn get_redists_size(vcpu_count: u64) -> u64 {
        vcpu_count * GICv3::KVM_VGIC_V3_REDIST_SIZE
    }
}

impl GICDevice for GICv3 {
    fn version() -> u32 {
        kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3
    }

    fn device_fd(&self) -> &DeviceFd {
        &self.fd
    }

    fn device_properties(&self) -> &[u64] {
        &self.properties
    }

    fn vcpu_count(&self) -> u64 {
        self.vcpu_count
    }

    fn fdt_compatibility(&self) -> &str {
        "arm,gic-v3"
    }

    fn fdt_maint_irq(&self) -> u32 {
        GICv3::ARCH_GIC_V3_MAINT_IRQ
    }

    fn create_device(fd: DeviceFd, vcpu_count: u64) -> Box<dyn GICDevice> {
        Box::new(GICv3 {
            fd,
            properties: [
                GICv3::get_dist_addr(),
                GICv3::get_dist_size(),
                GICv3::get_redists_addr(vcpu_count),
                GICv3::get_redists_size(vcpu_count),
            ],
            vcpu_count,
        })
    }

    fn init_device_attributes(gic_device: &dyn GICDevice) -> Result<()> {
        /* Setting up the distributor attribute.
         We are placing the GIC below 1GB so we need to substract the size of the distributor.
        */
        Self::set_device_attribute(
            &gic_device.device_fd(),
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            u64::from(kvm_bindings::KVM_VGIC_V3_ADDR_TYPE_DIST),
            &GICv3::get_dist_addr() as *const u64 as u64,
            0,
        )?;

        /* Setting up the redistributors' attribute.
        We are calculating here the start of the redistributors address. We have one per CPU.
        */
        Self::set_device_attribute(
            &gic_device.device_fd(),
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            u64::from(kvm_bindings::KVM_VGIC_V3_ADDR_TYPE_REDIST),
            &GICv3::get_redists_addr(gic_device.vcpu_count()) as *const u64 as u64,
            0,
        )?;

        Ok(())
    }
}

/// Function that flushes
/// RDIST pending tables into guest RAM.
///
/// The tables get flushed to guest RAM whenever the VM gets stopped.
fn save_pending_tables(fd: &DeviceFd) -> Result<()> {
    let init_gic_attr = kvm_bindings::kvm_device_attr {
        group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
        attr: u64::from(kvm_bindings::KVM_DEV_ARM_VGIC_SAVE_PENDING_TABLES),
        addr: 0,
        flags: 0,
    };
    fd.set_device_attr(&init_gic_attr)
        .map_err(|e| Error::DeviceAttribute(e, true, kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::gic::create_gic;
    use kvm_ioctls::Kvm;

    #[test]
    fn test_save_pending_tables() {
        use std::os::unix::io::AsRawFd;

        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let gic = create_gic(&vm, 1).expect("Cannot create gic");
        assert!(save_pending_tables(&gic.device_fd()).is_ok());

        unsafe { libc::close(gic.device_fd().as_raw_fd()) };

        let res = save_pending_tables(&gic.device_fd());
        assert!(res.is_err());
        assert_eq!(
            format!("{:?}", res.unwrap_err()),
            "DeviceAttribute(Error(9), true, 4)"
        );
    }
}
