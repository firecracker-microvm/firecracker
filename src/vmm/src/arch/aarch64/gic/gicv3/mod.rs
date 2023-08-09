// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod regs;

use kvm_ioctls::{DeviceFd, VmFd};

use crate::arch::aarch64::gic::{GicError, GicState};

#[derive(Debug)]
pub struct GICv3(super::GIC);

impl std::ops::Deref for GICv3 {
    type Target = super::GIC;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
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

    pub const VERSION: u32 = kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3;

    pub fn fdt_compatibility(&self) -> &str {
        "arm,gic-v3"
    }

    pub fn fdt_maint_irq(&self) -> u32 {
        GICv3::ARCH_GIC_V3_MAINT_IRQ
    }

    /// Create the GIC device object
    pub fn create_device(fd: DeviceFd, vcpu_count: u64) -> Self {
        GICv3(super::GIC {
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

    pub fn save_device(&self, mpidrs: &[u64]) -> Result<GicState, GicError> {
        regs::save_state(&self.fd, mpidrs)
    }

    pub fn restore_device(&self, mpidrs: &[u64], state: &GicState) -> Result<(), GicError> {
        regs::restore_state(&self.fd, mpidrs, state)
    }

    pub fn init_device_attributes(gic_device: &Self) -> Result<(), GicError> {
        // Setting up the distributor attribute.
        // We are placing the GIC below 1GB so we need to substract the size of the distributor.
        Self::set_device_attribute(
            gic_device.device_fd(),
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            u64::from(kvm_bindings::KVM_VGIC_V3_ADDR_TYPE_DIST),
            &GICv3::get_dist_addr() as *const u64 as u64,
            0,
        )?;

        // Setting up the redistributors' attribute.
        // We are calculating here the start of the redistributors address. We have one per CPU.
        Self::set_device_attribute(
            gic_device.device_fd(),
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            u64::from(kvm_bindings::KVM_VGIC_V3_ADDR_TYPE_REDIST),
            &GICv3::get_redists_addr(gic_device.vcpu_count()) as *const u64 as u64,
            0,
        )?;

        Ok(())
    }

    /// Initialize a GIC device
    pub fn init_device(vm: &VmFd) -> Result<DeviceFd, GicError> {
        let mut gic_device = kvm_bindings::kvm_create_device {
            type_: Self::VERSION,
            fd: 0,
            flags: 0,
        };

        vm.create_device(&mut gic_device)
            .map_err(GicError::CreateGIC)
    }

    /// Method to initialize the GIC device
    pub fn create(vm: &VmFd, vcpu_count: u64) -> Result<Self, GicError> {
        let vgic_fd = Self::init_device(vm)?;

        let device = Self::create_device(vgic_fd, vcpu_count);

        Self::init_device_attributes(&device)?;

        Self::finalize_device(&device)?;

        Ok(device)
    }

    /// Finalize the setup of a GIC device
    pub fn finalize_device(gic_device: &Self) -> Result<(), GicError> {
        // On arm there are 3 types of interrupts: SGI (0-15), PPI (16-31), SPI (32-1020).
        // SPIs are used to signal interrupts from various peripherals accessible across
        // the whole system so these are the ones that we increment when adding a new virtio device.
        // KVM_DEV_ARM_VGIC_GRP_NR_IRQS sets the highest SPI number. Consequently, we will have a
        // total of `super::layout::IRQ_MAX - 32` usable SPIs in our microVM.
        let nr_irqs: u32 = super::layout::IRQ_MAX;
        let nr_irqs_ptr = &nr_irqs as *const u32;
        Self::set_device_attribute(
            gic_device.device_fd(),
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
            0,
            nr_irqs_ptr as u64,
            0,
        )?;

        // Finalize the GIC.
        // See https://code.woboq.org/linux/linux/virt/kvm/arm/vgic/vgic-kvm-device.c.html#211.
        Self::set_device_attribute(
            gic_device.device_fd(),
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
            u64::from(kvm_bindings::KVM_DEV_ARM_VGIC_CTRL_INIT),
            0,
            0,
        )?;

        Ok(())
    }

    /// Set a GIC device attribute
    pub fn set_device_attribute(
        fd: &DeviceFd,
        group: u32,
        attr: u64,
        addr: u64,
        flags: u32,
    ) -> Result<(), GicError> {
        let attr = kvm_bindings::kvm_device_attr {
            flags,
            group,
            attr,
            addr,
        };
        fd.set_device_attr(&attr)
            .map_err(|err| GicError::DeviceAttribute(err, true, group))?;

        Ok(())
    }
}

/// Function that flushes
/// RDIST pending tables into guest RAM.
///
/// The tables get flushed to guest RAM whenever the VM gets stopped.
fn save_pending_tables(fd: &DeviceFd) -> Result<(), GicError> {
    let init_gic_attr = kvm_bindings::kvm_device_attr {
        group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
        attr: u64::from(kvm_bindings::KVM_DEV_ARM_VGIC_SAVE_PENDING_TABLES),
        addr: 0,
        flags: 0,
    };
    fd.set_device_attr(&init_gic_attr).map_err(|err| {
        GicError::DeviceAttribute(err, true, kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL)
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]
    use kvm_ioctls::Kvm;

    use super::*;
    use crate::arch::aarch64::gic::{create_gic, GICVersion};

    #[test]
    fn test_save_pending_tables() {
        use std::os::unix::io::AsRawFd;

        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let gic = create_gic(&vm, 1, Some(GICVersion::GICV3)).expect("Cannot create gic");
        assert!(save_pending_tables(gic.device_fd()).is_ok());

        unsafe { libc::close(gic.device_fd().as_raw_fd()) };

        let res = save_pending_tables(gic.device_fd());
        assert!(res.is_err());
        assert_eq!(
            format!("{:?}", res.unwrap_err()),
            "DeviceAttribute(Error(9), true, 4)"
        );
    }
}
