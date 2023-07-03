// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod regs;

use kvm_ioctls::{DeviceFd, VmFd};

use crate::arch::aarch64::gic::{GicError, GicState};

/// Represent a GIC v2 device
#[derive(Debug)]
pub struct GICv2(super::GIC);

impl std::ops::Deref for GICv2 {
    type Target = super::GIC;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl GICv2 {
    // Unfortunately bindgen omits defines that are based on other defines.
    // See arch/arm64/include/uapi/asm/kvm.h file from the linux kernel.
    const KVM_VGIC_V2_DIST_SIZE: u64 = 0x1000;
    const KVM_VGIC_V2_CPU_SIZE: u64 = 0x2000;

    // Device trees specific constants
    const ARCH_GIC_V2_MAINT_IRQ: u32 = 8;

    /// Get the address of the GICv2 distributor.
    const fn get_dist_addr() -> u64 {
        super::layout::MAPPED_IO_START - GICv2::KVM_VGIC_V2_DIST_SIZE
    }

    /// Get the size of the GIC_v2 distributor.
    const fn get_dist_size() -> u64 {
        GICv2::KVM_VGIC_V2_DIST_SIZE
    }

    /// Get the address of the GIC_v2 CPU.
    const fn get_cpu_addr() -> u64 {
        GICv2::get_dist_addr() - GICv2::KVM_VGIC_V2_CPU_SIZE
    }

    /// Get the size of the GIC_v2 CPU.
    const fn get_cpu_size() -> u64 {
        GICv2::KVM_VGIC_V2_CPU_SIZE
    }

    pub const VERSION: u32 = kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V2;

    pub fn fdt_compatibility(&self) -> &str {
        "arm,gic-400"
    }

    pub fn fdt_maint_irq(&self) -> u32 {
        GICv2::ARCH_GIC_V2_MAINT_IRQ
    }

    /// Create the GIC device object
    pub fn create_device(fd: DeviceFd, vcpu_count: u64) -> Self {
        GICv2(super::GIC {
            fd,
            properties: [
                GICv2::get_dist_addr(),
                GICv2::get_dist_size(),
                GICv2::get_cpu_addr(),
                GICv2::get_cpu_size(),
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
            u64::from(kvm_bindings::KVM_VGIC_V2_ADDR_TYPE_DIST),
            &GICv2::get_dist_addr() as *const u64 as u64,
            0,
        )?;

        // Setting up the CPU attribute.
        Self::set_device_attribute(
            gic_device.device_fd(),
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            u64::from(kvm_bindings::KVM_VGIC_V2_ADDR_TYPE_CPU),
            &GICv2::get_cpu_addr() as *const u64 as u64,
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
