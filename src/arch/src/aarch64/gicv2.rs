// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{boxed::Box, result};

use kvm_ioctls::DeviceFd;

use super::gic::{Error, GICDevice};

type Result<T> = result::Result<T, Error>;

/// Represent a GIC v2 device
pub struct GICv2 {
    /// The file descriptor for the KVM device
    fd: DeviceFd,

    /// GIC device properties, to be used for setting up the fdt entry
    properties: [u64; 4],

    /// Number of CPUs handled by the device
    vcpu_count: u64,
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
}

impl GICDevice for GICv2 {
    fn version() -> u32 {
        kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V2
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
        "arm,gic-400"
    }

    fn fdt_maint_irq(&self) -> u32 {
        GICv2::ARCH_GIC_V2_MAINT_IRQ
    }

    fn create_device(fd: DeviceFd, vcpu_count: u64) -> Box<dyn GICDevice> {
        Box::new(GICv2 {
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

    fn init_device_attributes(gic_device: &dyn GICDevice) -> Result<()> {
        /* Setting up the distributor attribute.
        We are placing the GIC below 1GB so we need to substract the size of the distributor. */
        Self::set_device_attribute(
            &gic_device.device_fd(),
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            u64::from(kvm_bindings::KVM_VGIC_V2_ADDR_TYPE_DIST),
            &GICv2::get_dist_addr() as *const u64 as u64,
            0,
        )?;

        /* Setting up the CPU attribute. */
        Self::set_device_attribute(
            &gic_device.device_fd(),
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            u64::from(kvm_bindings::KVM_VGIC_V2_ADDR_TYPE_CPU),
            &GICv2::get_cpu_addr() as *const u64 as u64,
            0,
        )?;

        Ok(())
    }
}
