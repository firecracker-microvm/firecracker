// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod gicv2;
mod gicv3;
mod regs;

use gicv2::GICv2;
use gicv3::GICv3;
use kvm_ioctls::{DeviceFd, VmFd};
pub use regs::GicState;

use super::layout;

/// Represent a V2 or V3 GIC device
#[derive(Debug)]
pub struct GIC {
    /// The file descriptor for the KVM device
    fd: DeviceFd,

    /// GIC device properties, to be used for setting up the fdt entry
    properties: [u64; 4],

    /// Number of CPUs handled by the device
    vcpu_count: u64,
}
impl GIC {
    /// Returns the file descriptor of the GIC device
    pub fn device_fd(&self) -> &DeviceFd {
        &self.fd
    }

    /// Returns an array with GIC device properties
    pub fn device_properties(&self) -> &[u64] {
        &self.properties
    }

    /// Returns the number of vCPUs this GIC handles
    pub fn vcpu_count(&self) -> u64 {
        self.vcpu_count
    }
}

/// Errors thrown while setting up the GIC.
#[derive(Debug, thiserror::Error, displaydoc::Display, PartialEq, Eq)]
pub enum GicError {
    /// Error while calling KVM ioctl for setting up the global interrupt controller: {0}
    CreateGIC(kvm_ioctls::Error),
    /// Error while setting or getting device attributes for the GIC: {0}, {1}, {2}
    DeviceAttribute(kvm_ioctls::Error, bool, u32),
    /// The number of vCPUs in the GicState doesn't match the number of vCPUs on the system.
    InconsistentVcpuCount,
    /// The VgicSysRegsState is invalid.
    InvalidVgicSysRegState,
}

/// List of implemented GICs.
#[derive(Debug)]
pub enum GICVersion {
    /// Legacy version.
    GICV2,
    /// GICV3 without ITS.
    GICV3,
}

/// Trait for GIC devices.
#[derive(Debug)]
pub enum GICDevice {
    /// Legacy version.
    V2(GICv2),
    /// GICV3 without ITS.
    V3(GICv3),
}
impl GICDevice {
    /// Returns the file descriptor of the GIC device
    pub fn device_fd(&self) -> &DeviceFd {
        match self {
            Self::V2(x) => x.device_fd(),
            Self::V3(x) => x.device_fd(),
        }
    }

    /// Returns an array with GIC device properties
    pub fn device_properties(&self) -> &[u64] {
        match self {
            Self::V2(x) => x.device_properties(),
            Self::V3(x) => x.device_properties(),
        }
    }

    /// Returns the number of vCPUs this GIC handles
    pub fn vcpu_count(&self) -> u64 {
        match self {
            Self::V2(x) => x.vcpu_count(),
            Self::V3(x) => x.vcpu_count(),
        }
    }

    /// Returns the fdt compatibility property of the device
    pub fn fdt_compatibility(&self) -> &str {
        match self {
            Self::V2(x) => x.fdt_compatibility(),
            Self::V3(x) => x.fdt_compatibility(),
        }
    }

    /// Returns the maint_irq fdt property of the device
    pub fn fdt_maint_irq(&self) -> u32 {
        match self {
            Self::V2(x) => x.fdt_maint_irq(),
            Self::V3(x) => x.fdt_maint_irq(),
        }
    }

    /// Returns the GIC version of the device
    pub fn version(&self) -> u32 {
        match self {
            Self::V2(_) => GICv2::VERSION,
            Self::V3(_) => GICv3::VERSION,
        }
    }

    /// Setup the device-specific attributes
    pub fn init_device_attributes(gic_device: &Self) -> Result<(), GicError> {
        match gic_device {
            Self::V2(x) => GICv2::init_device_attributes(x),
            Self::V3(x) => GICv3::init_device_attributes(x),
        }
    }

    /// Method to save the state of the GIC device.
    pub fn save_device(&self, mpidrs: &[u64]) -> Result<GicState, GicError> {
        match self {
            Self::V2(x) => x.save_device(mpidrs),
            Self::V3(x) => x.save_device(mpidrs),
        }
    }

    /// Method to restore the state of the GIC device.
    pub fn restore_device(&self, mpidrs: &[u64], state: &GicState) -> Result<(), GicError> {
        match self {
            Self::V2(x) => x.restore_device(mpidrs, state),
            Self::V3(x) => x.restore_device(mpidrs, state),
        }
    }
}

/// Create a GIC device.
///
/// If "version" parameter is "None" the function will try to create by default a GICv3 device.
/// If that fails it will try to fall-back to a GICv2 device.
/// If version is Some the function will try to create a device of exactly the specified version.
pub fn create_gic(
    vm: &VmFd,
    vcpu_count: u64,
    version: Option<GICVersion>,
) -> Result<GICDevice, GicError> {
    match version {
        Some(GICVersion::GICV2) => GICv2::create(vm, vcpu_count).map(GICDevice::V2),
        Some(GICVersion::GICV3) => GICv3::create(vm, vcpu_count).map(GICDevice::V3),
        None => GICv3::create(vm, vcpu_count)
            .map(GICDevice::V3)
            .or_else(|_| GICv2::create(vm, vcpu_count).map(GICDevice::V2)),
    }
}

#[cfg(test)]
mod tests {

    use kvm_ioctls::Kvm;

    use super::*;

    #[test]
    fn test_create_gic() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        assert!(create_gic(&vm, 1, None).is_ok());
    }
}
