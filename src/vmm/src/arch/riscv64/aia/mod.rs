// Copyright © 2025 Computing Systems Laboratory (CSLab), ECE, NTUA. All rights reserved.
//
// Copyright © 2024 Institute of Software, CAS. All rights reserved.
//
// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod regs;

use kvm_ioctls::{DeviceFd, VmFd};
pub use regs::AiaState;

/// Represent an AIA device
#[derive(Debug)]
pub struct AIADevice {
    fd: DeviceFd,
    vcpu_count: u64,
}

impl AIADevice {
    const VERSION: u32 = kvm_bindings::kvm_device_type_KVM_DEV_TYPE_RISCV_AIA;

    /// Return whether the device is MSI compatible.
    pub fn msi_compatible(&self) -> bool {
        true
    }

    /// Return the FDT `compatible` property string for IMSIC.
    pub fn imsic_compatibility(&self) -> &str {
        "riscv,imsics"
    }

    /// Return IMSIC properties.
    pub fn imsic_properties(&self) -> [u32; 4] {
        [
            0,
            AIADevice::get_imsic_addr() as u32,
            0,
            super::layout::IMSIC_SZ_PH * self.vcpu_count as u32,
        ]
    }

    /// Return the FDT `compatible` property string for APLIC.
    pub fn aplic_compatibility(&self) -> &str {
        "riscv,aplic"
    }

    /// Return APLIC properties.
    pub fn aplic_properties(&self) -> [u32; 4] {
        [
            0,
            AIADevice::get_aplic_addr() as u32,
            0,
            ::kvm_bindings::KVM_DEV_RISCV_APLIC_SIZE,
        ]
    }

    /// Return the file descriptor of the AIA device.
    pub fn device_fd(&self) -> &DeviceFd {
        &self.fd
    }

    /// Returns the number vCPUs this AIA device handles.
    pub fn vcpu_count(&self) -> u64 {
        self.vcpu_count
    }

    fn get_aplic_addr() -> u64 {
        super::layout::APLIC_START
    }

    fn get_imsic_addr() -> u64 {
        super::layout::IMSIC_START
    }

    /// Create the AIA device object.
    pub fn create_device(fd: DeviceFd, vcpu_count: u64) -> Self {
        Self { fd, vcpu_count }
    }

    /// Initialize an AIA device.
    pub fn init_device(vm: &VmFd) -> Result<DeviceFd, AiaError> {
        let mut aia_device = kvm_bindings::kvm_create_device {
            type_: Self::VERSION,
            fd: 0,
            flags: 0,
        };

        vm.create_device(&mut aia_device)
            .map_err(AiaError::CreateAIA)
    }

    fn init_device_attributes(aia_device: &Self) -> Result<(), AiaError> {
        // Set attributes.
        let nr_irqs: u32 = super::layout::IRQ_MAX;
        let aia_nr_sources: u32 = nr_irqs;
        Self::set_device_attribute(
            aia_device.device_fd(),
            kvm_bindings::KVM_DEV_RISCV_AIA_GRP_CONFIG,
            u64::from(kvm_bindings::KVM_DEV_RISCV_AIA_CONFIG_SRCS),
            &aia_nr_sources as *const u32 as u64,
            0,
        )?;

        let aia_hart_bits = u64::from(aia_device.vcpu_count) - 1;
        let aia_hart_bits = ::std::cmp::max(64 - aia_hart_bits.leading_zeros(), 1);
        Self::set_device_attribute(
            aia_device.device_fd(),
            kvm_bindings::KVM_DEV_RISCV_AIA_GRP_CONFIG,
            u64::from(kvm_bindings::KVM_DEV_RISCV_AIA_CONFIG_HART_BITS),
            &aia_hart_bits as *const u32 as u64,
            0,
        )?;

        // Set APLIC address.
        let aia_addr_aplic: u64 = AIADevice::get_aplic_addr();
        Self::set_device_attribute(
            aia_device.device_fd(),
            kvm_bindings::KVM_DEV_RISCV_AIA_GRP_ADDR,
            u64::from(kvm_bindings::KVM_DEV_RISCV_AIA_ADDR_APLIC),
            &aia_addr_aplic as *const u64 as u64,
            0,
        )?;

        let aia_imsic_addr = |hart| -> u64 {
            AIADevice::get_imsic_addr() + u64::from(hart) * u64::from(super::layout::IMSIC_SZ_PH)
        };
        for i in 0..aia_device.vcpu_count {
            let aia_addr_imsic = aia_imsic_addr(i);
            let aia_addr_imsic_attr = 1 + u64::from(i);
            Self::set_device_attribute(
                aia_device.device_fd(),
                kvm_bindings::KVM_DEV_RISCV_AIA_GRP_ADDR,
                u64::from(aia_addr_imsic_attr),
                &aia_addr_imsic as *const u64 as u64,
                0,
            )?;
        }

        Ok(())
    }

    /// Create an AIA device.
    pub fn create_aia(vm: &VmFd, vcpu_count: u64) -> Result<AIADevice, AiaError> {
        let aia_fd = Self::init_device(vm)?;

        let device = Self::create_device(aia_fd, vcpu_count);

        Self::init_device_attributes(&device)?;

        Self::finalize_device(&device)?;

        Ok(device)
    }

    /// Finalize the setup of an AIA device.
    pub fn finalize_device(aia_device: &Self) -> Result<(), AiaError> {
        // Finalize the AIA.
        Self::set_device_attribute(
            aia_device.device_fd(),
            kvm_bindings::KVM_DEV_RISCV_AIA_GRP_CTRL,
            u64::from(kvm_bindings::KVM_DEV_RISCV_AIA_CTRL_INIT),
            0,
            0,
        )?;

        Ok(())
    }

    /// Set an AIA device attribute.
    pub fn set_device_attribute(
        fd: &DeviceFd,
        group: u32,
        attr: u64,
        addr: u64,
        flags: u32,
    ) -> Result<(), AiaError> {
        let attr = kvm_bindings::kvm_device_attr {
            flags,
            group,
            attr,
            addr,
        };
        fd.set_device_attr(&attr)
            .map_err(|err| AiaError::DeviceAttribute(err, true, group))?;

        Ok(())
    }

    /// A safe wrapper over unsafe kvm_ioctl::get_device_attr()
    pub fn get_device_attribute(
        &self,
        attr: &mut ::kvm_bindings::kvm_device_attr,
    ) -> Result<(), AiaError> {
        // SAFETY: attr.addr is safe to write to.
        unsafe {
            self.fd
                .get_device_attr(attr)
                .map_err(|err| AiaError::DeviceAttribute(err, true, attr.group))?
        };

        Ok(())
    }
}

/// Errors thrown while setting up the AIA.
#[derive(Debug, thiserror::Error, displaydoc::Display, PartialEq, Eq)]
pub enum AiaError {
    /// Error while calling KVM ioctl for setting up the global interrupt controller: {0}
    CreateAIA(kvm_ioctls::Error),
    /// Error while setting or getting device attributes for the AIA: {0}, {1}, {2}
    DeviceAttribute(kvm_ioctls::Error, bool, u32),
}
