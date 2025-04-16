// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use displaydoc::Display;
use kvm_bindings::{KVM_ARM_VCPU_PVTIME_CTRL, KVM_ARM_VCPU_PVTIME_IPA};
use kvm_ioctls::VcpuFd;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use vm_memory::GuestAddress;

use crate::Vcpu;
use crate::device_manager::resources::ResourceAllocator;
use crate::snapshot::Persist;

/// 64 bytes due to alignment requirement in 3.1 of https://www.kernel.org/doc/html/v5.8/virt/kvm/devices/vcpu.html#attribute-kvm-arm-vcpu-pvtime-ipa
pub const STEALTIME_STRUCT_MEM_SIZE: u64 = 64;

/// Represent PVTime device for ARM
#[derive(Debug)]
pub struct PVTime {
    /// Number of vCPUs
    vcpu_count: u64,
    /// The base IPA of the shared memory region
    base_ipa: GuestAddress,
}

/// Errors associated with PVTime operations
#[derive(Debug, Error, Display, PartialEq, Eq)]
pub enum PVTimeError {
    /// Failed to allocate memory region: {0}
    AllocationFailed(vm_allocator::Error),
    /// Invalid VCPU ID: {0}
    InvalidVcpuIndex(u64),
    /// Error while setting or getting device attributes for vCPU: {0}
    DeviceAttribute(kvm_ioctls::Error),
}

impl PVTime {
    /// Helper function to get the IPA of the steal_time region for a given vCPU
    fn get_steal_time_region_addr(&self, vcpu_index: u64) -> Result<GuestAddress, PVTimeError> {
        if vcpu_index >= self.vcpu_count {
            return Err(PVTimeError::InvalidVcpuIndex(vcpu_index));
        }
        Ok(GuestAddress(
            self.base_ipa.0 + (vcpu_index * STEALTIME_STRUCT_MEM_SIZE),
        ))
    }

    /// Create a new PVTime device given a base addr
    /// - Assumes total shared memory region from base addr is already allocated
    fn from_base(base_ipa: GuestAddress, vcpu_count: u64) -> Self {
        PVTime {
            vcpu_count,
            base_ipa,
        }
    }

    /// Creates a new PVTime device by allocating new system memory for all vCPUs
    pub fn new(
        resource_allocator: &mut ResourceAllocator,
        vcpu_count: u64,
    ) -> Result<Self, PVTimeError> {
        // This returns the IPA of the start of our shared memory region for all vCPUs.
        let base_ipa: GuestAddress = GuestAddress(
            resource_allocator
                .allocate_system_memory(
                    STEALTIME_STRUCT_MEM_SIZE * vcpu_count,
                    STEALTIME_STRUCT_MEM_SIZE,
                    vm_allocator::AllocPolicy::LastMatch,
                )
                .map_err(PVTimeError::AllocationFailed)?,
        );
        Ok(Self::from_base(base_ipa, vcpu_count))
    }

    /// Check if PVTime is supported on vcpu
    pub fn is_supported(vcpu_fd: &VcpuFd) -> bool {
        // Check if pvtime is enabled
        let pvtime_device_attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_ARM_VCPU_PVTIME_CTRL,
            attr: kvm_bindings::KVM_ARM_VCPU_PVTIME_IPA as u64,
            addr: 0,
            flags: 0,
        };

        // Use kvm_has_device_attr to check if PVTime is supported
        vcpu_fd.has_device_attr(&pvtime_device_attr).is_ok()
    }

    /// Register a vCPU with its pre-allocated steal time region
    fn register_vcpu(
        &self,
        vcpu_index: u64,
        vcpu_fd: &kvm_ioctls::VcpuFd,
    ) -> Result<(), PVTimeError> {
        // Get IPA of the steal_time region for this vCPU
        let ipa = self.get_steal_time_region_addr(vcpu_index)?;

        // Use KVM syscall (kvm_set_device_attr) to register the vCPU with the steal_time region
        let vcpu_device_attr = kvm_bindings::kvm_device_attr {
            group: KVM_ARM_VCPU_PVTIME_CTRL,
            attr: KVM_ARM_VCPU_PVTIME_IPA as u64,
            addr: &ipa.0 as *const u64 as u64, // userspace address of attr data
            flags: 0,
        };

        vcpu_fd
            .set_device_attr(&vcpu_device_attr)
            .map_err(PVTimeError::DeviceAttribute)?;

        Ok(())
    }

    /// Register all vCPUs with their pre-allocated steal time regions
    pub fn register_all_vcpus(&self, vcpus: &mut [Vcpu]) -> Result<(), PVTimeError> {
        // Register the vcpu with the pvtime device to map its steal time region
        for (i, vcpu) in vcpus.iter().enumerate() {
            self.register_vcpu(i as u64, &vcpu.kvm_vcpu.fd)?;
        }
        Ok(())
    }
}

/// Logic to save/restore the state of a PVTime device
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct PVTimeState {
    /// base IPA of the total shared memory region
    pub base_ipa: u64,
}

/// Arguments to restore a PVTime device from PVTimeState
#[derive(Debug)]
pub struct PVTimeConstructorArgs<'a> {
    /// For steal_time shared memory region
    pub resource_allocator: &'a mut ResourceAllocator,
    /// Number of vCPUs (should be consistent with pre-snapshot state)
    pub vcpu_count: u64,
}

impl<'a> Persist<'a> for PVTime {
    type State = PVTimeState;
    type ConstructorArgs = PVTimeConstructorArgs<'a>;
    type Error = PVTimeError;

    /// Save base IPA of PVTime device for persistence
    fn save(&self) -> Self::State {
        PVTimeState {
            base_ipa: self.base_ipa.0,
        }
    }

    /// Restore state of PVTime device from given base IPA
    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> std::result::Result<Self, PVTimeError> {
        constructor_args
            .resource_allocator
            .allocate_system_memory(
                STEALTIME_STRUCT_MEM_SIZE * constructor_args.vcpu_count,
                STEALTIME_STRUCT_MEM_SIZE,
                vm_allocator::AllocPolicy::ExactMatch(state.base_ipa),
            )
            .map_err(PVTimeError::AllocationFailed)?;
        Ok(Self::from_base(
            GuestAddress(state.base_ipa),
            constructor_args.vcpu_count,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_manager::resources::ResourceAllocator;

    #[test]
    fn test_get_steal_time_region_addr() {
        let base = GuestAddress(0x1000);
        let dev = PVTime::from_base(base, 3);

        assert_eq!(
            dev.get_steal_time_region_addr(0).unwrap(),
            GuestAddress(0x1000)
        );
        assert_eq!(
            dev.get_steal_time_region_addr(1).unwrap(),
            GuestAddress(0x1000 + STEALTIME_STRUCT_MEM_SIZE)
        );
        assert!(matches!(
            dev.get_steal_time_region_addr(3),
            Err(PVTimeError::InvalidVcpuIndex(3))
        ));
    }

    #[test]
    fn test_new_pvtime_allocates_correctly() {
        let mut allocator = ResourceAllocator::new().unwrap();
        let dev = PVTime::new(&mut allocator, 2).unwrap();

        assert_eq!(dev.vcpu_count, 2);
        assert_eq!(
            dev.base_ipa.0 % STEALTIME_STRUCT_MEM_SIZE,
            0,
            "Base IPA should be aligned"
        );
    }
}
