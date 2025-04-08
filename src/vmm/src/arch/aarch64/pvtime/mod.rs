// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::collections::HashMap;

use displaydoc::Display;
use kvm_bindings::{KVM_ARM_VCPU_PVTIME_CTRL, KVM_ARM_VCPU_PVTIME_IPA};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use vm_memory::GuestAddress;

use crate::device_manager::resources::ResourceAllocator;
use crate::snapshot::Persist;

/// 64 bytes due to alignment requirement in 3.1 of https://www.kernel.org/doc/html/v5.8/virt/kvm/devices/vcpu.html#attribute-kvm-arm-vcpu-pvtime-ipa
pub const STEALTIME_STRUCT_MEM_SIZE: u64 = 64;

/// Represent PVTime device for ARM
/// TODO: Decide whether we want to keep the hashmap OR the base IPA
#[derive(Debug)]
pub struct PVTime {
    /// Maps vCPU index to IPA location of stolen_time struct as defined in DEN0057A
    steal_time_regions: HashMap<u8, u64>,
    /// The base IPA of the shared memory region
    base_ipa: u64,
}

/// Errors associated with PVTime operations
#[derive(Debug, Error, Display, PartialEq, Eq)]
pub enum PVTimeError {
    /// Failed to allocate memory region: {0}
    AllocationFailed(String),
    /// Invalid VCPU ID: {0}
    InvalidVcpuIndex(u8),
    /// Error while setting or getting device attributes for vCPU: {0}, {1}, {2}
    DeviceAttribute(kvm_ioctls::Error, bool, u32),
}

impl PVTime {
    /// Create a new PVTime device given a base addr
    /// - Assumes total shared memory region from base addr is already allocated
    fn from_base(base_addr: GuestAddress, vcpu_count: u8) -> Self {
        let base_ipa: u64 = base_addr.0;

        // Now we need to store the base IPA for each vCPU's steal_time struct.
        let mut steal_time_regions = HashMap::new();
        for i in 0..vcpu_count {
            let ipa = base_ipa + (i as u64 * STEALTIME_STRUCT_MEM_SIZE);
            steal_time_regions.insert(i, ipa);
        }

        // Return the PVTime device with the steal_time region IPAs mapped to vCPU indices.
        PVTime {
            steal_time_regions,
            base_ipa,
        }
    }

    /// Creates a new PVTime device by allocating new system memory for all vCPUs
    pub fn new(
        resource_allocator: &mut ResourceAllocator,
        vcpu_count: u8,
    ) -> Result<Self, PVTimeError> {
        // This returns the IPA of the start of our shared memory region for all vCPUs.
        let base_ipa: GuestAddress = GuestAddress(
            resource_allocator
                .allocate_system_memory(
                    STEALTIME_STRUCT_MEM_SIZE * vcpu_count as u64,
                    64,
                    vm_allocator::AllocPolicy::LastMatch,
                )
                .map_err(|e| PVTimeError::AllocationFailed(e.to_string()))?,
        );

        Ok(Self::from_base(base_ipa, vcpu_count))
    }

    /// Register a vCPU with its pre-allocated steal time region
    pub fn register_vcpu(
        &self,
        vcpu_index: u8,
        vcpu_fd: &kvm_ioctls::VcpuFd,
    ) -> Result<(), PVTimeError> {
        // Get IPA of the steal_time region for this vCPU
        let ipa = self
            .steal_time_regions
            .get(&vcpu_index)
            .ok_or(PVTimeError::InvalidVcpuIndex(vcpu_index))?;

        // Use KVM syscall (kvm_set_device_attr) to register the vCPU with the steal_time region
        let vcpu_device_attr = kvm_bindings::kvm_device_attr {
            group: KVM_ARM_VCPU_PVTIME_CTRL,
            attr: KVM_ARM_VCPU_PVTIME_IPA as u64,
            addr: ipa as *const u64 as u64, // userspace address of attr data
            flags: 0,
        };

        vcpu_fd
            .set_device_attr(&vcpu_device_attr)
            .map_err(|err| PVTimeError::DeviceAttribute(err, true, KVM_ARM_VCPU_PVTIME_CTRL))?;

        Ok(())
    }
}

/// Logic to save/restore the state of a PVTime device
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct PVTimeState {
    /// base IPA of the total shared memory region
    pub base_ipa: u64,
}

#[derive(Debug)]
pub struct PVTimeConstructorArgs<'a> {
    pub resource_allocator: &'a mut ResourceAllocator,
    pub vcpu_count: u8,
}

impl<'a> Persist<'a> for PVTime {
    type State = PVTimeState;
    type ConstructorArgs = PVTimeConstructorArgs<'a>;
    type Error = PVTimeError;

    /// Save base IPA of PVTime device for persistence
    fn save(&self) -> Self::State {
        PVTimeState {
            base_ipa: self.base_ipa,
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
                STEALTIME_STRUCT_MEM_SIZE * constructor_args.vcpu_count as u64,
                64,
                vm_allocator::AllocPolicy::ExactMatch(state.base_ipa),
            )
            .map_err(|e| PVTimeError::AllocationFailed(e.to_string()))?;
        Ok(Self::from_base(
            GuestAddress(state.base_ipa),
            constructor_args.vcpu_count,
        ))
    }
}
