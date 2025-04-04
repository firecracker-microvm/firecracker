// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::collections::HashMap;

use displaydoc::Display;
use kvm_bindings::{KVM_ARM_VCPU_PVTIME_CTRL, KVM_ARM_VCPU_PVTIME_IPA};
use log::{debug, info, warn};
use thiserror::Error;

use crate::device_manager::resources::ResourceAllocator;

/// Size of the stolen_time struct in bytes, see 3.2.2 in DEN0057A
pub const STEALTIME_STRUCT_MEM_SIZE: u64 = 16;

/// Represent PVTime device for ARM
#[derive(Debug)]
pub struct PVTime {
    /// Maps vCPU index to IPA location of stolen_time struct as defined in DEN0057A
    steal_time_regions: HashMap<u8, u64>,
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
    /// Creates a new PVTime device by allocating system memory for all vCPUs
    pub fn new(
        resource_allocator: &mut ResourceAllocator,
        vcpu_count: u8,
    ) -> Result<Self, PVTimeError> {
        info!("Creating PVTime for {vcpu_count} vCPUs...");
        // This returns the IPA(?) of the start of our shared memory region for all vCPUs.
        // Q: Confirm that allocate_system_memory returns an IPA?
        let base_addr = resource_allocator
            .allocate_system_memory(
                STEALTIME_STRUCT_MEM_SIZE * vcpu_count as u64,
                16, // Q: We believe this to be 16, need confirmation.
                vm_allocator::AllocPolicy::LastMatch,
            )
            .map_err(|e| PVTimeError::AllocationFailed(e.to_string()))?;

        debug!(
            "Allocated base address for PVTime stolen_time region: 0x{:x}",
            base_addr
        );

        // Now we need to store the base IPA for each vCPU's steal_time struct.
        let mut steal_time_regions = HashMap::new();
        for i in 0..vcpu_count {
            let ipa = base_addr + (i as u64 * STEALTIME_STRUCT_MEM_SIZE);
            debug!("Assigned vCPU {} to stolen_time IPA 0x{:x}", i, ipa);
            steal_time_regions.insert(i, ipa);
        }

        // Return the PVTime device with the steal_time region IPAs mapped to vCPU indices.
        Ok(PVTime { steal_time_regions })
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

        debug!(
            "Registering vCPU {} with stolen_time IPA = 0x{:x}",
            vcpu_index, ipa
        );

        // IMPORTANT QUESTION: We need to confirm this is safe. We need to somehow
        // ensure the ipa value is not dropped before we use it etc. since we
        // are creating a raw pointer? Do we need a Box?
        let ipa_val = *ipa;
        let ipa_ptr = &ipa_val as *const u64;
        debug!(
            "Registering vCPU {} with stolen_time IPA = 0x{:x} (at userspace addr 0x{:x})",
            vcpu_index, ipa_val, ipa_ptr as u64
        );

        // Use KVM syscall (kvm_set_device_attr) to register the vCPU with the steal_time region
        let vcpu_device_attr = kvm_bindings::kvm_device_attr {
            group: KVM_ARM_VCPU_PVTIME_CTRL,
            attr: KVM_ARM_VCPU_PVTIME_IPA as u64,
            addr: ipa_ptr as u64, // userspace address of attr data
            flags: 0,
        };

        vcpu_fd.set_device_attr(&vcpu_device_attr).map_err(|err| {
            warn!(
                "Failed to set device attribute for vCPU {}: {:?}",
                vcpu_index, err
            );
            PVTimeError::DeviceAttribute(err, true, KVM_ARM_VCPU_PVTIME_CTRL)
        })?;

        Ok(())
    }
}

// TODO/Q: Would we be correct in implementing Persist for PVTime? Some sort of persistence is
// needed for snapshot capability. We would only need to store base_addr IPA of shared memory region
// assuming the # of vCPUs is constant across snapshots. Also assuming we are correct that
// kvm_set_device_attr takes an IPA and we get an IPA back from resource_allocator.
