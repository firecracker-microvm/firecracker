// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use kvm_bindings::KVM_API_VERSION;
use kvm_ioctls::Kvm as KvmFd;
use serde::{Deserialize, Serialize};

pub use crate::arch::{Kvm, KvmArchError};
use crate::cpu_config::templates::KvmCapability;

/// Errors associated with the wrappers over KVM ioctls.
/// Needs `rustfmt::skip` to make multiline comments work
#[rustfmt::skip]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum KvmError {
    /// The host kernel reports an invalid KVM API version: {0}
    ApiVersion(i32),
    /// Missing KVM capabilities: {0:#x?}
    Capabilities(u32),
    /**  Error creating KVM object: {0} Make sure the user launching the firecracker process is \
    configured on the /dev/kvm file's ACL. */
    Kvm(kvm_ioctls::Error),
    /// Architecture specific error: {0}
    ArchError(#[from] KvmArchError)
}

impl Kvm {
    /// Create `Kvm` struct.
    pub fn new(kvm_cap_modifiers: Vec<KvmCapability>) -> Result<Self, KvmError> {
        let kvm_fd = KvmFd::new().map_err(KvmError::Kvm)?;

        // Check that KVM has the correct version.
        // Safe to cast because this is a constant.
        #[allow(clippy::cast_possible_wrap)]
        if kvm_fd.get_api_version() != KVM_API_VERSION as i32 {
            return Err(KvmError::ApiVersion(kvm_fd.get_api_version()));
        }

        let total_caps = Self::combine_capabilities(&kvm_cap_modifiers);
        // Check that all desired capabilities are supported.
        Self::check_capabilities(&kvm_fd, &total_caps).map_err(KvmError::Capabilities)?;

        Ok(Kvm::init_arch(kvm_fd, kvm_cap_modifiers)?)
    }

    fn combine_capabilities(kvm_cap_modifiers: &[KvmCapability]) -> Vec<u32> {
        let mut total_caps = Self::DEFAULT_CAPABILITIES.to_vec();
        for modifier in kvm_cap_modifiers.iter() {
            match modifier {
                KvmCapability::Add(cap) => {
                    if !total_caps.contains(cap) {
                        total_caps.push(*cap);
                    }
                }
                KvmCapability::Remove(cap) => {
                    if let Some(pos) = total_caps.iter().position(|c| c == cap) {
                        total_caps.swap_remove(pos);
                    }
                }
            }
        }
        total_caps
    }

    fn check_capabilities(kvm_fd: &KvmFd, capabilities: &[u32]) -> Result<(), u32> {
        for cap in capabilities {
            // If capability is not supported kernel will return 0.
            if kvm_fd.check_extension_raw(u64::from(*cap)) == 0 {
                return Err(*cap);
            }
        }
        Ok(())
    }

    /// Saves and returns the Kvm state.
    pub fn save_state(&self) -> KvmState {
        KvmState {
            kvm_cap_modifiers: self.kvm_cap_modifiers.clone(),
        }
    }

    /// Returns the maximal number of memslots allowed in a [`Vm`]
    pub fn max_nr_memslots(&self) -> usize {
        self.fd.get_nr_memslots()
    }
}

/// Structure holding an general specific VM state.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct KvmState {
    /// Additional capabilities that were specified in cpu template.
    pub kvm_cap_modifiers: Vec<KvmCapability>,
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn test_combine_capabilities() {
        // Default caps for x86_64 and aarch64 both have KVM_CAP_IOEVENTFD and don't have
        // KVM_CAP_IOMMU caps.
        let additional_capabilities = vec![
            KvmCapability::Add(kvm_bindings::KVM_CAP_IOMMU),
            KvmCapability::Remove(kvm_bindings::KVM_CAP_IOEVENTFD),
        ];

        let combined_caps = Kvm::combine_capabilities(&additional_capabilities);
        assert!(
            combined_caps
                .iter()
                .any(|c| *c == kvm_bindings::KVM_CAP_IOMMU)
        );
        assert!(
            !combined_caps
                .iter()
                .any(|c| *c == kvm_bindings::KVM_CAP_IOEVENTFD)
        );
    }
}
