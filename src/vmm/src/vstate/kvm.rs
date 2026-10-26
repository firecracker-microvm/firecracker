// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use kvm_bindings::KVM_API_VERSION;
use kvm_ioctls::Kvm as KvmFd;
use serde::{Deserialize, Serialize};

pub use crate::arch::{Kvm, KvmArchError};
use crate::cpu_config::templates::KvmCapability;

// TODO: take them from kvm-bindings when guest_memfd flags and userfault support are merged
// upstream
const KVM_CAP_GUEST_MEMFD_FLAGS: u32 = 244;
const KVM_CAP_USERFAULT: u32 = 245;

const GUEST_MEMFD_FLAG_MMAP: u64 = 1;
const GUEST_MEMFD_FLAG_INIT_SHARED: u64 = 2;
const GUEST_MEMFD_FLAG_NO_DIRECT_MAP: u64 = 4;
const GUEST_MEMFD_FLAG_WRITE: u64 = 8;

pub(crate) const SECRET_FREE_BOOT_GUEST_MEMFD_FLAGS: u64 =
    GUEST_MEMFD_FLAG_MMAP | GUEST_MEMFD_FLAG_INIT_SHARED | GUEST_MEMFD_FLAG_NO_DIRECT_MAP;
pub(crate) const SECRET_FREE_RESTORE_GUEST_MEMFD_FLAGS: u64 =
    SECRET_FREE_BOOT_GUEST_MEMFD_FLAGS | GUEST_MEMFD_FLAG_WRITE;

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
    /// guest_memfd flags are not supported on this host kernel: requested {0:#x}, supported {1:#x}.
    GuestMemfdFlagsNotSupported(u64, u64),
    /// Architecture specific error: {0}
    ArchError(#[from] KvmArchError)
}

impl Kvm {
    /// Create `Kvm` struct.
    ///
    /// Checks that the host kernel supports all KVM capabilities required by the microVM before
    /// any VM resource is created, so that an unsupported host fails early.
    ///
    /// # Arguments
    ///
    /// * `kvm_cap_modifiers` - Capabilities added to or removed from the required ones (e.g. by a
    ///   CPU template). They are applied last, so they can remove any required capability.
    /// * `secret_free` - Whether the microVM uses secret-free guest memory backed by guest_memfd.
    /// * `from_snapshot` - Whether the microVM is restored from a snapshot instead of booted.
    pub fn new(
        kvm_cap_modifiers: Vec<KvmCapability>,
        secret_free: bool,
        from_snapshot: bool,
    ) -> Result<Self, KvmError> {
        let kvm_fd = KvmFd::new().map_err(KvmError::Kvm)?;

        // Check that KVM has the correct version.
        // Safe to cast because this is a constant.
        #[allow(clippy::cast_possible_wrap)]
        if kvm_fd.get_api_version() != KVM_API_VERSION as i32 {
            return Err(KvmError::ApiVersion(kvm_fd.get_api_version()));
        }

        let total_caps = Self::combine_capabilities(&kvm_cap_modifiers, secret_free, from_snapshot);
        // Check that all desired capabilities are supported.
        Self::check_capabilities(&kvm_fd, &total_caps).map_err(KvmError::Capabilities)?;

        // Check that all desired guest_memfd flags are supported.
        Self::check_guest_memfd_flags(&kvm_fd, &total_caps, secret_free, from_snapshot)?;

        Ok(Kvm::init_arch(kvm_fd, kvm_cap_modifiers)?)
    }

    /// Returns the capabilities that the host kernel must support for the given microVM
    /// configuration.
    ///
    /// The capabilities required by the configuration are added to
    /// [`Self::DEFAULT_CAPABILITIES`] first, and `kvm_cap_modifiers` are applied last, so that
    /// the modifiers can add or remove any capability, including the required ones.
    fn combine_capabilities(
        kvm_cap_modifiers: &[KvmCapability],
        secret_free: bool,
        from_snapshot: bool,
    ) -> Vec<u32> {
        let mut total_caps = Self::DEFAULT_CAPABILITIES.to_vec();

        // Required by secret freedom regardless of how the microVM is built.
        if secret_free {
            total_caps.extend([
                kvm_bindings::KVM_CAP_GUEST_MEMFD,
                KVM_CAP_GUEST_MEMFD_FLAGS,
                kvm_bindings::KVM_CAP_USER_MEMORY2,
            ]);
            // Snapshot restore also tracks guest memory population with a userfault bitmap.
            if from_snapshot {
                total_caps.push(KVM_CAP_USERFAULT);
            }
        }

        // Apply the modifiers on top of the required capabilities.
        for modifier in kvm_cap_modifiers.iter() {
            match modifier {
                KvmCapability::Add(cap) => {
                    if !total_caps.contains(cap) {
                        total_caps.push(*cap);
                    }
                }
                KvmCapability::Remove(cap) => total_caps.retain(|c| c != cap),
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

    /// Checks that the host kernel supports the guest_memfd flags required by the given microVM
    /// configuration.
    ///
    /// The flags are not checked when `KVM_CAP_GUEST_MEMFD_FLAGS` was removed from the combined
    /// capabilities, so that capability modifiers can override this check as well.
    fn check_guest_memfd_flags(
        kvm_fd: &KvmFd,
        total_caps: &[u32],
        secret_free: bool,
        from_snapshot: bool,
    ) -> Result<(), KvmError> {
        if !secret_free || !total_caps.contains(&KVM_CAP_GUEST_MEMFD_FLAGS) {
            return Ok(());
        }

        let required_flags = match from_snapshot {
            false => SECRET_FREE_BOOT_GUEST_MEMFD_FLAGS,
            true => SECRET_FREE_RESTORE_GUEST_MEMFD_FLAGS,
        };
        // KVM_CHECK_EXTENSION returns a negative value only if the ioctl itself fails, which is
        // treated as no flags being supported.
        let supported_flags =
            u64::try_from(kvm_fd.check_extension_raw(KVM_CAP_GUEST_MEMFD_FLAGS.into()))
                .unwrap_or(0);

        if supported_flags & required_flags == required_flags {
            Ok(())
        } else {
            Err(KvmError::GuestMemfdFlagsNotSupported(
                required_flags,
                supported_flags,
            ))
        }
    }

    /// Saves and returns the Kvm state.
    pub fn save_state(&self) -> KvmState {
        KvmState {
            kvm_cap_modifiers: self.kvm_cap_modifiers.clone(),
        }
    }

    /// Returns the maximal number of memslots allowed in a [`Vm`]
    pub fn max_nr_memslots(&self) -> u32 {
        self.fd
            .get_nr_memslots()
            .try_into()
            .expect("Number of vcpus reported by KVM exceeds u32::MAX")
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

        let combined_caps = Kvm::combine_capabilities(&additional_capabilities, false, false);
        assert!(combined_caps.contains(&kvm_bindings::KVM_CAP_IOMMU));
        assert!(!combined_caps.contains(&kvm_bindings::KVM_CAP_IOEVENTFD));
    }

    #[test]
    fn test_combine_capabilities_secret_free() {
        let default_caps = Kvm::DEFAULT_CAPABILITIES.to_vec();

        // Without secret freedom, neither boot nor snapshot restore requires additional
        // capabilities.
        assert_eq!(Kvm::combine_capabilities(&[], false, false), default_caps);
        assert_eq!(Kvm::combine_capabilities(&[], false, true), default_caps);

        // Secret freedom requires guest_memfd and KVM_SET_USER_MEMORY_REGION2, and userfault
        // only on snapshot restore.
        let boot_caps = Kvm::combine_capabilities(&[], true, false);
        let restore_caps = Kvm::combine_capabilities(&[], true, true);
        for cap in [
            kvm_bindings::KVM_CAP_GUEST_MEMFD,
            KVM_CAP_GUEST_MEMFD_FLAGS,
            kvm_bindings::KVM_CAP_USER_MEMORY2,
        ] {
            assert!(boot_caps.contains(&cap));
            assert!(restore_caps.contains(&cap));
        }
        assert!(!boot_caps.contains(&KVM_CAP_USERFAULT));
        assert!(restore_caps.contains(&KVM_CAP_USERFAULT));

        // Capability modifiers can remove capabilities required by secret freedom, in the same
        // way as they can remove the default ones.
        let modifiers = vec![
            KvmCapability::Remove(kvm_bindings::KVM_CAP_USER_MEMORY2),
            KvmCapability::Remove(KVM_CAP_USERFAULT),
        ];
        let combined_caps = Kvm::combine_capabilities(&modifiers, true, true);
        assert!(!combined_caps.contains(&kvm_bindings::KVM_CAP_USER_MEMORY2));
        assert!(!combined_caps.contains(&KVM_CAP_USERFAULT));
        assert!(combined_caps.contains(&kvm_bindings::KVM_CAP_GUEST_MEMFD));
    }

    #[test]
    fn test_check_guest_memfd_flags() {
        let kvm_fd = KvmFd::new().unwrap();

        // No guest_memfd flags are required without secret freedom.
        let total_caps = Kvm::combine_capabilities(&[], false, false);
        Kvm::check_guest_memfd_flags(&kvm_fd, &total_caps, false, false).unwrap();

        // Removing `KVM_CAP_GUEST_MEMFD_FLAGS` skips the check, even if the host kernel does not
        // support the required flags.
        let modifiers = vec![KvmCapability::Remove(KVM_CAP_GUEST_MEMFD_FLAGS)];
        let total_caps = Kvm::combine_capabilities(&modifiers, true, true);
        Kvm::check_guest_memfd_flags(&kvm_fd, &total_caps, true, true).unwrap();
    }
}
