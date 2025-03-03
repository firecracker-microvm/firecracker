// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use kvm_bindings::KVM_API_VERSION;
#[cfg(target_arch = "x86_64")]
use kvm_bindings::{CpuId, MsrList, KVM_MAX_CPUID_ENTRIES};
use kvm_ioctls::Kvm as KvmFd;
use serde::{Deserialize, Serialize};
#[cfg(target_arch = "x86_64")]
use vmm_sys_util::syscall::SyscallReturnCode;

#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::gen::arch_prctl;
use crate::cpu_config::templates::KvmCapability;
use crate::vstate::memory::{GuestMemory, GuestMemoryMmap};

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
    #[cfg(target_arch = "x86_64")]
    /// Failed to get supported cpuid: {0}
    GetSupportedCpuId(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get supported XSTATE features: {0}
    GetSupportedXstateFeatures(std::io::Error),
    /// The number of configured slots is bigger than the maximum reported by KVM
    NotEnoughMemorySlots,
    #[cfg(target_arch = "x86_64")]
    /// Failed to enable XSTATE features ({0:#b}): {1}
    RequestXstateFeatures(u32, std::io::Error),
}

/// Struct with kvm fd and kvm associated paramenters.
#[derive(Debug)]
pub struct Kvm {
    /// KVM fd.
    pub fd: KvmFd,
    /// Maximum number of memory slots allowed by KVM.
    pub max_memslots: usize,
    /// Additional capabilities that were specified in cpu template.
    pub kvm_cap_modifiers: Vec<KvmCapability>,

    #[cfg(target_arch = "x86_64")]
    /// Supported CpuIds.
    pub supported_cpuid: CpuId,
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

        let max_memslots = kvm_fd.get_nr_memslots();

        #[cfg(target_arch = "aarch64")]
        {
            Ok(Self {
                fd: kvm_fd,
                max_memslots,
                kvm_cap_modifiers,
            })
        }

        #[cfg(target_arch = "x86_64")]
        {
            Self::enable_intel_amx()?;

            let supported_cpuid = kvm_fd
                .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
                .map_err(KvmError::GetSupportedCpuId)?;

            Ok(Kvm {
                fd: kvm_fd,
                max_memslots,
                kvm_cap_modifiers,
                supported_cpuid,
            })
        }
    }

    #[cfg(target_arch = "x86_64")]
    // XSTATE feature mask for Intel AMX.
    const INTEL_AMX_XCOMP_MASK: libc::c_ulong =
        (1u64 << arch_prctl::ARCH_XCOMP_TILECFG) | (1u64 << arch_prctl::ARCH_XCOMP_TILEDATA);

    /// Enable Intel AMX if available.
    ///
    /// Intel AMX (Advanced Matrix Extensions) is an instruction set for AI workloads that was
    /// introduced in Intel Sapphire Rapids (*7i.metal). Since it requires larger area to save the
    /// state, it is disabled by default.
    /// https://github.com/torvalds/linux/blob/master/Documentation/arch/x86/xstate.rst
    ///
    /// We enable it by default but can be disabled by CPU template; otherwise,
    /// KVM_GET_SUPPORTED_CPUID returns a inconsistent state where TILECFG is enabled but TILEDATA
    /// is disabled, causing guest's #GP fault on xsetbv due to the lack of sanity check.
    /// https://lore.kernel.org/all/20230405004520.421768-1-seanjc@google.com/
    ///
    /// Dynamically-enabled feature bits need to be requested with arch_prctl() before calling
    /// KVM_GET_SUPPORTED_CPUID. Feature bits that have not been requested are excluded from the
    /// result of KVM_GET_SUPPORTED_CPUID.
    /// https://docs.kernel.org/virt/kvm/api.html
    ///
    /// Note that no memory allocation to save Intel AMX state happens here immediately.
    #[cfg(target_arch = "x86_64")]
    fn enable_intel_amx() -> Result<(), KvmError> {
        // Get the supported xstate features.
        let mut supported_xfeatures: libc::c_ulong = 0;
        // SAFETY: Safe because the second input (`op`) might not be valid for unsupported kernels
        // but EINVAL is handled later, and the third input (`addr`) is a valid c_ulong pointer.
        // https://man7.org/linux/man-pages/man2/arch_prctl.2.html
        SyscallReturnCode(unsafe {
            libc::syscall(
                libc::SYS_arch_prctl,
                arch_prctl::ARCH_GET_XCOMP_SUPP,
                &mut supported_xfeatures as *mut libc::c_ulong,
            )
        })
        .into_empty_result()
        .or_else(|err| {
            // EINVAL is returned if ARCH_GET_XCOMP_SUPP is not supported (e.g. kernel versions
            // prior to v5.17).
            // https://github.com/torvalds/linux/commit/980fe2fddcff21937c93532b4597c8ea450346c1
            if err.raw_os_error() == Some(libc::EINVAL) {
                Ok(())
            } else {
                Err(err)
            }
        })
        .map_err(KvmError::GetSupportedXstateFeatures)?;

        // Enable Intel AMX if supported.
        if (supported_xfeatures & Self::INTEL_AMX_XCOMP_MASK) == Self::INTEL_AMX_XCOMP_MASK {
            // SAFETY: Safe because ARCH_REQ_XCOMP_GUEST_PERM is supported if ARCH_GET_XCOMP_SUPP is
            // supported and it has been confirmed that ARCH_XCOMP_TILEDATA is supported.
            SyscallReturnCode(unsafe {
                libc::syscall(
                    libc::SYS_arch_prctl,
                    arch_prctl::ARCH_REQ_XCOMP_GUEST_PERM,
                    arch_prctl::ARCH_XCOMP_TILEDATA,
                )
            })
            .into_empty_result()
            .map_err(|err| KvmError::RequestXstateFeatures(arch_prctl::ARCH_XCOMP_TILEDATA, err))?;
        }

        Ok(())
    }

    /// Msrs needed to be saved on snapshot creation.
    #[cfg(target_arch = "x86_64")]
    pub fn msrs_to_save(&self) -> Result<MsrList, crate::arch::x86_64::msr::MsrError> {
        crate::arch::x86_64::msr::get_msrs_to_save(&self.fd)
    }

    /// Check guest memory does not have more regions than kvm allows.
    pub fn check_memory(&self, guest_mem: &GuestMemoryMmap) -> Result<(), KvmError> {
        if guest_mem.num_regions() > self.max_memslots {
            Err(KvmError::NotEnoughMemorySlots)
        } else {
            Ok(())
        }
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
}
#[cfg(target_arch = "aarch64")]
/// Optional capabilities.
#[derive(Debug, Default)]
pub struct OptionalCapabilities {
    /// KVM_CAP_COUNTER_OFFSET
    pub counter_offset: bool,
}
#[cfg(target_arch = "aarch64")]
impl Kvm {
    const DEFAULT_CAPABILITIES: [u32; 7] = [
        kvm_bindings::KVM_CAP_IOEVENTFD,
        kvm_bindings::KVM_CAP_IRQFD,
        kvm_bindings::KVM_CAP_USER_MEMORY,
        kvm_bindings::KVM_CAP_ARM_PSCI_0_2,
        kvm_bindings::KVM_CAP_DEVICE_CTRL,
        kvm_bindings::KVM_CAP_MP_STATE,
        kvm_bindings::KVM_CAP_ONE_REG,
    ];

    /// Returns struct with optional capabilities statuses.
    pub fn optional_capabilities(&self) -> OptionalCapabilities {
        OptionalCapabilities {
            counter_offset: self
                .fd
                .check_extension_raw(kvm_bindings::KVM_CAP_COUNTER_OFFSET.into())
                != 0,
        }
    }
}

#[cfg(target_arch = "x86_64")]
impl Kvm {
    const DEFAULT_CAPABILITIES: [u32; 14] = [
        kvm_bindings::KVM_CAP_IRQCHIP,
        kvm_bindings::KVM_CAP_IOEVENTFD,
        kvm_bindings::KVM_CAP_IRQFD,
        kvm_bindings::KVM_CAP_USER_MEMORY,
        kvm_bindings::KVM_CAP_SET_TSS_ADDR,
        kvm_bindings::KVM_CAP_PIT2,
        kvm_bindings::KVM_CAP_PIT_STATE2,
        kvm_bindings::KVM_CAP_ADJUST_CLOCK,
        kvm_bindings::KVM_CAP_DEBUGREGS,
        kvm_bindings::KVM_CAP_MP_STATE,
        kvm_bindings::KVM_CAP_VCPU_EVENTS,
        kvm_bindings::KVM_CAP_XCRS,
        kvm_bindings::KVM_CAP_XSAVE,
        kvm_bindings::KVM_CAP_EXT_CPUID,
    ];
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
        assert!(combined_caps
            .iter()
            .any(|c| *c == kvm_bindings::KVM_CAP_IOMMU));
        assert!(!combined_caps
            .iter()
            .any(|c| *c == kvm_bindings::KVM_CAP_IOEVENTFD));
    }

    #[cfg(target_arch = "x86_64")]
    mod x86_64 {
        use super::*;
        use crate::arch::x86_64::cpu_model::CpuModel;

        #[derive(PartialEq, PartialOrd)]
        struct KernelVersion(u32, u32);

        impl KernelVersion {
            fn current() -> Self {
                let version_str = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap();
                let mut parts = version_str.trim().split('.');

                let major = parts.next().unwrap().parse::<u32>().unwrap();
                let minor = parts.next().unwrap().parse::<u32>().unwrap();

                KernelVersion(major, minor)
            }
        }

        #[derive(PartialEq)]
        enum Vendor {
            Intel,
            Amd,
        }

        impl Vendor {
            fn new() -> Self {
                let vendor_id = Self::get_vendor_id_str();
                match vendor_id.as_str() {
                    "GenuineIntel" => Vendor::Intel,
                    "AuthenticAMD" => Vendor::Amd,
                    _ => panic!("Unknown vendor_id: {}", vendor_id),
                }
            }

            fn get_vendor_id_str() -> String {
                let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap();

                for line in cpuinfo.lines() {
                    if line.starts_with("vendor_id") {
                        return line
                            .split(':')
                            .nth(1)
                            .map(|s| s.trim().to_string())
                            .unwrap();
                    }
                }
                panic!("`vendor_id` not found in /proc/cpuinfo");
            }
        }

        #[cfg(target_arch = "x86_64")]
        #[test]
        fn test_enable_intel_amx() {
            Kvm::enable_intel_amx().unwrap();

            // ARCH_{REQ,GET}_XCOMP_GUEST_PERM were added in kernel v5.17.
            //  https://github.com/torvalds/linux/commit/980fe2fddcff21937c93532b4597c8ea450346c1
            let supported_version = KernelVersion(5, 17);
            let current_version = KernelVersion::current();

            if current_version >= supported_version {
                let mut permitted_xfeatures: libc::c_ulong = 0;
                // SAFETY: Safe because the second input (`op`) should be valid on kernel v5.17+,
                // and the third input (`addr`) is a valid `c_ulong` pointer.
                SyscallReturnCode(unsafe {
                    libc::syscall(
                        libc::SYS_arch_prctl,
                        arch_prctl::ARCH_GET_XCOMP_GUEST_PERM,
                        &mut permitted_xfeatures as *mut libc::c_ulong,
                    )
                })
                .into_empty_result()
                .unwrap();

                // Intel AMX is available only on Intel processors now.
                let vendor = Vendor::new();

                // Intel AMX is introduced in Intel Sapphire Rapids (CPUID.01H:EAX = 0x000806f8).
                let supported_cpu = CpuModel::from(&0x000806f8);
                let current_cpu = CpuModel::get_cpu_model();

                if current_cpu >= supported_cpu && vendor == Vendor::Intel {
                    assert_eq!(
                        permitted_xfeatures & Kvm::INTEL_AMX_XCOMP_MASK,
                        Kvm::INTEL_AMX_XCOMP_MASK
                    );
                } else {
                    assert_eq!(permitted_xfeatures & Kvm::INTEL_AMX_XCOMP_MASK, 0);
                }
            }
        }
    }
}
