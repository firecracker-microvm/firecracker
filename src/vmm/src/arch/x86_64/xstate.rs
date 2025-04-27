// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm_sys_util::syscall::SyscallReturnCode;

use crate::arch::x86_64::generated::arch_prctl;

const INTEL_AMX_MASK: u64 = 1u64 << arch_prctl::ARCH_XCOMP_TILEDATA;

/// Errors assocaited with x86_64's dynamic XSAVE state features.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum XstateError {
    /// Failed to get supported XSTATE features: {0}
    GetSupportedFeatures(std::io::Error),
    /// Failed to request permission for XSTATE feature ({0}): {1}
    RequestFeaturePermission(u32, std::io::Error),
}

/// Request permission for all dynamic XSTATE features.
///
/// Some XSTATE features are not permitted by default, because they may require a larger area to
/// save their states than the tranditional 4096-byte area. Instead, the permission for them can be
/// requested via arch_prctl().
/// https://github.com/torvalds/linux/blob/master/Documentation/arch/x86/xstate.rst
///
/// Firecracker requests permission for them by default if available in order to retrieve the
/// full supported feature set via KVM_GET_SUPPORTED_CPUID.
/// https://docs.kernel.org/virt/kvm/api.html#kvm-get-supported-cpuid
///
/// Note that requested features can be masked by a CPU template.
pub fn request_dynamic_xstate_features() -> Result<(), XstateError> {
    let supported_xfeatures =
        match get_supported_xfeatures().map_err(XstateError::GetSupportedFeatures)? {
            Some(supported_xfeatures) => supported_xfeatures,
            // Exit early if dynamic XSTATE feature enabling is not supported on the kernel.
            None => return Ok(()),
        };

    // Intel AMX's TILEDATA
    //
    // Unless requested, on kernels prior to v6.4, KVM_GET_SUPPORTED_CPUID returns an
    // inconsistent state where TILECFG is set but TILEDATA isn't. Such a half-enabled state
    // causes guest crash during boot because a guest calls XSETBV instruction with all
    // XSAVE feature bits enumerated on CPUID and XSETBV only accepts either of both Intel
    // AMX bits enabled or disabled; otherwise resulting in general protection fault.
    if supported_xfeatures & INTEL_AMX_MASK == INTEL_AMX_MASK {
        request_xfeature_permission(arch_prctl::ARCH_XCOMP_TILEDATA).map_err(|err| {
            XstateError::RequestFeaturePermission(arch_prctl::ARCH_XCOMP_TILEDATA, err)
        })?;
    }

    Ok(())
}

/// Get supported XSTATE features
///
/// Returns Ok(None) if dynamic XSTATE feature enabling is not supported.
fn get_supported_xfeatures() -> Result<Option<u64>, std::io::Error> {
    let mut supported_xfeatures: u64 = 0;

    // SAFETY: Safe because the third input (`addr`) is a valid `c_ulong` pointer.
    // https://man7.org/linux/man-pages/man2/arch_prctl.2.html
    match SyscallReturnCode(unsafe {
        libc::syscall(
            libc::SYS_arch_prctl,
            arch_prctl::ARCH_GET_XCOMP_SUPP,
            &mut supported_xfeatures as *mut libc::c_ulong,
        )
    })
    .into_empty_result()
    {
        Ok(()) => Ok(Some(supported_xfeatures)),
        // EINVAL is returned if the dynamic XSTATE feature enabling is not supported (e.g. kernel
        // version prior to v5.17).
        // https://github.com/torvalds/linux/commit/980fe2fddcff21937c93532b4597c8ea450346c1
        Err(err) if err.raw_os_error() == Some(libc::EINVAL) => Ok(None),
        Err(err) => Err(err),
    }
}

/// Request permission for a dynamic XSTATE feature.
///
/// This should be called after `get_supported_xfeatures()` that also checks that dynamic XSTATE
/// feature enabling is supported.
fn request_xfeature_permission(xfeature: u32) -> Result<(), std::io::Error> {
    // SAFETY: Safe because the third input (`addr`) is a valid `c_ulong` value.
    // https://man7.org/linux/man-pages/man2/arch_prctl.2.html
    SyscallReturnCode(unsafe {
        libc::syscall(
            libc::SYS_arch_prctl,
            arch_prctl::ARCH_REQ_XCOMP_GUEST_PERM as libc::c_ulong,
            xfeature as libc::c_ulong,
        )
    })
    .into_empty_result()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Get permitted XSTATE features.
    fn get_permitted_xstate_features() -> Result<u64, std::io::Error> {
        let mut permitted_xfeatures: u64 = 0;
        // SAFETY: Safe because the third input (`addr`) is a valid `c_ulong` pointer.
        match SyscallReturnCode(unsafe {
            libc::syscall(
                libc::SYS_arch_prctl,
                arch_prctl::ARCH_GET_XCOMP_GUEST_PERM,
                &mut permitted_xfeatures as *mut libc::c_ulong,
            )
        })
        .into_empty_result()
        {
            Ok(()) => Ok(permitted_xfeatures),
            Err(err) => Err(err),
        }
    }

    #[test]
    fn test_request_xstate_feature_permission() {
        request_dynamic_xstate_features().unwrap();

        let supported_xfeatures = match get_supported_xfeatures().unwrap() {
            Some(supported_xfeatures) => supported_xfeatures,
            // Nothing to test if dynamic XSTATE feature enabling is not supported on the kernel.
            None => return,
        };

        // Check each dynamic feature is enabled. (currently only Intel AMX TILEDATA)
        if supported_xfeatures & INTEL_AMX_MASK == INTEL_AMX_MASK {
            let permitted_xfeatures = get_permitted_xstate_features().unwrap();
            assert_eq!(permitted_xfeatures & INTEL_AMX_MASK, INTEL_AMX_MASK);
        }
    }
}
