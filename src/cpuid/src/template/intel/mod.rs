// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Follows a C3 template in setting up the CPUID.
pub mod c3;
/// Follows a T2 template in setting up the CPUID.
pub mod t2;
/// Follows a T2 template for setting up the CPUID with additional MSRs
/// that are speciffic to an Intel Skylake CPU.
pub mod t2s;

use std::collections::HashSet;

use arch_gen::x86::msr_index::*;
use kvm_bindings::CpuId;

use crate::common::{get_vendor_id_from_host, VENDOR_ID_INTEL};
use crate::cpuid_is_feature_set;
use crate::transformer::Error;

pub fn validate_vendor_id() -> Result<(), Error> {
    let vendor_id = get_vendor_id_from_host()?;
    if &vendor_id != VENDOR_ID_INTEL {
        return Err(Error::InvalidVendor);
    }

    Ok(())
}

/// Returns MSRs to be saved based on the Intel CPUID features that are enabled.
pub(crate) fn msrs_to_save_by_cpuid(cpuid: &CpuId) -> HashSet<u32> {
    use crate::cpu_leaf::*;

    let mut msrs = HashSet::new();

    // Macro used for easy definition of CPUID-MSR dependencies.
    macro_rules! cpuid_msr_dep {
        ($leaf:expr, $index:expr, $reg:tt, $feature_bit:expr, $msr:expr) => {
            if cpuid_is_feature_set!(cpuid, $leaf, $index, $reg, $feature_bit) {
                msrs.extend($msr)
            }
        };
    }

    // TODO: Add more dependencies.
    cpuid_msr_dep!(
        0x7,
        0,
        ebx,
        leaf_0x7::index0::ebx::MPX_BITINDEX,
        [MSR_IA32_BNDCFGS]
    );
    msrs
}
