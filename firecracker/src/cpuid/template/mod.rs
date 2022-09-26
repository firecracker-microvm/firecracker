// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Contains Intel specific templates.
pub mod intel;

use std::collections::HashSet;

use kvm_bindings::CpuId;

use crate::common::{get_vendor_id_from_cpuid, VENDOR_ID_INTEL};
use crate::transformer::Error;

/// Returns MSRs to be saved based on CPUID features that are enabled.
pub fn msrs_to_save_by_cpuid(cpuid: &CpuId) -> Result<HashSet<u32>, Error> {
    let vendor_id = get_vendor_id_from_cpuid(cpuid).map_err(|_| Error::InvalidVendor)?;
    match &vendor_id {
        VENDOR_ID_INTEL => Ok(intel::msrs_to_save_by_cpuid(cpuid)),
        _ => {
            // We don't have MSR-CPUID dependencies set for other vendors yet.
            Ok(HashSet::new())
        }
    }
}
