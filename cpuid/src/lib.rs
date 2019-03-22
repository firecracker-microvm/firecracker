// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

#![deny(missing_docs)]
//! Utility for configuring the CPUID (CPU identification) for the guest microVM.

extern crate kvm;
extern crate kvm_bindings;

use kvm::CpuId;

mod common;
use common::*;

/// Contains helper methods for bit operations.
pub mod bit_helper;

mod template;
pub use template::c3;
pub use template::t2;

mod cpu_leaf;

mod transformer;
pub use transformer::Error;
use transformer::*;

mod brand_string;

/// Sets up the CPUID entries for the given vcpu.
///
/// # Arguments
///
/// * `cpu_id` - The index of the VCPU for which the CPUID entries are configured.
/// * `cpu_count` - The total number of present VCPUs.
/// * `ht_enabled` - Whether or not to enable HT.
/// * `kvm_cpuid` - KVM related structure holding the relevant CPUID info.
///
/// # Example
/// ```
/// extern crate cpuid;
/// extern crate kvm;
///
/// use cpuid::filter_cpuid;
/// use kvm::{CpuId, Kvm, MAX_KVM_CPUID_ENTRIES};
///
/// let kvm = Kvm::new().unwrap();
/// let mut kvm_cpuid: CpuId = kvm.get_supported_cpuid(MAX_KVM_CPUID_ENTRIES).unwrap();
/// filter_cpuid(0, 1, true, &mut kvm_cpuid).unwrap();
///
/// // Get expected `kvm_cpuid` entries.
/// let entries = kvm_cpuid.mut_entries_slice();
/// ```
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn filter_cpuid(
    cpu_id: u8,
    cpu_count: u8,
    ht_enabled: bool,
    kvm_cpuid: &mut CpuId,
) -> Result<(), Error> {
    let vendor_id = get_vendor_id().map_err(Error::InternalError)?;
    let vm_spec = VmSpec::new(&vendor_id, cpu_id, cpu_count, ht_enabled);

    let maybe_cpuid_transformer: Option<&dyn CpuidTransformer> = match &vendor_id {
        VENDOR_ID_INTEL => Some(&intel::IntelCpuidTransformer {}),
        VENDOR_ID_AMD => Some(&amd::AmdCpuidTransformer {}),
        _ => None,
    };

    if let Some(cpuid_transformer) = maybe_cpuid_transformer {
        cpuid_transformer.preprocess_cpuid(kvm_cpuid)?;
        for entry in kvm_cpuid.mut_entries_slice().iter_mut() {
            cpuid_transformer.transform_entry(entry, &vm_spec)?;
        }
    }

    Ok(())
}
