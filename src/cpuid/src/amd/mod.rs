// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![warn(clippy::pedantic)]

use std::convert::TryInto;
use std::fmt;

use log_derive::{logfn, logfn_inputs};
use serde::{Deserialize, Serialize};

use crate::{FeatureRelation, FixedString, RawCpuid};

/// Error type for [`AmdCpuid::apply_vm_spec`].
#[derive(Debug)]
pub struct ApplyVmSpecError;
impl std::error::Error for ApplyVmSpecError {}
impl fmt::Display for ApplyVmSpecError {
    fn fmt(&self, _f: &mut fmt::Formatter) -> fmt::Result {
        unimplemented!()
    }
}
/// A structure containing the information as described in the AMD CPUID specification as described
/// in
/// [AMD64 Architecture Programmer’s Manual Volume 3: General-Purpose and System Instructions](https://www.amd.com/system/files/TechDocs/24594.pdf)
/// .
///
/// # Notes
///
/// We not do not currently check AMD features on snapshot restore.
#[allow(clippy::unsafe_derive_deserialize, clippy::module_name_repetitions)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct AmdCpuid(pub RawCpuid);

// TODO: Replace checking of CPUID avaiblity with `x86` and `x86_64` check and
// [`std::arch_x86_64::has_cpuid()`] when this is stabilized. CPUID is supported when:
// - We are on an x86 archtecture with `sse` enabled and `sgx disabled`.
// - We are on an x86_64 architecture with `sgx` disabled
#[cfg(any(
    all(target_arch = "x86", target_feature = "sse", not(target_env = "sgx")),
    all(target_arch = "x86_64", not(target_env = "sgx"))
))]
impl AmdCpuid {
    /// Alias for [`AmdCpuid::default`]
    #[must_use]
    pub fn new() -> Self {
        Self(RawCpuid::new())
    }
}
impl AmdCpuid {
    /// Returns the CPUID manufacturers ID. E.g. `GenuineIntel` or `AuthenticAMD`.
    ///
    /// # Panics
    ///
    /// When the underlying [`RawCpuid`] has no entry for leaf 0.
    #[must_use]
    pub fn manufacturer_id(&self) -> FixedString<12> {
        let leaf = self.0.get(0, 0).unwrap();
        let manufacturer_str: [u8; 12] = [
            leaf.ebx.to_ne_bytes(),
            leaf.edx.to_ne_bytes(),
            leaf.ecx.to_ne_bytes(),
        ]
        .concat()
        .try_into()
        .unwrap();
        FixedString(manufacturer_str)
    }
    /// Applies `vm_spec` to `self`.
    ///
    /// # Errors
    ///
    /// Never.
    #[allow(clippy::unused_self)]
    pub fn apply_vm_spec(&mut self, _vm_spec: &crate::VmSpec) -> Result<(), ApplyVmSpecError> {
        // unimplemented
        Ok(())
    }
}
impl crate::FeatureComparison for AmdCpuid {
    /// Checks if `self` is a able to support `other`.
    ///
    /// Checks if a process from an environment with CPUID `other` could be continued in an
    /// environment with the CPUID `self`.
    #[logfn(Trace)]
    #[logfn_inputs(Trace)]
    fn feature_cmp(&self, other: &Self) -> Option<FeatureRelation> {
        Some(FeatureRelation::Equal)
    }
}
impl Default for AmdCpuid {
    /// Constructs new `Cpuid` via [`core::arch::x86_64::__cpuid_count`].
    ///
    /// # Note
    ///
    /// As we do not currently support the AMD CPUID specification this constructs an empty
    /// [`RawCpuid`].
    fn default() -> Self {
        Self(RawCpuid::new())
    }
}
impl From<RawCpuid> for AmdCpuid {
    fn from(raw_cpuid: RawCpuid) -> Self {
        Self(raw_cpuid)
    }
}
impl From<AmdCpuid> for RawCpuid {
    fn from(amd_cpuid: AmdCpuid) -> Self {
        amd_cpuid.0
    }
}
