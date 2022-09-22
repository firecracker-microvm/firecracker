// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.
#![warn(clippy::pedantic)]
#![allow(clippy::unsafe_derive_deserialize)]
#![deny(missing_docs)]
//! Utility for configuring the CPUID (CPU identification) for the guest micro-VM.

use std::cmp::Ordering;
use std::convert::{TryFrom, TryInto};
use std::default::Default;
use std::{fmt, str};

pub use amd::AmdCpuid;
use common::GetCpuidError;
pub use cpuid_ffi::*;
pub use intel::IntelCpuid;
use log_derive::{logfn, logfn_inputs};
use serde::{Deserialize, Serialize};

/// cpuid utility functions.
pub mod common;

/// Contains helper methods for bit operations.
pub mod bit_helper;

mod brand_string;
/// T2S Intel template
pub mod t2s;

/// AMD CPUID specification handling.
pub mod amd;
/// Raw CPUID specification handling.
mod cpuid_ffi;
/// Intel CPUID specification handling.
pub mod intel;

/// Errors associated with processing the CPUID leaves.
#[allow(clippy::pub_enum_variant_names)]
#[derive(Debug, Clone, derive_more::From)]
pub enum Error {
    /// A FamStructWrapper operation has failed
    FamError(utils::fam::Error),
    /// A call to an internal helper method failed
    InternalError(common::Error),
    /// The operation is not permitted for the current vendor
    InvalidVendor,
    /// The maximum number of addressable logical CPUs cannot be stored in an `u8`.
    VcpuCountOverflow,
}

/// Structure containing the specifications of the VM
pub struct VmSpec {
    /// The vendor id of the CPU
    cpu_vendor_id: [u8; 12],
    /// The desired brand string for the guest.
    #[allow(dead_code)]
    brand_string: brand_string::BrandString,
    /// The index of the current logical CPU in the range [0..cpu_count].
    cpu_index: u8,
    /// The total number of logical CPUs.
    cpu_count: u8,
    /// The number of bits needed to enumerate logical CPUs per core.
    cpu_bits: u8,
}

impl VmSpec {
    /// Creates a new instance of [`VmSpec`] with the specified parameters
    /// The brand string is deduced from the `vendor_id`.
    ///
    /// # Errors
    ///
    /// When CPUID leaf 0 is not supported.
    pub fn new(cpu_index: u8, cpu_count: u8, smt: bool) -> Result<VmSpec, GetCpuidError> {
        let cpu_vendor_id = common::get_vendor_id_from_host()?;
        Ok(VmSpec {
            cpu_vendor_id,
            cpu_index,
            cpu_count,
            cpu_bits: (cpu_count > 1 && smt) as u8,
            brand_string: brand_string::BrandString::from_vendor_id(&cpu_vendor_id),
        })
    }

    /// Returns an immutable reference to `cpu_vendor_id`.
    #[must_use]
    pub fn cpu_vendor_id(&self) -> &[u8; 12] {
        &self.cpu_vendor_id
    }

    /// Returns the number of cpus per core
    #[must_use]
    pub fn cpus_per_core(&self) -> u8 {
        1 << self.cpu_bits
    }
}

/// CPUID infomation
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub enum Cpuid {
    /// Intel CPUID specific infomation.
    Intel(IntelCpuid),
    /// AMD CPUID specific infomation.
    Amd(AmdCpuid),
}

#[cfg(not(feature = "static"))]
/// Error type for [`Cpuid::new`].
#[derive(Debug)]
pub struct CpuidNewError(FixedString<12>);
#[cfg(not(feature = "static"))]
impl std::error::Error for CpuidNewError {}
#[cfg(not(feature = "static"))]
impl fmt::Display for Structure {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Unsupported manufacturer: \"{}\"", self.0)
    }
}

/// Error type for [`Cpuid::new`].
#[cfg(feature = "static")]
#[derive(Debug, thiserror::Error)]
pub enum CpuidNewError {
    /// Unsupported manufacturer.
    #[error("Unsupported manufacturer: \"{0}\"")]
    UnsupportedManufacturer(FixedString<12>),
    /// Cpuid has a leaf with more enumerated sub-leaves than are supported.
    #[error("Cpuid has a leaf with more enumerated sub-leaves than are supported: {0}")]
    LeafOverflow(#[from] intel::LeafOverflowError),
}

/// Error type for [`Cpuid::new`].
#[cfg(target_os = "linux")]
#[derive(Debug, thiserror::Error)]
pub enum KvmGetSupportedCpuidError {
    /// Could not access KVM.
    #[error("Could not access KVM: {0}")]
    KvmAccess(#[from] utils::errno::Error),
    /// Failed to create CPUID structure.
    #[error("Failed to create CPUID structure: {0}")]
    UnsupportedCPUIDManufacturerId(#[from] CpuidNewError),
}
/// Error type for [`Cpuid::apply_vm_spec`].
#[derive(Debug, thiserror::Error)]
pub enum ApplyVmSpecError {
    /// Failed to apply VmSpec to Intel CPUID.
    #[error("Failed to apply VmSpec to Intel CPUID: {0}")]
    Intel(#[from] intel::ApplyVmSpecError),
    /// Failed to apply VmSpec to AMD CPUID.
    #[error("Failed to apply VmSpec to AMD CPUID: {0}")]
    Amd(#[from] amd::ApplyVmSpecError),
}

// TODO: Replace checking of CPUID availability with `x86` and `x86_64` check and
// [`std::arch_x86_64::has_cpuid()`] when this is stabilized. CPUID is supported when:
// - We are on an x86 archtecture with `see` enabled and `sgx disabled`.
// - We are on an x86_64 architecture with `sgx` disabled
#[cfg(any(
    all(target_arch = "x86", target_feature = "sse", not(target_env = "sgx")),
    all(target_arch = "x86_64", not(target_env = "sgx"))
))]
impl Cpuid {
    // This is safe as we check for CPUID support, see above.
    /// Constructs new `Cpuid` via [`core::archx86_64::__cpuid_count`].
    ///
    /// # Safety
    ///
    /// The present compile time checks for implementation of CPUID are not complete, and the
    /// runtime checks within CPUID for implemented leaves have not been rigorously verified as
    /// correct. Thus while this function has not been found to produce unsafe behavior it cannot
    /// be stated with certainty it will never do so.
    ///
    /// # Errors
    ///
    /// When the host CPUID manufacturer ID is not `GenuineIntel` or `AuthenticAMD`.
    pub unsafe fn new() -> Result<Cpuid, CpuidNewError> {
        let manufacturer_str = Self::host_manufacturer_id();
        #[cfg(not(feature = "static"))]
        match &manufacturer_str.0 {
            b"GenuineIntel" => Ok(Cpuid::Intel(IntelCpuid::new())),
            b"AuthenticAMD" => Ok(Cpuid::Amd(AmdCpuid::new())),
            _ => Err(CpuidNewError(manufacturer_str)),
        }

        #[cfg(feature = "static")]
        match &manufacturer_str.0 {
            b"GenuineIntel" => Ok(Cpuid::Intel(IntelCpuid::new()?)),
            b"AuthenticAMD" => Ok(Cpuid::Amd(AmdCpuid::new())),
            _ => Err(CpuidNewError::UnsupportedManufacturer(manufacturer_str)),
        }
    }
    /// Returns the CPUID manufacturers ID. E.g. `GenuineIntel` or `AuthenticAMD`.
    ///
    /// # Panics
    ///
    /// Never. Unwrap is used in case where it will never error, see:
    /// ```ignore
    /// let manufacturer_str: [u8; 12] = [
    ///     leaf_0.ebx.to_ne_bytes(),
    ///     leaf_0.edx.to_ne_bytes(),
    ///     leaf_0.ecx.to_ne_bytes(),
    /// ].concat().try_into().unwrap();
    /// ```
    #[must_use]
    pub fn host_manufacturer_id() -> FixedString<12> {
        let leaf_0 = unsafe { core::arch::x86_64::__cpuid_count(0, 0) };
        let manufacturer_str: [u8; 12] = [
            leaf_0.ebx.to_ne_bytes(),
            leaf_0.edx.to_ne_bytes(),
            leaf_0.ecx.to_ne_bytes(),
        ]
        .concat()
        .try_into()
        .unwrap();
        FixedString(manufacturer_str)
    }
    /// Gets supported CPUID by KVM.
    ///
    /// # Errors
    ///
    /// When failed to access KVM.
    #[cfg(target_os = "linux")]
    pub fn kvm_get_supported_cpuid() -> std::result::Result<Self, KvmGetSupportedCpuidError> {
        let supported_kvm_cpuid =
            kvm_ioctls::Kvm::new()?.get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)?;
        let supported_raw_cpuid = RawCpuid::from(supported_kvm_cpuid);
        Cpuid::try_from(supported_raw_cpuid)
            .map_err(KvmGetSupportedCpuidError::UnsupportedCPUIDManufacturerId)
    }
}
impl Cpuid {
    #[cfg(any(feature = "c3", feature = "t2", feature = "t2s"))]
    const SIZE: usize = 66824; // std::mem::size_of::<Cpuid>()
    /// CPUID template for an AWS EC2 C3 instance.
    #[cfg(feature = "c3")]
    pub const C3: Cpuid = {
        let bytes = include_bytes!("./templates/c3");

        unsafe { std::mem::transmute::<[u8; Self::SIZE], Cpuid>(*bytes) }
    };
    /// CPUID template for an AWS EC2 T2 instance.
    #[cfg(feature = "t2")]
    pub const T2: Cpuid = {
        let bytes = include_bytes!("./templates/t2");

        unsafe { std::mem::transmute::<[u8; Self::SIZE], Cpuid>(*bytes) }
    };
    /// CPUID template for an AWS EC2 T2S instance.
    #[cfg(feature = "t2s")]
    pub const T2S: Cpuid = {
        let bytes = include_bytes!("./templates/t2s");

        unsafe { std::mem::transmute::<[u8; Self::SIZE], Cpuid>(*bytes) }
    };

    /// Returns `Some(&IntelCpuid)` if `Self == Self::Intel(_)` else returns `None`.
    #[must_use]
    pub fn intel(&self) -> Option<&IntelCpuid> {
        match self {
            Self::Intel(intel) => Some(intel),
            Self::Amd(_) => None,
        }
    }
    /// Returns `Some(&AmdCpuid)` if `Self == Self::Amd(_)` else returns `None`.
    #[must_use]
    pub fn amd(&self) -> Option<&AmdCpuid> {
        match self {
            Self::Intel(_) => None,
            Self::Amd(amd) => Some(amd),
        }
    }
    /// Returns the CPUID manufacturers ID. E.g. `GenuineIntel` or `AuthenticAMD`.
    #[must_use]
    pub fn manufacturer_id(&self) -> FixedString<12> {
        match self {
            Self::Intel(intel) => intel.manufacturer_id(),
            Self::Amd(amd) => amd.manufacturer_id(),
        }
    }
    /// Applies `vm_spec` to `self`.
    ///
    /// # Errors
    ///
    /// When failing:
    /// - [`Cpuid::IntelCpuid::apply_vm_spec`].
    /// - [`Cpuid::AmdCpuid::apply_vm_spec`].
    pub fn apply_vm_spec(&mut self, vm_spec: &VmSpec) -> Result<(), ApplyVmSpecError> {
        match self {
            Self::Intel(intel) => intel
                .apply_vm_spec(vm_spec)
                .map_err(ApplyVmSpecError::Intel),
            Self::Amd(amd) => amd.apply_vm_spec(vm_spec).map_err(ApplyVmSpecError::Amd),
        }
    }
}
impl FeatureComparison for Cpuid {
    /// Compare support of `self` to support `other`.
    ///
    /// For checking if a process from an environment with cpuid `other` could be continued in the
    /// environment with the cpuid `self`.
    ///
    /// - `Some(Equal)`: When `self` exactly matches `other`.
    /// - `Some(Subset)`: When `self` has less support than `other`.
    /// - `Some(Superset)`: When `self` has more support than `other`.
    /// - `None`: When a clear comparison cannot be drawn, e.g. Intel vs Amd.
    #[logfn(Trace)]
    #[logfn_inputs(Trace)]
    fn feature_cmp(&self, other: &Self) -> Option<FeatureRelation> {
        match (self, other) {
            (Self::Intel(a), Self::Intel(b)) => a.feature_cmp(b),
            (Self::Amd(a), Self::Amd(b)) => a.feature_cmp(b),
            _ => None,
        }
    }
}

/// Compares the feature supports between 2 structures.
pub trait FeatureComparison {
    /// Compares the feature supports between 2 structures.
    fn feature_cmp(&self, other: &Self) -> Option<FeatureRelation>;
}
impl<T: FeatureComparison> FeatureComparison for Option<T> {
    fn feature_cmp(&self, other: &Self) -> Option<FeatureRelation> {
        match (self, other) {
            (Some(a), Some(b)) => a.feature_cmp(&b),
            (None, Some(_)) => Some(FeatureRelation::Subset),
            (Some(_), None) => Some(FeatureRelation::Superset),
            (None, None) => Some(FeatureRelation::Equal),
        }
    }
}

/// Describes the feature support between 2 structures.
#[derive(Debug, PartialEq, Eq)]
pub enum FeatureRelation {
    /// Feature support is a superset.
    Superset,
    /// Feature support is equal.
    Equal,
    /// Feature support is a subset.
    Subset,
}
impl From<Ordering> for FeatureRelation {
    fn from(cmp: Ordering) -> Self {
        match cmp {
            Ordering::Less => FeatureRelation::Subset,
            Ordering::Equal => FeatureRelation::Equal,
            Ordering::Greater => FeatureRelation::Superset,
        }
    }
}

/// Error type for [`Cpuid::try_from`] for `RawCpuid`.
#[derive(Debug)]
pub struct UnsupportedCPUIDManufacturerId([u8; 12]);
impl std::error::Error for UnsupportedCPUIDManufacturerId {}
impl fmt::Display for UnsupportedCPUIDManufacturerId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Unsupported CPUID manufacturer ID '{}' (only 'GenuineIntel' and 'AuthenticAMD' are \
             supported)",
            std::str::from_utf8(&self.0).unwrap()
        )
    }
}

impl TryFrom<RawCpuid> for Cpuid {
    type Error = CpuidNewError;
    fn try_from(raw_cpuid: RawCpuid) -> Result<Self, Self::Error> {
        let manufacturer_str: [u8; 12] = [
            raw_cpuid[0].ebx.to_ne_bytes(),
            raw_cpuid[0].edx.to_ne_bytes(),
            raw_cpuid[0].ecx.to_ne_bytes(),
        ]
        .concat()
        .try_into()
        .unwrap();

        #[cfg(not(feature = "static"))]
        match &manufacturer_str {
            b"GenuineIntel" => Ok(Cpuid::Intel(IntelCpuid::from(raw_cpuid))),
            b"AuthenticAMD" => Ok(Cpuid::Amd(AmdCpuid::from(raw_cpuid))),
            _ => Err(CpuidNewError(FixedString(manufacturer_str))),
        }

        #[cfg(feature = "static")]
        match &manufacturer_str {
            b"GenuineIntel" => Ok(Cpuid::Intel(IntelCpuid::try_from(raw_cpuid)?)),
            b"AuthenticAMD" => Ok(Cpuid::Amd(AmdCpuid::from(raw_cpuid))),
            _ => Err(CpuidNewError::UnsupportedManufacturer(FixedString(
                manufacturer_str,
            ))),
        }
    }
}
// TODO Why doesn't this work?
// impl TryFrom<kvm_bindings::CpuId> for Self {
//     type Error = String;
//     fn try_from(kvm_cpuid: kvm_bindings::CpuId) -> Result<Self, Self::Error> {
//         let raw_cpuid = RawCpuid::from(kvm_cpuid);
//         Cpuid::try_from(raw_cpuid)
//     }
// }
impl From<Cpuid> for RawCpuid {
    fn from(cpuid: Cpuid) -> Self {
        match cpuid {
            Cpuid::Intel(intel_cpuid) => RawCpuid::from(intel_cpuid),
            Cpuid::Amd(amd_cpuid) => RawCpuid::from(amd_cpuid),
        }
    }
}
impl From<Cpuid> for kvm_bindings::CpuId {
    fn from(cpuid: Cpuid) -> Self {
        let raw_cpuid = RawCpuid::from(cpuid);
        Self::from(raw_cpuid)
    }
}
/// A string wrapper around a byte array.
#[derive(Clone, Eq, PartialEq)]
#[repr(C)]
pub struct FixedString<const N: usize>(pub [u8; N]);
impl From<u32> for FixedString<4> {
    fn from(x: u32) -> Self {
        Self(x.to_ne_bytes())
    }
}
impl<const N: usize> From<[u8; N]> for FixedString<N> {
    fn from(x: [u8; N]) -> Self {
        Self(x)
    }
}
impl<const N: usize> From<&[u8; N]> for FixedString<N> {
    fn from(x: &[u8; N]) -> Self {
        Self(*x)
    }
}
impl From<FixedString<4>> for u32 {
    fn from(string: FixedString<4>) -> u32 {
        u32::from_ne_bytes(string.0)
    }
}
impl From<(FixedString<4>, FixedString<4>, FixedString<4>)> for FixedString<12> {
    fn from((b, c, d): (FixedString<4>, FixedString<4>, FixedString<4>)) -> Self {
        let mut temp: [u8; 12] = [Default::default(); 12];
        temp[0] = b.0[0];
        temp[1] = b.0[1];
        temp[2] = b.0[2];
        temp[3] = b.0[3];
        temp[4] = d.0[0];
        temp[5] = d.0[1];
        temp[6] = d.0[2];
        temp[7] = d.0[3];
        temp[8] = c.0[0];
        temp[9] = c.0[1];
        temp[10] = c.0[2];
        temp[11] = c.0[3];
        FixedString(temp)
    }
}
impl<const N: usize> fmt::Debug for FixedString<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", str::from_utf8(&self.0).unwrap())
    }
}
impl<const N: usize> fmt::Display for FixedString<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", str::from_utf8(&self.0).unwrap())
    }
}
impl<const N: usize> Default for FixedString<N> {
    fn default() -> Self {
        Self([Default::default(); N])
    }
}
impl<const N: usize> Serialize for FixedString<N> {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        Serialize::serialize(
            str::from_utf8(&self.0)
                .map_err(|_| serde::ser::Error::custom("invalid utf8 manufacturer id"))?,
            ser,
        )
    }
}
impl<'a, const N: usize> Deserialize<'a> for FixedString<N> {
    fn deserialize<D: serde::Deserializer<'a>>(des: D) -> Result<Self, D::Error> {
        let base = <&str>::deserialize(des)?;
        let bytes = base
            .as_bytes()
            .try_into()
            .map_err(|_| serde::de::Error::custom("incorrectly sized manufacturer id"))?;
        Ok(FixedString(bytes))
    }
}

#[allow(clippy::shadow_unrelated)]
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn serialize() {
        let native_cpuid = unsafe { Cpuid::new().unwrap() };

        let serialized = serde_json::to_string_pretty(&native_cpuid).unwrap();
        let deserialized = serde_json::from_str(&serialized).unwrap();
        assert_eq!(native_cpuid, deserialized);

        let serialized = serde_json::to_vec(&native_cpuid).unwrap();
        let deserialized = serde_json::from_slice(&serialized).unwrap();
        assert_eq!(native_cpuid, deserialized);

        let serialized = bincode::serialize(&native_cpuid).unwrap();
        let deserialized = bincode::deserialize(&serialized).unwrap();
        assert_eq!(native_cpuid, deserialized);
    }
    #[test]
    fn kvm_native_compare() {
        // Get KVM CPUID
        // ---------------------------------------------------------------------------------------------
        let kvm_cpuid = Cpuid::kvm_get_supported_cpuid().unwrap();

        // Get native CPUID
        // ---------------------------------------------------------------------------------------------
        let native_cpuid = unsafe { Cpuid::new().unwrap() };

        // Test them against each other
        // ---------------------------------------------------------------------------------------------
        let (kvm_intel, native_intel) = match (kvm_cpuid, native_cpuid) {
            (Cpuid::Intel(a), Cpuid::Intel(b)) => (a, b),
            (Cpuid::Amd(_), Cpuid::Amd(_)) => return,
            _ => panic!("Non-matching native & kvm CPUID manufacturers"),
        };
        assert_eq!(native_intel.leaf_0, kvm_intel.leaf_0);
        assert_eq!(native_intel.leaf_1.eax, kvm_intel.leaf_1.eax);
        assert_eq!(native_intel.leaf_1.ebx, kvm_intel.leaf_1.ebx);
        assert!(native_intel.leaf_1.ecx.superset(&kvm_intel.leaf_1.ecx));
        assert!(native_intel.leaf_1.edx.superset(&kvm_intel.leaf_1.edx));

        assert_eq!(native_intel.leaf_2, kvm_intel.leaf_2);
        assert_eq!(native_intel.leaf_3, kvm_intel.leaf_3);

        // `kvm_intel` includes an invalid subleaf (EAX=0,EBX=0,ECX=0,EDX=0) at the end, while
        // `native_intel` does not.
        let n = kvm_intel.leaf_4.0.len() - 1;
        assert_eq!(native_intel.leaf_4.0.len(), n);
        assert_eq!(native_intel.leaf_4.0, kvm_intel.leaf_4.0[..n]);
        // Check for terminating leaf 4 with all zero registers
        assert_eq!(kvm_intel.leaf_4.0[n], intel::Leaf4Subleaf::default());

        // Check for terminating leaf 5 with all zero registers
        assert_eq!(kvm_intel.leaf_5, intel::Leaf5::default());
        assert!(matches!(
            native_intel.leaf_6.feature_cmp(&kvm_intel.leaf_6),
            Some(FeatureRelation::Superset) | Some(FeatureRelation::Equal)
        ));

        assert!(
            native_intel.leaf_7.0.eax.max_input_value_subleaf
                >= kvm_intel.leaf_7.0.eax.max_input_value_subleaf
        );
        assert!(native_intel.leaf_7.0.ebx.superset(&kvm_intel.leaf_7.0.ebx));
        // kvm may have the feature flag `UMIP` enabled at the same time as native having it
        // disabled TODO check superset excluding this flag
        assert!(native_intel.leaf_7.0.edx.superset(&kvm_intel.leaf_7.0.edx));

        assert_eq!(native_intel.leaf_9, kvm_intel.leaf_9);
        assert!(matches!(
            native_intel.leaf_a.feature_cmp(&kvm_intel.leaf_a),
            Some(FeatureRelation::Superset) | Some(FeatureRelation::Equal)
        ));

        // `kvm_intel` includes an invalid subleaf (EAX=0,EBX=0) at the end, while `native_intel`
        // does not.
        let n = kvm_intel.leaf_b.0.len() - 1;
        assert_eq!(native_intel.leaf_b.0.len(), n);
        assert_eq!(native_intel.leaf_b.0, kvm_intel.leaf_b.0[..n]);
        // TODO Check `kvm_intel.leaf_4.0[n]`

        assert!(native_intel.leaf_d.2.len() >= kvm_intel.leaf_d.2.len());
        assert!(matches!(
            native_intel.leaf_f.feature_cmp(&kvm_intel.leaf_f),
            Some(FeatureRelation::Superset) | Some(FeatureRelation::Equal)
        ));
        assert!(matches!(
            native_intel.leaf_10.feature_cmp(&kvm_intel.leaf_10),
            Some(FeatureRelation::Superset) | Some(FeatureRelation::Equal)
        ));
        assert!(matches!(
            native_intel.leaf_14.feature_cmp(&kvm_intel.leaf_14),
            Some(FeatureRelation::Superset) | Some(FeatureRelation::Equal)
        ));

        assert_eq!(native_intel.leaf_1f, kvm_intel.leaf_1f);
        assert_eq!(native_intel.leaf_20, kvm_intel.leaf_20);
        assert_eq!(native_intel.leaf_80000000, kvm_intel.leaf_80000000);
        assert_eq!(native_intel.leaf_80000001, kvm_intel.leaf_80000001);
        assert_eq!(native_intel.leaf_80000005, kvm_intel.leaf_80000005);
        assert_eq!(native_intel.leaf_80000006, kvm_intel.leaf_80000006);
        assert_eq!(native_intel.leaf_80000007, kvm_intel.leaf_80000007);
        assert!(matches!(
            native_intel
                .leaf_80000008
                .feature_cmp(&kvm_intel.leaf_80000008),
            Some(FeatureRelation::Superset) | Some(FeatureRelation::Equal)
        ));
    }
}
