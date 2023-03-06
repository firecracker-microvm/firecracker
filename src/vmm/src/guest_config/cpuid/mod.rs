// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

#![warn(clippy::pedantic, clippy::restriction)]
#![allow(
    clippy::blanket_clippy_restriction_lints,
    clippy::implicit_return,
    clippy::pattern_type_mismatch,
    clippy::std_instead_of_alloc,
    clippy::std_instead_of_core,
    clippy::pub_use,
    clippy::non_ascii_literal,
    clippy::single_char_lifetime_names,
    clippy::exhaustive_enums,
    clippy::exhaustive_structs,
    clippy::unseparated_literal_suffix,
    clippy::mod_module_files,
    clippy::missing_trait_methods
)]
// Apply CPUID specific lint adjustments.
#![allow(
    clippy::unsafe_derive_deserialize,
    clippy::unreadable_literal,
    clippy::similar_names,
    clippy::same_name_method,
    clippy::doc_markdown,
    clippy::module_name_repetitions
)]

//! Utility for configuring the CPUID (CPU identification) for the guest microVM.

use std::convert::TryFrom;
use std::mem::{size_of, transmute};

/// cpuid utility functions.
pub mod common;

/// Raw CPUID specification handling.
pub(crate) mod cpuid_ffi;
pub use cpuid_ffi::*;

/// AMD CPUID specification handling.
pub mod amd;
pub use amd::AmdCpuid;

/// Intel CPUID specification handling.
pub mod intel;
pub use intel::IntelCpuid;

/// Indexing implementations (shared between AMD and Intel).
mod indexing;
pub(crate) use indexing::index_leaf;
pub use indexing::{IndexLeaf, IndexLeafMut};

/// Leaf structs (shared between AMD and Intel).
mod leaves;
pub use leaves::Leaf;

/// CPUID normalize implementation.
mod normalize;

pub use normalize::{FeatureInformationError, GetMaxCpusPerPackageError, NormalizeCpuidError};

/// Register bit fields (shared between AMD and Intel).
mod registers;

/// Intel brand string.
pub const VENDOR_ID_INTEL: &[u8; 12] = b"GenuineIntel";

/// AMD brand string.
pub const VENDOR_ID_AMD: &[u8; 12] = b"AuthenticAMD";

/// Intel brand string.
#[allow(clippy::undocumented_unsafe_blocks)]
pub const VENDOR_ID_INTEL_STR: &str = unsafe { std::str::from_utf8_unchecked(VENDOR_ID_INTEL) };

/// AMD brand string.
#[allow(clippy::undocumented_unsafe_blocks)]
pub const VENDOR_ID_AMD_STR: &str = unsafe { std::str::from_utf8_unchecked(VENDOR_ID_AMD) };

/// To store the brand string we have 3 leaves, each with 4 registers, each with 4 bytes.
pub const BRAND_STRING_LENGTH: usize = 3 * 4 * 4;

/// Mimic of [`std::arch::x86_64::__cpuid`] that wraps [`cpuid_count`].
fn cpuid(leaf: u32) -> std::arch::x86_64::CpuidResult {
    cpuid_count(leaf, 0)
}

/// Safe wrapper around [`std::arch::x86_64::__cpuid_count`].
fn cpuid_count(leaf: u32, subleaf: u32) -> std::arch::x86_64::CpuidResult {
    // JUSTIFICATION: There is no safe alternative.
    // SAFETY: The `cfg(cpuid)` wrapping the `cpuid` module guarantees `CPUID` is supported.
    unsafe { std::arch::x86_64::__cpuid_count(leaf, subleaf) }
}

/// Gets the Intel default brand.
// As we pass through host frequency, we require CPUID and thus `cfg(cpuid)`.
/// Gets host brand string.
///
/// Its stored in-order with bytes flipped in each register e.g.:
/// ```text
/// "etnI" | ")4(l" | "oeX " | ")R(n" |
/// "orP " | "ssec" | "@ ro" | "0.3 " |
/// "zHG0" | null | null | null
/// ------------------------------------
/// Intel(R) Xeon(R) Processor @ 3.00Ghz
/// ```
#[inline]
#[must_use]
pub fn host_brand_string() -> [u8; BRAND_STRING_LENGTH] {
    let leaf_a = cpuid(0x80000002);
    let leaf_b = cpuid(0x80000003);
    let leaf_c = cpuid(0x80000004);

    let arr = [
        leaf_a.eax, leaf_a.ebx, leaf_a.ecx, leaf_a.edx, leaf_b.eax, leaf_b.ebx, leaf_b.ecx,
        leaf_b.edx, leaf_c.eax, leaf_c.ebx, leaf_c.ecx, leaf_c.edx,
    ];

    // JUSTIFICATION: There is no safe alternative.
    // SAFETY: Transmuting `[u32;12]` to `[u8;BRAND_STRING_LENGTH]` (`[u8;48]`) is always safe.
    unsafe { std::mem::transmute(arr) }
}

/// Trait defining shared behaviour between CPUID structures.
pub trait CpuidTrait {
    /// Returns the CPUID manufacturers ID (e.g. `GenuineIntel` or `AuthenticAMD`) or `None` if it
    /// cannot be found in CPUID (e.g. leaf 0x0 is missing).
    #[inline]
    #[must_use]
    fn vendor_id(&self) -> Option<[u8; 12]> {
        let leaf_0 = self.get(&CpuidKey::leaf(0x0))?;

        // The ordering of the vendor string is ebx,edx,ecx this is not a mistake.
        let (ebx, edx, ecx) = (
            leaf_0.result.ebx.to_ne_bytes(),
            leaf_0.result.edx.to_ne_bytes(),
            leaf_0.result.ecx.to_ne_bytes(),
        );
        let arr: [u8; 12] = [
            ebx[0], ebx[1], ebx[2], ebx[3], edx[0], edx[1], edx[2], edx[3], ecx[0], ecx[1], ecx[2],
            ecx[3],
        ];
        Some(arr)
    }

    /// Get immutable reference to leaf.
    #[inline]
    #[must_use]
    fn leaf<const N: usize>(&self) -> <Self as IndexLeaf<N>>::Output<'_>
    where
        Self: IndexLeaf<N>,
    {
        <Self as IndexLeaf<N>>::index_leaf(self)
    }

    /// Get mutable reference to leaf.
    #[inline]
    #[must_use]
    fn leaf_mut<const N: usize>(&mut self) -> <Self as IndexLeafMut<N>>::Output<'_>
    where
        Self: IndexLeafMut<N>,
    {
        <Self as IndexLeafMut<N>>::index_leaf_mut(self)
    }

    /// Gets a given sub-leaf.
    fn get(&self, key: &CpuidKey) -> Option<&CpuidEntry>;

    /// Gets a given sub-leaf.
    fn get_mut(&mut self, key: &CpuidKey) -> Option<&mut CpuidEntry>;

    /// Applies a given brand string to CPUID.
    ///
    /// # Errors
    ///
    /// When any of the leaves 0x80000002, 0x80000003 or 0x80000004 are not present.
    #[inline]
    fn apply_brand_string(
        &mut self,
        brand_string: &[u8; BRAND_STRING_LENGTH],
    ) -> Result<(), MissingBrandStringLeaves> {
        // 0x80000002
        {
            let leaf: &mut CpuidEntry = self
                .get_mut(&CpuidKey::leaf(0x80000002))
                .ok_or(MissingBrandStringLeaves)?;
            leaf.result.eax = u32::from_ne_bytes([
                brand_string[0],
                brand_string[1],
                brand_string[2],
                brand_string[3],
            ]);
            leaf.result.ebx = u32::from_ne_bytes([
                brand_string[4],
                brand_string[5],
                brand_string[6],
                brand_string[7],
            ]);
            leaf.result.ecx = u32::from_ne_bytes([
                brand_string[8],
                brand_string[9],
                brand_string[10],
                brand_string[11],
            ]);
            leaf.result.edx = u32::from_ne_bytes([
                brand_string[12],
                brand_string[13],
                brand_string[14],
                brand_string[15],
            ]);
        }

        // 0x80000003
        {
            let leaf: &mut CpuidEntry = self
                .get_mut(&CpuidKey::leaf(0x80000003))
                .ok_or(MissingBrandStringLeaves)?;
            leaf.result.eax = u32::from_ne_bytes([
                brand_string[16],
                brand_string[17],
                brand_string[18],
                brand_string[19],
            ]);
            leaf.result.ebx = u32::from_ne_bytes([
                brand_string[20],
                brand_string[21],
                brand_string[22],
                brand_string[23],
            ]);
            leaf.result.ecx = u32::from_ne_bytes([
                brand_string[24],
                brand_string[25],
                brand_string[26],
                brand_string[27],
            ]);
            leaf.result.edx = u32::from_ne_bytes([
                brand_string[28],
                brand_string[29],
                brand_string[30],
                brand_string[31],
            ]);
        }

        // 0x80000004
        {
            let leaf: &mut CpuidEntry = self
                .get_mut(&CpuidKey::leaf(0x80000004))
                .ok_or(MissingBrandStringLeaves)?;
            leaf.result.eax = u32::from_ne_bytes([
                brand_string[32],
                brand_string[33],
                brand_string[34],
                brand_string[35],
            ]);
            leaf.result.ebx = u32::from_ne_bytes([
                brand_string[36],
                brand_string[37],
                brand_string[38],
                brand_string[39],
            ]);
            leaf.result.ecx = u32::from_ne_bytes([
                brand_string[40],
                brand_string[41],
                brand_string[42],
                brand_string[43],
            ]);
            leaf.result.edx = u32::from_ne_bytes([
                brand_string[44],
                brand_string[45],
                brand_string[46],
                brand_string[47],
            ]);
        }

        Ok(())
    }
}

impl CpuidTrait for kvm_bindings::CpuId {
    /// Gets a given sub-leaf.
    #[allow(clippy::transmute_ptr_to_ptr, clippy::unwrap_used)]
    #[inline]
    fn get(&self, CpuidKey { leaf, subleaf }: &CpuidKey) -> Option<&CpuidEntry> {
        let entry_opt = self
            .as_slice()
            .iter()
            .find(|entry| entry.function == *leaf && entry.index == *subleaf);

        entry_opt.map(|entry| {
            // JUSTIFICATION: There is no safe alternative.
            // SAFETY: The `kvm_cpuid_entry2` and `CpuidEntry` are `repr(C)` with known sizes.
            unsafe {
                let arr: &[u8; size_of::<kvm_bindings::kvm_cpuid_entry2>()] = transmute(entry);
                let arr2: &[u8; size_of::<CpuidEntry>()] = arr[8..28].try_into().unwrap();
                transmute::<_, &CpuidEntry>(arr2)
            }
        })
    }

    /// Gets a given sub-leaf.
    #[allow(clippy::transmute_ptr_to_ptr, clippy::unwrap_used)]
    #[inline]
    fn get_mut(&mut self, CpuidKey { leaf, subleaf }: &CpuidKey) -> Option<&mut CpuidEntry> {
        let entry_opt = self
            .as_mut_slice()
            .iter_mut()
            .find(|entry| entry.function == *leaf && entry.index == *subleaf);
        entry_opt.map(|entry| {
            // JUSTIFICATION: There is no safe alternative.
            // SAFETY: The `kvm_cpuid_entry2` and `CpuidEntry` are `repr(C)` with known sizes.
            unsafe {
                let arr: &mut [u8; size_of::<kvm_bindings::kvm_cpuid_entry2>()] = transmute(entry);
                let arr2: &mut [u8; size_of::<CpuidEntry>()] =
                    (&mut arr[8..28]).try_into().unwrap();
                transmute::<_, &mut CpuidEntry>(arr2)
            }
        })
    }
}

/// Error type for [`apply_brand_string`].
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
#[error("Missing brand string leaves 0x80000002, 0x80000003 and 0x80000004.")]
pub struct MissingBrandStringLeaves;

/// Error type for [`Cpuid::kvm_get_supported_cpuid`].
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum KvmGetSupportedCpuidError {
    /// Could not access KVM.
    #[error("Could not access KVM: {0}")]
    KvmAccess(#[from] utils::errno::Error),
}

/// Error type for [`<Cpuid as TryFrom<RawCpuid>>::try_from`].
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum CpuidTryFromRawCpuid {
    /// Leaf 0 not found in the given `RawCpuid`..
    #[error("Leaf 0 not found in the given `RawCpuid`.")]
    MissingLeaf0,
    /// Unsupported CPUID manufacturer id.
    #[error(
        "Unsupported CPUID manufacturer id: \"{0:?}\" (only 'GenuineIntel' and 'AuthenticAMD' are \
         supported)."
    )]
    UnsupportedVendor([u8; 12]),
}

/// CPUID information
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cpuid {
    /// Intel CPUID specific information.
    Intel(IntelCpuid),
    /// AMD CPUID specific information.
    Amd(AmdCpuid),
}

/// Error type for [`Cpuid::join`].
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
#[error("Failed to join CPUIDs as they belong to different manufactures.")]
pub struct CpuidJoinError;

impl Cpuid {
    /// Returns `Some(&mut IntelCpuid)` if `Self == Self::Intel(_)` else returns `None`.
    #[inline]
    #[must_use]
    pub fn intel_mut(&mut self) -> Option<&mut IntelCpuid> {
        match self {
            Self::Intel(intel) => Some(intel),
            Self::Amd(_) => None,
        }
    }

    /// Returns `Some(&IntelCpuid)` if `Self == Self::Intel(_)` else returns `None`.
    #[inline]
    #[must_use]
    pub fn intel(&self) -> Option<&IntelCpuid> {
        match self {
            Self::Intel(intel) => Some(intel),
            Self::Amd(_) => None,
        }
    }

    /// Returns `Some(&AmdCpuid)` if `Self == Self::Amd(_)` else returns `None`.
    #[inline]
    #[must_use]
    pub fn amd(&self) -> Option<&AmdCpuid> {
        match self {
            Self::Intel(_) => None,
            Self::Amd(amd) => Some(amd),
        }
    }

    /// Returns `Some(&mut AmdCpuid)` if `Self == Self::Amd(_)` else returns `None`.
    #[inline]
    #[must_use]
    pub fn amd_mut(&mut self) -> Option<&mut AmdCpuid> {
        match self {
            Self::Intel(_) => None,
            Self::Amd(amd) => Some(amd),
        }
    }

    /// Include leaves from `other` that are not present in `self`.
    ///
    /// # Errors
    ///
    /// When CPUIDs have different manufacturer IDs.
    #[inline]
    pub fn include_leaves_from(self, other: Self) -> Result<Self, CpuidJoinError> {
        match (self, other) {
            (Self::Intel(a), Self::Intel(b)) => Ok(Self::Intel(a.include_leaves_from(b))),
            (Self::Amd(a), Self::Amd(b)) => Ok(Self::Amd(a.include_leaves_from(b))),
            _ => Err(CpuidJoinError),
        }
    }
}

impl CpuidTrait for Cpuid {
    /// Gets a given sub-leaf.
    #[inline]
    fn get(&self, key: &CpuidKey) -> Option<&CpuidEntry> {
        match self {
            Self::Intel(intel_cpuid) => intel_cpuid.get(key),
            Self::Amd(amd_cpuid) => amd_cpuid.get(key),
        }
    }

    /// Gets a given sub-leaf.
    #[inline]
    fn get_mut(&mut self, key: &CpuidKey) -> Option<&mut CpuidEntry> {
        match self {
            Self::Intel(intel_cpuid) => intel_cpuid.get_mut(key),
            Self::Amd(amd_cpuid) => amd_cpuid.get_mut(key),
        }
    }
}

impl TryFrom<RawCpuid> for Cpuid {
    type Error = CpuidTryFromRawCpuid;

    #[inline]
    fn try_from(raw_cpuid: RawCpuid) -> Result<Self, Self::Error> {
        let vendor_id = raw_cpuid
            .vendor_id()
            .ok_or(CpuidTryFromRawCpuid::MissingLeaf0)?;

        match std::str::from_utf8(&vendor_id) {
            Ok(VENDOR_ID_INTEL_STR) => Ok(Cpuid::Intel(IntelCpuid::from(raw_cpuid))),
            Ok(VENDOR_ID_AMD_STR) => Ok(Cpuid::Amd(AmdCpuid::from(raw_cpuid))),
            _ => Err(CpuidTryFromRawCpuid::UnsupportedVendor(vendor_id)),
        }
    }
}

impl From<Cpuid> for RawCpuid {
    #[inline]
    fn from(cpuid: Cpuid) -> Self {
        match cpuid {
            Cpuid::Intel(intel_cpuid) => RawCpuid::from(intel_cpuid),
            Cpuid::Amd(amd_cpuid) => RawCpuid::from(amd_cpuid),
        }
    }
}

impl From<Cpuid> for kvm_bindings::CpuId {
    #[inline]
    fn from(cpuid: Cpuid) -> Self {
        let raw_cpuid = RawCpuid::from(cpuid);
        Self::from(raw_cpuid)
    }
}

/// CPUID index values `leaf` and `subleaf`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CpuidKey {
    /// CPUID leaf.
    pub leaf: u32,
    /// CPUID subleaf.
    pub subleaf: u32,
}

impl CpuidKey {
    /// `CpuidKey { leaf, subleaf: 0 }`
    #[inline]
    #[must_use]
    pub fn leaf(leaf: u32) -> Self {
        Self { leaf, subleaf: 0 }
    }

    /// `CpuidKey { leaf, subleaf }`
    #[inline]
    #[must_use]
    pub fn subleaf(leaf: u32, subleaf: u32) -> Self {
        Self { leaf, subleaf }
    }
}

impl std::cmp::PartialOrd for CpuidKey {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(
            self.leaf
                .cmp(&other.leaf)
                .then(self.subleaf.cmp(&other.subleaf)),
        )
    }
}

impl std::cmp::Ord for CpuidKey {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.leaf
            .cmp(&other.leaf)
            .then(self.subleaf.cmp(&other.subleaf))
    }
}

/// CPUID entry information stored for each leaf of [`IntelCpuid`].
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CpuidEntry {
    /// The KVM requires a `flags` parameter which indicates if a given CPUID leaf has sub-leaves.
    /// This does not change at runtime so we can save memory by not storing this under every
    /// sub-leaf and instead fetching from a map when converting back to the KVM CPUID
    /// structure. But for robustness we currently do store we do not use this approach.
    ///
    /// A map on flags would look like:
    /// ```ignore
    /// use cpuid::KvmCpuidFlags;
    /// #[allow(clippy::non_ascii_literal)]
    /// pub static KVM_CPUID_LEAF_FLAGS: phf::Map<u32, KvmCpuidFlags> = phf::phf_map! {
    ///     0x00u32 => KvmCpuidFlags::empty(),
    ///     0x01u32 => KvmCpuidFlags::empty(),
    ///     0x02u32 => KvmCpuidFlags::empty(),
    ///     0x03u32 => KvmCpuidFlags::empty(),
    ///     0x04u32 => KvmCpuidFlags::SIGNIFICANT_INDEX,
    ///     0x05u32 => KvmCpuidFlags::empty(),
    ///     0x06u32 => KvmCpuidFlags::empty(),
    ///     0x07u32 => KvmCpuidFlags::SIGNIFICANT_INDEX,
    ///     0x09u32 => KvmCpuidFlags::empty(),
    ///     0x0Au32 => KvmCpuidFlags::empty(),
    ///     0x0Bu32 => KvmCpuidFlags::SIGNIFICANT_INDEX,
    ///     0x0Fu32 => KvmCpuidFlags::SIGNIFICANT_INDEX,
    ///     0x10u32 => KvmCpuidFlags::SIGNIFICANT_INDEX,
    ///     0x12u32 => KvmCpuidFlags::SIGNIFICANT_INDEX,
    ///     0x14u32 => KvmCpuidFlags::SIGNIFICANT_INDEX,
    ///     0x15u32 => KvmCpuidFlags::empty(),
    ///     0x16u32 => KvmCpuidFlags::empty(),
    ///     0x17u32 => KvmCpuidFlags::SIGNIFICANT_INDEX,
    ///     0x18u32 => KvmCpuidFlags::SIGNIFICANT_INDEX,
    ///     0x19u32 => KvmCpuidFlags::empty(),
    ///     0x1Au32 => KvmCpuidFlags::empty(),
    ///     0x1Bu32 => KvmCpuidFlags::empty(),
    ///     0x1Cu32 => KvmCpuidFlags::empty(),
    ///     0x1Fu32 => KvmCpuidFlags::SIGNIFICANT_INDEX,
    ///     0x20u32 => KvmCpuidFlags::empty(),
    ///     0x80000000u32 => KvmCpuidFlags::empty(),
    ///     0x80000001u32 => KvmCpuidFlags::empty(),
    ///     0x80000002u32 => KvmCpuidFlags::empty(),
    ///     0x80000003u32 => KvmCpuidFlags::empty(),
    ///     0x80000004u32 => KvmCpuidFlags::empty(),
    ///     0x80000005u32 => KvmCpuidFlags::empty(),
    ///     0x80000006u32 => KvmCpuidFlags::empty(),
    ///     0x80000007u32 => KvmCpuidFlags::empty(),
    ///     0x80000008u32 => KvmCpuidFlags::empty(),
    /// };
    /// ```
    pub flags: crate::guest_config::cpuid::cpuid_ffi::KvmCpuidFlags,
    /// Register values.
    pub result: CpuidRegisters,
}

/// To transmute this into leaves such that we can return mutable reference to it with leaf specific
/// accessors, requires this to have a consistent member ordering. [`core::arch::x86::CpuidResult`]
/// is not `repr(C)`.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(C)]
pub struct CpuidRegisters {
    /// EAX
    pub eax: u32,
    /// EBX
    pub ebx: u32,
    /// ECX
    pub ecx: u32,
    /// EDX
    pub edx: u32,
}

impl From<core::arch::x86_64::CpuidResult> for CpuidRegisters {
    #[inline]
    fn from(
        core::arch::x86_64::CpuidResult { eax, ebx, ecx, edx }: core::arch::x86_64::CpuidResult,
    ) -> Self {
        Self { eax, ebx, ecx, edx }
    }
}

impl From<(CpuidKey, CpuidEntry)> for RawKvmCpuidEntry {
    #[inline]
    fn from(
        (CpuidKey { leaf, subleaf }, CpuidEntry { flags, result }): (CpuidKey, CpuidEntry),
    ) -> Self {
        let CpuidRegisters { eax, ebx, ecx, edx } = result;
        Self {
            function: leaf,
            index: subleaf,
            flags,
            eax,
            ebx,
            ecx,
            edx,
            padding: Padding::default(),
        }
    }
}

impl From<RawKvmCpuidEntry> for (CpuidKey, CpuidEntry) {
    #[inline]
    fn from(
        RawKvmCpuidEntry {
            function,
            index,
            flags,
            eax,
            ebx,
            ecx,
            edx,
            ..
        }: RawKvmCpuidEntry,
    ) -> Self {
        (
            CpuidKey {
                leaf: function,
                subleaf: index,
            },
            CpuidEntry {
                flags,
                result: CpuidRegisters { eax, ebx, ecx, edx },
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn include_leaves_from() {
        let first = Cpuid::Amd(AmdCpuid(BTreeMap::new()));
        let second = Cpuid::Intel(IntelCpuid(BTreeMap::new()));

        assert_eq!(
            first.clone().include_leaves_from(second.clone()),
            Err(CpuidJoinError)
        );
        assert_eq!(second.include_leaves_from(first), Err(CpuidJoinError));
    }

    #[test]
    fn get() {
        let cpuid = Cpuid::Intel(IntelCpuid(std::collections::BTreeMap::new()));
        assert_eq!(
            cpuid.get(&CpuidKey {
                leaf: 0,
                subleaf: 0
            }),
            None
        );
    }

    #[test]
    fn get_mut() {
        let mut cpuid = Cpuid::Intel(IntelCpuid(std::collections::BTreeMap::new()));
        assert_eq!(
            cpuid.get_mut(&CpuidKey {
                leaf: 0,
                subleaf: 0
            }),
            None
        );
    }
}
