// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(
    clippy::similar_names,
    clippy::module_name_repetitions,
    clippy::unreadable_literal,
    clippy::unsafe_derive_deserialize
)]

#[cfg(cpuid)]
use std::convert::TryInto;

/// Leaf structs.
mod leaves;

/// Indexing implementations.
mod indexing;

/// CPUID normalize implementation.
#[cfg(cpuid)]
mod normalize;
#[cfg(cpuid)]
pub use normalize::{DeterministicCacheError, ExtendedTopologyError, NormalizeCpuidError};

/// Register bit fields.
mod registers;

use super::{CpuidEntry, CpuidKey, CpuidTrait, RawCpuid, RawKvmCpuidEntry};

/// A structure matching the Intel CPUID specification as described in
/// [Intel® 64 and IA-32 Architectures Software Developer's Manual Combined Volumes 2A, 2B, 2C, and 2D: Instruction Set Reference, A-Z](https://cdrdv2.intel.com/v1/dl/getContent/671110)
/// .
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct IntelCpuid(pub std::collections::BTreeMap<CpuidKey, CpuidEntry>);

impl CpuidTrait for IntelCpuid {
    /// Gets a given sub-leaf.
    #[inline]
    fn get(&self, key: &CpuidKey) -> Option<&CpuidEntry> {
        self.0.get(key)
    }

    /// Gets a given sub-leaf.
    #[inline]
    fn get_mut(&mut self, key: &CpuidKey) -> Option<&mut CpuidEntry> {
        self.0.get_mut(key)
    }
}

/// Error type for [`IntelCpuid::default_brand_string`].
#[cfg(cpuid)]
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum DefaultBrandStringError {
    /// Missing frequency.
    #[error("Missing frequency: {0:?}.")]
    Missingfrequency([u8; crate::BRAND_STRING_LENGTH]),
    /// Missing space.
    #[error("Missing space: {0:?}.")]
    MissingSpace([u8; crate::BRAND_STRING_LENGTH]),
    /// Insufficient space in brand string.
    #[error("Insufficient space in brand string.")]
    Overflow,
}

impl IntelCpuid {
    /// Gets the brand string always used for Intel.
    ///
    /// # Errors
    ///
    /// When unable to parse the host brand string.
    /// `brand_string.try_into().unwrap()` cannot panic as we know
    /// `brand_string.len() == BRAND_STRING_LENGTH`
    ///
    /// # Panics
    ///
    /// Never.
    // As we pass through host frequency, we require CPUID and thus `cfg(cpuid)`.
    // TODO: Use `split_array_ref`
    // (https://github.com/firecracker-microvm/firecracker/issues/3347)
    #[allow(
        clippy::indexing_slicing,
        clippy::integer_arithmetic,
        clippy::arithmetic_side_effects
    )]
    #[cfg(cpuid)]
    #[inline]
    pub fn default_brand_string(
    ) -> Result<[u8; super::BRAND_STRING_LENGTH], DefaultBrandStringError> {
        /// We always use this brand string.
        const DEFAULT_BRAND_STRING_BASE: &[u8] = b"Intel(R) Xeon(R) Processor @";

        // Get host brand string.
        // This will look like b"Intel(4) Xeon(R) Processor @ 3.00GHz".
        let host_brand_string: [u8; super::BRAND_STRING_LENGTH] = super::host_brand_string();

        // The slice of the host string before the frequency suffix
        // e.g. b"Intel(4) Xeon(R) Processor @ 3.00" and "GHz"
        let (before, after) = 'outer: {
            for i in 0..host_brand_string.len() {
                // Find position of b"THz" or b"GHz" or b"MHz"
                if let [b'T' | b'G' | b'M', b'H', b'z', ..] = host_brand_string[i..] {
                    break 'outer Ok(host_brand_string.split_at(i));
                }
            }
            Err(DefaultBrandStringError::Missingfrequency(host_brand_string))
        }?;

        // We iterate from the end until hitting a space, getting the frequency number
        // e.g. b"Intel(4) Xeon(R) Processor @ " and "3.00"
        let (_, frequency) = 'outer: {
            for i in (0..before.len()).rev() {
                if before[i] == b' ' {
                    break 'outer Ok(before.split_at(i));
                }
            }
            Err(DefaultBrandStringError::MissingSpace(host_brand_string))
        }?;

        // As `DEFAULT_BRAND_STRING_BASE.len() + frequency.len() + after.len()` is guaranteed
        // to be less than or equal to  `2*BRAND_STRING_LENGTH` and we know
        // `2*BRAND_STRING_LENGTH <= usize::MAX` since `BRAND_STRING_LENGTH==48`, this is always
        // safe.
        let len = DEFAULT_BRAND_STRING_BASE.len() + frequency.len() + after.len();

        let brand_string = DEFAULT_BRAND_STRING_BASE
            .iter()
            .copied()
            // Include frequency e.g. "3.00"
            .chain(frequency.iter().copied())
            // Include frequency suffix e.g. "GHz"
            .chain(after.iter().copied())
            // Pad with 0s to `BRAND_STRING_LENGTH`
            .chain(
                std::iter::repeat(b'\0').take(
                    super::BRAND_STRING_LENGTH
                        .checked_sub(len)
                        .ok_or(DefaultBrandStringError::Overflow)?,
                ),
            )
            .collect::<Vec<_>>();

        // SAFETY: Padding ensures `brand_string.len() == BRAND_STRING_LENGTH`.
        Ok(unsafe { brand_string.try_into().unwrap_unchecked() })
    }
}

impl From<RawCpuid> for IntelCpuid {
    #[inline]
    fn from(raw_cpuid: RawCpuid) -> Self {
        let map = raw_cpuid
            .iter()
            .cloned()
            .map(<(CpuidKey, CpuidEntry)>::from)
            .collect();
        Self(map)
    }
}

impl From<IntelCpuid> for RawCpuid {
    #[inline]
    fn from(intel_cpuid: IntelCpuid) -> Self {
        let entries = intel_cpuid
            .0
            .into_iter()
            .map(RawKvmCpuidEntry::from)
            .collect::<Vec<_>>();
        Self::from(entries)
    }
}
