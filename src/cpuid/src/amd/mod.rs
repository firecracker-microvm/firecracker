// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::similar_names, clippy::unreadable_literal)]

use super::{CpuidEntry, CpuidKey, CpuidTrait, RawCpuid, RawKvmCpuidEntry};

/// Indexing implementations.
mod indexing;

/// Leaf structs.
mod leaves;

/// CPUID normalize implementation.
#[cfg(cpuid)]
mod normalize;
#[cfg(cpuid)]
pub use normalize::{
    ExtendedApicIdError, ExtendedCacheTopologyError, FeatureEntryError, NormalizeCpuidError,
};

/// Register bit fields.
mod registers;

/// A structure matching the AMD CPUID specification as described in
/// [AMD64 Architecture Programmer’s Manual Volume 3: General-Purpose and System Instructions](https://www.amd.com/system/files/TechDocs/24594.pdf)
/// .
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AmdCpuid(pub std::collections::BTreeMap<CpuidKey, CpuidEntry>);

impl CpuidTrait for AmdCpuid {
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

impl From<RawCpuid> for AmdCpuid {
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

impl From<AmdCpuid> for RawCpuid {
    #[inline]
    fn from(amd_cpuid: AmdCpuid) -> Self {
        let entries = amd_cpuid
            .0
            .into_iter()
            .map(RawKvmCpuidEntry::from)
            .collect::<Vec<_>>();
        Self::from(entries)
    }
}
