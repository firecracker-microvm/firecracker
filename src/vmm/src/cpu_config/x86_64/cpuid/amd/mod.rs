// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::similar_names, clippy::unreadable_literal)]

use super::{CpuidEntry, CpuidKey, CpuidTrait, cpuid_insert};

/// CPUID normalize implementation.
mod normalize;

pub use normalize::{
    ExtendedApicIdError, ExtendedCacheTopologyError, FeatureEntryError, NormalizeCpuidError,
};

/// A structure matching the AMD CPUID specification as described in
/// [AMD64 Architecture Programmer's Manual Volume 3: General-Purpose and System Instructions](https://www.amd.com/system/files/TechDocs/24594.pdf)
/// .
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, PartialEq)]
pub struct AmdCpuid(pub kvm_bindings::CpuId);

impl Eq for AmdCpuid {}

impl AmdCpuid {
    /// Insert or update a CPUID entry.
    pub fn insert(&mut self, key: CpuidKey, entry: CpuidEntry) {
        cpuid_insert(&mut self.0, key, entry);
    }
}

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
