// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(
    clippy::similar_names,
    clippy::module_name_repetitions,
    clippy::unreadable_literal,
    clippy::unsafe_derive_deserialize
)]

/// CPUID normalize implementation.
mod normalize;

pub use normalize::{DeterministicCacheError, NormalizeCpuidError};

use super::{CpuidEntry, CpuidKey, CpuidTrait, cpuid_insert};

/// A structure matching the Intel CPUID specification as described in
/// [Intel® 64 and IA-32 Architectures Software Developer's Manual Combined Volumes 2A, 2B, 2C, and 2D: Instruction Set Reference, A-Z](https://cdrdv2.intel.com/v1/dl/getContent/671110)
/// .
#[derive(Debug, Clone, PartialEq)]
pub struct IntelCpuid(pub kvm_bindings::CpuId);

impl Eq for IntelCpuid {}

impl IntelCpuid {
    /// Insert or update a CPUID entry.
    pub fn insert(&mut self, key: CpuidKey, entry: CpuidEntry) {
        cpuid_insert(&mut self.0, key, entry);
    }
}

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
