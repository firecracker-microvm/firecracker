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

use super::{CpuidEntry, CpuidKey, CpuidRegisters, CpuidTrait, KvmCpuidFlags};

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

impl From<kvm_bindings::CpuId> for IntelCpuid {
    #[inline]
    fn from(kvm_cpuid: kvm_bindings::CpuId) -> Self {
        let map = kvm_cpuid
            .as_slice()
            .iter()
            .map(|entry| {
                (
                    CpuidKey {
                        leaf: entry.function,
                        subleaf: entry.index,
                    },
                    CpuidEntry {
                        flags: KvmCpuidFlags(entry.flags),
                        result: CpuidRegisters {
                            eax: entry.eax,
                            ebx: entry.ebx,
                            ecx: entry.ecx,
                            edx: entry.edx,
                        },
                    },
                )
            })
            .collect();
        Self(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get() {
        let cpuid = IntelCpuid(std::collections::BTreeMap::new());
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
        let mut cpuid = IntelCpuid(std::collections::BTreeMap::new());
        assert_eq!(
            cpuid.get_mut(&CpuidKey {
                leaf: 0,
                subleaf: 0
            }),
            None
        );
    }
}
