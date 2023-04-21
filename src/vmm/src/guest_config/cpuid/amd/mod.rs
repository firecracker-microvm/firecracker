// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::similar_names, clippy::unreadable_literal)]

use super::{CpuidEntry, CpuidKey, CpuidRegisters, CpuidTrait, KvmCpuidFlags};

/// CPUID normalize implementation.
mod normalize;

pub use normalize::{
    ExtendedApicIdError, ExtendedCacheTopologyError, FeatureEntryError, NormalizeCpuidError,
};

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

impl From<kvm_bindings::CpuId> for AmdCpuid {
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
        let cpuid = AmdCpuid(std::collections::BTreeMap::new());
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
        let mut cpuid = AmdCpuid(std::collections::BTreeMap::new());
        assert_eq!(
            cpuid.get_mut(&CpuidKey {
                leaf: 0,
                subleaf: 0
            }),
            None
        );
    }
}
