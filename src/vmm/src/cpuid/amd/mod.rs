// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::similar_names, clippy::unreadable_literal)]

use super::{CpuidEntry, CpuidKey, CpuidTrait, RawCpuid, RawKvmCpuidEntry};

/// Indexing implementations.
mod indexing;

/// Leaf structs.
mod leaves;

/// CPUID normalize implementation.
mod normalize;

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

impl AmdCpuid {
    /// Include leaves from `other` that are not present in `self`.
    #[inline]
    #[must_use]
    pub fn include_leaves_from(mut self, other: Self) -> Self {
        let leaves = self
            .0
            .iter()
            .map(|x| x.0.leaf)
            .collect::<std::collections::HashSet<_>>();

        self.0
            .extend(other.0.into_iter().filter(|x| !leaves.contains(&x.0.leaf)));

        self
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

    #[allow(clippy::too_many_lines)]
    #[test]
    fn include_leaves_from() {
        let first = AmdCpuid(
            [
                (
                    CpuidKey {
                        leaf: 0,
                        subleaf: 0,
                    },
                    CpuidEntry::default(),
                ),
                (
                    CpuidKey {
                        leaf: 1,
                        subleaf: 0,
                    },
                    CpuidEntry::default(),
                ),
                (
                    CpuidKey {
                        leaf: 1,
                        subleaf: 1,
                    },
                    CpuidEntry::default(),
                ),
                (
                    CpuidKey {
                        leaf: 3,
                        subleaf: 0,
                    },
                    CpuidEntry::default(),
                ),
            ]
            .into_iter()
            .collect(),
        );
        let second = AmdCpuid(
            [
                (
                    CpuidKey {
                        leaf: 0,
                        subleaf: 0,
                    },
                    CpuidEntry::default(),
                ),
                (
                    CpuidKey {
                        leaf: 1,
                        subleaf: 0,
                    },
                    CpuidEntry::default(),
                ),
                (
                    CpuidKey {
                        leaf: 1,
                        subleaf: 2,
                    },
                    CpuidEntry::default(),
                ),
                (
                    CpuidKey {
                        leaf: 2,
                        subleaf: 1,
                    },
                    CpuidEntry::default(),
                ),
                (
                    CpuidKey {
                        leaf: 4,
                        subleaf: 0,
                    },
                    CpuidEntry::default(),
                ),
            ]
            .into_iter()
            .collect(),
        );
        let expected = AmdCpuid(
            [
                // First
                (
                    CpuidKey {
                        leaf: 0,
                        subleaf: 0,
                    },
                    CpuidEntry::default(),
                ),
                (
                    CpuidKey {
                        leaf: 1,
                        subleaf: 0,
                    },
                    CpuidEntry::default(),
                ),
                (
                    CpuidKey {
                        leaf: 1,
                        subleaf: 1,
                    },
                    CpuidEntry::default(),
                ),
                (
                    CpuidKey {
                        leaf: 3,
                        subleaf: 0,
                    },
                    CpuidEntry::default(),
                ),
                // Second
                (
                    CpuidKey {
                        leaf: 2,
                        subleaf: 1,
                    },
                    CpuidEntry::default(),
                ),
                (
                    CpuidKey {
                        leaf: 4,
                        subleaf: 0,
                    },
                    CpuidEntry::default(),
                ),
            ]
            .into_iter()
            .collect(),
        );

        assert_eq!(first.include_leaves_from(second), expected);
    }
}
