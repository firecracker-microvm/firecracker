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

pub use normalize::{DeterministicCacheError, ExtendedTopologyError, NormalizeCpuidError};

use super::{CpuidEntry, CpuidKey, CpuidTrait, RawCpuid, RawKvmCpuidEntry};

/// A structure matching the Intel CPUID specification as described in
/// [Intel® 64 and IA-32 Architectures Software Developer's Manual Combined Volumes 2A, 2B, 2C, and 2D: Instruction Set Reference, A-Z](https://cdrdv2.intel.com/v1/dl/getContent/671110)
/// .
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct IntelCpuid(pub std::collections::BTreeMap<CpuidKey, CpuidEntry>);

impl IntelCpuid {
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

    #[allow(clippy::too_many_lines)]
    #[test]
    fn include_leaves_from() {
        let first = IntelCpuid(
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
        let second = IntelCpuid(
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
        let expected = IntelCpuid(
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
