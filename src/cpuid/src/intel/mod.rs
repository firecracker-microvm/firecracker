// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(
    clippy::similar_names,
    clippy::module_name_repetitions,
    clippy::unreadable_literal,
    clippy::unsafe_derive_deserialize
)]

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

/// Supports implementations.
mod supports;
pub use supports::*;

use super::{CpuidEntry, CpuidKey, CpuidTrait, RawCpuid, RawKvmCpuidEntry, Supports};

/// Macro to log warnings on unchecked leaves when validating support.
macro_rules! warn_leaf_support {
    ($($x:literal),*) => {
        $(
            log::warn!("Could not validate support for Intel CPUID leaf {}.",$x);
        )*

    }
}

// -------------------------------------------------------------------------------------------------
// Intel cpuid structure
// -------------------------------------------------------------------------------------------------

/// A structure matching supporting the  Intel CPUID specification as described in
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

/// Error type for [`<IntelCpuidNotSupported as Supports>::supports`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum IntelCpuidNotSupported {
    /// MissingLeaf0.
    #[error("MissingLeaf0.")]
    MissingLeaf0,
    /// Leaf0.
    #[error("Leaf0: {0}")]
    Leaf0(super::Leaf0NotSupported),
    /// MissingLeaf1.
    #[error("MissingLeaf1.")]
    MissingLeaf1,
    /// Leaf1.
    #[error("Leaf1: {0}")]
    Leaf1(super::Leaf1NotSupported),
    /// MissingLeaf5.
    #[error("MissingLeaf5.")]
    MissingLeaf5,
    /// Leaf5.
    #[error("Leaf5: {0}")]
    Leaf5(Leaf5NotSupported),
    /// MissingLeaf6.
    #[error("MissingLeaf6.")]
    MissingLeaf6,
    /// Leaf6.
    #[error("Leaf6: {0}")]
    Leaf6(Leaf6NotSupported),
    /// Leaf7
    #[error("Leaf7: {0}")]
    Leaf7(Leaf7NotSupported),
    /// MissingLeafA.
    #[error("MissingLeafA.")]
    MissingLeafA,
    /// LeafA.
    #[error("LeafA: {0}")]
    LeafA(LeafANotSupported),
    /// LeafF.
    #[error("LeafF: {0}")]
    LeafF(LeafFNotSupported),
    /// Leaf10.
    #[error("Leaf10: {0}")]
    Leaf10(Leaf10NotSupported),
    /// Leaf14.
    #[error("Leaf14: {0}")]
    Leaf14(Leaf14NotSupported),
    /// Leaf18.
    #[error("Leaf18: {0}")]
    Leaf18(Leaf18NotSupported),
    /// MissingLeaf19.
    #[error("MissingLeaf19.")]
    MissingLeaf19,
    /// Leaf19.
    #[error("Leaf19: {0}")]
    Leaf19(Leaf19NotSupported),
    /// MissingLeaf1C.
    #[error("MissingLeaf1C.")]
    MissingLeaf1C,
    /// Leaf1C.
    #[error("Leaf1C: {0}")]
    Leaf1C(Leaf1CNotSupported),
    /// MissingLeaf20.
    #[error("MissingLeaf20.")]
    MissingLeaf20,
    /// Leaf20.
    #[error("Leaf20: {0}")]
    Leaf20(Leaf20NotSupported),
    /// MissingLeaf80000000.
    #[error("MissingLeaf80000000.")]
    MissingLeaf80000000,
    /// Leaf80000000.
    #[error("Leaf80000000: {0}")]
    Leaf80000000(Leaf80000000NotSupported),
    /// MissingLeaf80000001.
    #[error("MissingLeaf80000001.")]
    MissingLeaf80000001,
    /// Leaf80000001.
    #[error("Leaf80000001: {0}")]
    Leaf80000001(Leaf80000001NotSupported),
    /// MissingLeaf80000007.
    #[error("MissingLeaf80000007.")]
    MissingLeaf80000007,
    /// Leaf80000007
    #[error("Leaf80000007: {0}")]
    Leaf80000007(Leaf80000007NotSupported),
    /// MissingLeaf80000008.
    #[error("MissingLeaf80000008.")]
    MissingLeaf80000008,
    /// Leaf80000008.
    #[error("Leaf80000008: {0}")]
    Leaf80000008(Leaf80000008NotSupported),
}

impl Supports for IntelCpuid {
    type Error = IntelCpuidNotSupported;

    /// Checks if `self` is a able to support `other`.
    ///
    /// Checks if a process from an environment with CPUID `other` could be continued in an
    /// environment with the CPUID `self`.
    #[inline]
    fn supports(&self, other: &Self) -> Result<(), Self::Error> {
        match (self.leaf::<0x00>(), other.leaf::<0x00>()) {
            (_, None) => (),
            (None, Some(_)) => return Err(IntelCpuidNotSupported::MissingLeaf0),
            (Some(a), Some(b)) => a.supports(b).map_err(IntelCpuidNotSupported::Leaf0)?,
        }
        match (self.leaf::<0x01>(), other.leaf::<0x01>()) {
            (_, None) => (),
            (None, Some(_)) => return Err(IntelCpuidNotSupported::MissingLeaf1),
            (Some(a), Some(b)) => a.supports(b).map_err(IntelCpuidNotSupported::Leaf1)?,
        }
        match (self.leaf::<0x05>(), other.leaf::<0x05>()) {
            (_, None) => (),
            (None, Some(_)) => return Err(IntelCpuidNotSupported::MissingLeaf5),
            (Some(a), Some(b)) => a.supports(b).map_err(IntelCpuidNotSupported::Leaf5)?,
        }
        match (self.leaf::<0x06>(), other.leaf::<0x06>()) {
            (_, None) => (),
            (None, Some(_)) => return Err(IntelCpuidNotSupported::MissingLeaf6),
            (Some(a), Some(b)) => a.supports(b).map_err(IntelCpuidNotSupported::Leaf6)?,
        }
        self.leaf::<0x7>()
            .supports(&other.leaf::<0x7>())
            .map_err(IntelCpuidNotSupported::Leaf7)?;

        match (self.leaf::<0x0A>(), other.leaf::<0x0A>()) {
            (_, None) => (),
            (None, Some(_)) => return Err(IntelCpuidNotSupported::MissingLeafA),
            (Some(a), Some(b)) => a.supports(b).map_err(IntelCpuidNotSupported::LeafA)?,
        }

        self.leaf::<0x0F>()
            .supports(&other.leaf::<0x0F>())
            .map_err(IntelCpuidNotSupported::LeafF)?;

        self.leaf::<0x10>()
            .supports(&other.leaf::<0x10>())
            .map_err(IntelCpuidNotSupported::Leaf10)?;

        self.leaf::<0x14>()
            .supports(&other.leaf::<0x14>())
            .map_err(IntelCpuidNotSupported::Leaf14)?;

        self.leaf::<0x18>()
            .supports(&other.leaf::<0x18>())
            .map_err(IntelCpuidNotSupported::Leaf18)?;

        match (self.leaf::<0x19>(), other.leaf::<0x19>()) {
            (_, None) => (),
            (None, Some(_)) => return Err(IntelCpuidNotSupported::MissingLeaf19),
            (Some(a), Some(b)) => a.supports(b).map_err(IntelCpuidNotSupported::Leaf19)?,
        }
        match (self.leaf::<0x1C>(), other.leaf::<0x1C>()) {
            (_, None) => (),
            (None, Some(_)) => return Err(IntelCpuidNotSupported::MissingLeaf1C),
            (Some(a), Some(b)) => a.supports(b).map_err(IntelCpuidNotSupported::Leaf1C)?,
        }
        match (self.leaf::<0x20>(), other.leaf::<0x20>()) {
            (_, None) => (),
            (None, Some(_)) => return Err(IntelCpuidNotSupported::MissingLeaf20),
            (Some(a), Some(b)) => a.supports(b).map_err(IntelCpuidNotSupported::Leaf20)?,
        }
        match (self.leaf::<0x80000000>(), other.leaf::<0x80000000>()) {
            (_, None) => (),
            (None, Some(_)) => return Err(IntelCpuidNotSupported::MissingLeaf80000000),
            (Some(a), Some(b)) => a
                .supports(b)
                .map_err(IntelCpuidNotSupported::Leaf80000000)?,
        }
        match (self.leaf::<0x80000001>(), other.leaf::<0x80000001>()) {
            (_, None) => (),
            (None, Some(_)) => return Err(IntelCpuidNotSupported::MissingLeaf80000001),
            (Some(a), Some(b)) => a
                .supports(b)
                .map_err(IntelCpuidNotSupported::Leaf80000001)?,
        }
        match (self.leaf::<0x80000007>(), other.leaf::<0x80000007>()) {
            (_, None) => (),
            (None, Some(_)) => return Err(IntelCpuidNotSupported::MissingLeaf80000007),
            (Some(a), Some(b)) => a
                .supports(b)
                .map_err(IntelCpuidNotSupported::Leaf80000007)?,
        }
        match (self.leaf::<0x80000008>(), other.leaf::<0x80000008>()) {
            (_, None) => (),
            (None, Some(_)) => return Err(IntelCpuidNotSupported::MissingLeaf80000008),
            (Some(a), Some(b)) => a
                .supports(b)
                .map_err(IntelCpuidNotSupported::Leaf80000008)?,
        }

        #[rustfmt::skip]
        warn_leaf_support!(
            0x2u64,0x3u64,0x4u64,0x9u64,0xBu64,0xDu64,0x12u64,0x15u64,0x16u64,0x17u64,
            0x18u64,0x1Au64,0x1Bu64,0x1Fu64,0x80000002u64,0x80000003u64,0x80000004u64,
            0x80000005u64,0x80000006u64
        );

        Ok(())
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
