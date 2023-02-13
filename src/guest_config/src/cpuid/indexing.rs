// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::transmute_ptr_to_ptr, clippy::needless_lifetimes)]

#[allow(clippy::wildcard_imports)]
use super::leaves::*;

/// Indexes leaf.
#[must_use]
pub trait IndexLeaf<const INDEX: usize> {
    /// Leaf type.
    type Output<'a>
    where
        Self: 'a;
    /// Gets immutable reference to leaf.
    fn index_leaf<'a>(&'a self) -> Self::Output<'a>;
}
/// Indexes leaf.
#[must_use]
pub trait IndexLeafMut<const INDEX: usize> {
    /// Leaf type.
    type Output<'a>
    where
        Self: 'a;
    /// Gets mutable reference to leaf.
    fn index_leaf_mut<'a>(&'a mut self) -> Self::Output<'a>;
}

/// Transmutes `Vec<T>` into `Vec<U>` where `size::<T>() == size::<U>()`.
/// # Safety
///
/// Unsafe due to raw casting between types T and U.
/// Make sure sizes and memory alignments of T and U are equal.
#[inline]
#[must_use]
pub unsafe fn transmute_vec<T, U>(from: Vec<T>) -> Vec<U> {
    let mut intermediate = std::mem::ManuallyDrop::new(from);
    Vec::from_raw_parts(
        intermediate.as_mut_ptr().cast(),
        intermediate.len(),
        intermediate.capacity(),
    )
}

/// Convenience macro for indexing leaves.
#[macro_export]
macro_rules! index_leaf {
    ($index: literal, $leaf: ty, $cpuid: ty) => {
        impl $crate::cpuid::IndexLeaf<$index> for $cpuid {
            type Output<'a> = Option<&'a $leaf>;
            #[inline]
            fn index_leaf<'a>(&'a self) -> Self::Output<'a> {
                self.0
                    .get(&$crate::cpuid::CpuidKey::leaf($index))
                    // SAFETY: Transmuting reference to same sized types is safe.
                    .map(|entry| unsafe { std::mem::transmute::<_, &$leaf>(&entry.result) })
            }
        }
        impl $crate::cpuid::IndexLeafMut<$index> for $cpuid {
            type Output<'a> = Option<&'a mut $leaf>;
            #[inline]
            fn index_leaf_mut<'a>(&'a mut self) -> Self::Output<'a> {
                self.0
                    .get_mut(&$crate::cpuid::CpuidKey::leaf($index))
                    // SAFETY: Transmuting reference to same sized types is safe.
                    .map(|entry| unsafe { std::mem::transmute::<_, &mut $leaf>(&mut entry.result) })
            }
        }
    };
}

/// Convenience macro for indexing shared leaves.
macro_rules! cpuid_index_leaf {
    ($index: literal, $leaf: ty) => {
        impl IndexLeaf<$index> for super::Cpuid {
            type Output<'a> = Option<&'a $leaf>;
            #[inline]
            fn index_leaf<'a>(&'a self) -> Self::Output<'a> {
                match self {
                    Self::Intel(intel_cpuid) => {
                        <crate::cpuid::IntelCpuid as IndexLeaf<$index>>::index_leaf(intel_cpuid)
                    }
                    Self::Amd(amd_cpuid) => {
                        <crate::cpuid::AmdCpuid as IndexLeaf<$index>>::index_leaf(amd_cpuid)
                    }
                }
            }
        }
        impl IndexLeafMut<$index> for super::Cpuid {
            type Output<'a> = Option<&'a mut $leaf>;
            #[inline]
            fn index_leaf_mut<'a>(&'a mut self) -> Self::Output<'a> {
                match self {
                    Self::Intel(intel_cpuid) => <crate::cpuid::IntelCpuid as IndexLeafMut<
                        $index,
                    >>::index_leaf_mut(intel_cpuid),
                    Self::Amd(amd_cpuid) => {
                        <crate::cpuid::AmdCpuid as IndexLeafMut<$index>>::index_leaf_mut(amd_cpuid)
                    }
                }
            }
        }
        index_leaf!($index, $leaf, crate::cpuid::AmdCpuid);
        index_leaf!($index, $leaf, crate::cpuid::IntelCpuid);
    };
}

cpuid_index_leaf!(0x0, Leaf0);

cpuid_index_leaf!(0x1, Leaf1);

cpuid_index_leaf!(0x80000002, Leaf80000002);

cpuid_index_leaf!(0x80000003, Leaf80000003);

cpuid_index_leaf!(0x80000004, Leaf80000004);
