// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::transmute_ptr_to_ptr, clippy::needless_lifetimes)]

#[allow(clippy::wildcard_imports)]
use super::leaves::*;
use crate::guest_config::cpuid::{AmdCpuid, CpuidEntry, IntelCpuid};

/// Indexs leaf.
pub trait IndexLeaf<const INDEX: usize> {
    /// Leaf type.
    type Output<'a>
    where
        Self: 'a;
    /// Gets immutable reference to leaf.
    fn index_leaf<'a>(&'a self) -> Self::Output<'a>;
}
/// Indexs leaf.
pub trait IndexLeafMut<const INDEX: usize> {
    /// Leaf type.
    type Output<'a>
    where
        Self: 'a;
    /// Gets mutable reference to leaf.
    fn index_leaf_mut<'a>(&'a mut self) -> Self::Output<'a>;
}

/// Convenience macro for indexing leaves.
///
/// # Justification
///
/// `get`  and `get_mut` is a common Rust pattern, these functions typically return `&T`  and
/// `&mut T`  respectively. In the case of `get` it is preferable to return a reference over a copy,
/// a reference can be optimized to a copy (while a copy cannot be optimized to a reference). To
/// return a reference in either case requires `std::mem::transmute` (or casting the reference as a
/// pointer, to the same affect). This is why `std::mem::transmute` and `unsafe` is used here.
///
/// # Safety
///
/// The lifetime 'a as defined on `index_leaf<'a>(&'a self) -> Self::Output<'a>` informs the borrow
/// checker that `Self::Output` immutably borrows `self`. This prevents dropping or mutating `self`
/// before dropping `Self::Output`.
///
/// E.g.
/// ```ignore
/// fn main() {
///     let mut a: Vec<i32> = vec![1, 2, 3, 4];
///     let b = tester(&a);
///
///     // drop(a);
///     // drop(b); // Attempting to drop b after a errors.
///
///     // a[0] += 2;
///     // drop(b); // Attempting to mutably borrow a before dropping b errors.
/// }
///
/// #[derive(Debug)]
/// struct Wrapper<'a>(Vec<&'a u32>);
///
/// fn tester<'a>(vec: &'a Vec<i32>) -> Wrapper<'a> {
///     Wrapper(
///         vec.iter()
///             .map(|x: &'a i32| unsafe { std::mem::transmute::<&'a i32, &'a u32>(x) })
///             .collect::<Vec<_>>(),
///     )
/// }
/// ```
macro_rules! index_leaf {
    ($index: literal, $leaf: ty, $cpuid: ty) => {
        impl $crate::guest_config::cpuid::IndexLeaf<$index> for $cpuid {
            type Output<'a> = Option<&'a $leaf>;
            #[inline]
            fn index_leaf<'a>(&'a self) -> Self::Output<'a> {
                self.0
                    .get(&$crate::guest_config::cpuid::CpuidKey::leaf($index))
                    // JUSTIFICATION: There is no safe alternative.
                    // SAFETY: Transmuting references to same size and alignment types is safe. For
                    // further information See `index_leaf!`.
                    .map(|entry: &'a CpuidEntry| unsafe {
                        std::mem::transmute::<_, &'a $leaf>(&entry.result)
                    })
            }
        }
        impl $crate::guest_config::cpuid::IndexLeafMut<$index> for $cpuid {
            type Output<'a> = Option<&'a mut $leaf>;
            #[inline]
            fn index_leaf_mut<'a>(&'a mut self) -> Self::Output<'a> {
                self.0
                    .get_mut(&$crate::guest_config::cpuid::CpuidKey::leaf($index))
                    // JUSTIFICATION: There is no safe alternative.
                    // SAFETY: Transmuting references to same size and alignment types is safe.
                    // For further information See `index_leaf!`.
                    .map(|entry: &'a mut CpuidEntry| unsafe {
                        std::mem::transmute::<_, &'a mut $leaf>(&mut entry.result)
                    })
            }
        }
    };
}

pub(crate) use index_leaf;

/// Convenience macro for indexing shared leaves.
macro_rules! cpuid_index_leaf {
    ($index: literal, $leaf: ty) => {
        impl crate::guest_config::cpuid::IndexLeaf<$index> for super::Cpuid {
            type Output<'a> = Option<&'a $leaf>;
            #[inline]
            fn index_leaf<'a>(&'a self) -> Self::Output<'a> {
                match self {
                    Self::Intel(intel_cpuid) => {
                        <IntelCpuid as IndexLeaf<$index>>::index_leaf(intel_cpuid)
                    }
                    Self::Amd(amd_cpuid) => <AmdCpuid as IndexLeaf<$index>>::index_leaf(amd_cpuid),
                }
            }
        }
        impl crate::guest_config::cpuid::IndexLeafMut<$index> for super::Cpuid {
            type Output<'a> = Option<&'a mut $leaf>;
            #[inline]
            fn index_leaf_mut<'a>(&'a mut self) -> Self::Output<'a> {
                match self {
                    Self::Intel(intel_cpuid) => {
                        <IntelCpuid as IndexLeafMut<$index>>::index_leaf_mut(intel_cpuid)
                    }
                    Self::Amd(amd_cpuid) => {
                        <AmdCpuid as IndexLeafMut<$index>>::index_leaf_mut(amd_cpuid)
                    }
                }
            }
        }
        index_leaf!($index, $leaf, AmdCpuid);
        index_leaf!($index, $leaf, IntelCpuid);
    };
}

cpuid_index_leaf!(0x0, Leaf0);

cpuid_index_leaf!(0x1, Leaf1);

cpuid_index_leaf!(0x80000002, Leaf80000002);

cpuid_index_leaf!(0x80000003, Leaf80000003);

cpuid_index_leaf!(0x80000004, Leaf80000004);
