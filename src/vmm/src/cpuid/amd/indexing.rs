// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::transmute_ptr_to_ptr, clippy::needless_lifetimes)]

use std::mem::transmute;

#[allow(clippy::wildcard_imports)]
use super::leaves::*;
use crate::cpuid::{index_leaf, AmdCpuid, CpuidEntry, CpuidKey, IndexLeaf, IndexLeafMut};

index_leaf!(0x7, Leaf7, AmdCpuid);

index_leaf!(0x80000000, Leaf80000000, AmdCpuid);

index_leaf!(0x80000001, Leaf80000001, AmdCpuid);

index_leaf!(0x80000008, Leaf80000008, AmdCpuid);

impl IndexLeaf<0x8000001d> for AmdCpuid {
    type Output<'a> = Leaf8000001d<'a>;

    #[inline]
    fn index_leaf<'a>(&'a self) -> Self::Output<'a> {
        // JUSTIFICATION: There is no safe alternative.
        // SAFETY: Transmuting references to same size and alignment types is safe. For
        // further information See `index_leaf!`.
        unsafe {
            Leaf8000001d(
                self.0
                    .range(CpuidKey::leaf(0x8000001d)..CpuidKey::leaf(0x8000001e))
                    .map(|(_, v): (_, &'a CpuidEntry)| {
                        transmute::<_, &'a Leaf8000001dSubleaf>(&v.result)
                    })
                    .collect(),
            )
        }
    }
}

impl IndexLeafMut<0x8000001d> for AmdCpuid {
    type Output<'a> = Leaf8000001dMut<'a>;

    #[inline]
    fn index_leaf_mut<'a>(&'a mut self) -> Self::Output<'a> {
        // JUSTIFICATION: There is no safe alternative.
        // SAFETY: Transmuting references to same size and alignment types is safe. For
        // further information See `index_leaf!`.
        unsafe {
            Leaf8000001dMut(
                self.0
                    .range_mut(CpuidKey::leaf(0x8000001d)..CpuidKey::leaf(0x8000001e))
                    .map(|(_, v): (_, &'a mut CpuidEntry)| {
                        transmute::<_, &'a mut Leaf8000001dSubleaf>(&mut v.result)
                    })
                    .collect(),
            )
        }
    }
}

index_leaf!(0x8000001E, Leaf8000001e, AmdCpuid);
