// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::transmute_ptr_to_ptr, clippy::needless_lifetimes)]

use std::mem::transmute;

#[allow(clippy::wildcard_imports)]
use super::leaves::*;
use crate::{index_leaf, transmute_vec, CpuidKey, IndexLeaf, IndexLeafMut, IntelCpuid};

index_leaf!(0x2, Leaf2, IntelCpuid);

index_leaf!(0x3, Leaf3, IntelCpuid);

impl IndexLeaf<0x4> for IntelCpuid {
    type Output<'a> = Leaf4<'a>;

    #[inline]
    fn index_leaf<'a>(&'a self) -> Self::Output<'a> {
        // SAFETY: Transmuting reference to same sized types is safe.
        unsafe {
            Leaf4(transmute_vec(
                self.0
                    .range(CpuidKey::leaf(0x4)..CpuidKey::leaf(0x5))
                    .map(|(_, v)| transmute::<_, &'a Leaf4Subleaf>(&v.result))
                    .collect(),
            ))
        }
    }
}

impl IndexLeafMut<0x4> for IntelCpuid {
    type Output<'a> = Leaf4Mut<'a>;

    #[inline]
    fn index_leaf_mut<'a>(&'a mut self) -> Self::Output<'a> {
        // SAFETY: Transmuting reference to same sized types is safe.
        unsafe {
            Leaf4Mut(transmute_vec(
                self.0
                    .range_mut(CpuidKey::leaf(0x4)..CpuidKey::leaf(0x5))
                    .map(|(_, v)| transmute::<_, &'a mut Leaf4Subleaf>(&mut v.result))
                    .collect(),
            ))
        }
    }
}

index_leaf!(0x5, Leaf5, IntelCpuid);

index_leaf!(0x6, Leaf6, IntelCpuid);

impl IndexLeaf<0x7> for IntelCpuid {
    type Output<'a> = Leaf7<'a>;

    #[inline]
    fn index_leaf<'a>(&'a self) -> Self::Output<'a> {
        Leaf7(
            self.0
                .get(&CpuidKey::subleaf(0x7, 0x0))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a Leaf7Subleaf0>(&entry.result) }),
            self.0
                .get(&CpuidKey::subleaf(0x7, 0x1))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a Leaf7Subleaf1>(&entry.result) }),
        )
    }
}

impl IndexLeafMut<0x7> for IntelCpuid {
    type Output<'a> = Leaf7Mut<'a>;

    #[inline]
    fn index_leaf_mut<'a>(&'a mut self) -> Self::Output<'a> {
        Leaf7Mut(
            self.0
                .get_mut(&CpuidKey::subleaf(0x7, 0x0))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a mut Leaf7Subleaf0>(&mut entry.result) }),
            self.0
                .get_mut(&CpuidKey::subleaf(0x7, 0x1))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a mut Leaf7Subleaf1>(&mut entry.result) }),
        )
    }
}

index_leaf!(0x9, Leaf9, IntelCpuid);

index_leaf!(0xA, LeafA, IntelCpuid);

impl IndexLeaf<0xB> for IntelCpuid {
    type Output<'a> = LeafB<'a>;

    #[inline]
    fn index_leaf<'a>(&'a self) -> Self::Output<'a> {
        // SAFETY: Transmuting reference to same sized types is safe.
        unsafe {
            LeafB(transmute_vec(
                self.0
                    .range(CpuidKey::leaf(0xB)..CpuidKey::leaf(0xC))
                    .map(|(_, v)| transmute::<_, &'a LeafBSubleaf>(&v.result))
                    .collect(),
            ))
        }
    }
}

impl IndexLeafMut<0xB> for IntelCpuid {
    type Output<'a> = LeafBMut<'a>;

    #[inline]
    fn index_leaf_mut<'a>(&'a mut self) -> Self::Output<'a> {
        // SAFETY: Transmuting reference to same sized types is safe.
        unsafe {
            LeafBMut(transmute_vec(
                self.0
                    .range_mut(CpuidKey::leaf(0xB)..CpuidKey::leaf(0xC))
                    .map(|(_, v)| transmute::<_, &'a mut LeafBSubleaf>(&mut v.result))
                    .collect(),
            ))
        }
    }
}

impl IndexLeaf<0xF> for IntelCpuid {
    type Output<'a> = LeafF<'a>;

    #[inline]
    fn index_leaf<'a>(&'a self) -> Self::Output<'a> {
        LeafF(
            self.0
                .get(&CpuidKey::subleaf(0x7, 0x0))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a LeafFSubleaf0>(&entry.result) }),
            self.0
                .get(&CpuidKey::subleaf(0x7, 0x1))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a LeafFSubleaf1>(&entry.result) }),
        )
    }
}

impl IndexLeafMut<0xF> for IntelCpuid {
    type Output<'a> = LeafFMut<'a>;

    #[inline]
    fn index_leaf_mut<'a>(&'a mut self) -> Self::Output<'a> {
        LeafFMut(
            self.0
                .get_mut(&CpuidKey::subleaf(0x7, 0x0))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a mut LeafFSubleaf0>(&mut entry.result) }),
            self.0
                .get_mut(&CpuidKey::subleaf(0x7, 0x1))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a mut LeafFSubleaf1>(&mut entry.result) }),
        )
    }
}

impl IndexLeaf<0x10> for IntelCpuid {
    type Output<'a> = Leaf10<'a>;

    #[inline]
    fn index_leaf<'a>(&'a self) -> Self::Output<'a> {
        Leaf10(
            self.0
                .get(&CpuidKey::subleaf(0x10, 0x0))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a Leaf10Subleaf0>(&entry.result) }),
            self.0
                .get(&CpuidKey::subleaf(0x10, 0x1))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a Leaf10Subleaf1>(&entry.result) }),
            self.0
                .get(&CpuidKey::subleaf(0x10, 0x2))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a Leaf10Subleaf2>(&entry.result) }),
            self.0
                .get(&CpuidKey::subleaf(0x10, 0x3))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a Leaf10Subleaf3>(&entry.result) }),
        )
    }
}

impl IndexLeafMut<0x10> for IntelCpuid {
    type Output<'a> = Leaf10Mut<'a>;

    #[inline]
    fn index_leaf_mut<'a>(&'a mut self) -> Self::Output<'a> {
        Leaf10Mut(
            self.0
                .get_mut(&CpuidKey::subleaf(0x10, 0x0))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a mut Leaf10Subleaf0>(&mut entry.result) }),
            self.0
                .get_mut(&CpuidKey::subleaf(0x10, 0x1))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a mut Leaf10Subleaf1>(&mut entry.result) }),
            self.0
                .get_mut(&CpuidKey::subleaf(0x10, 0x2))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a mut Leaf10Subleaf2>(&mut entry.result) }),
            self.0
                .get_mut(&CpuidKey::subleaf(0x10, 0x3))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a mut Leaf10Subleaf3>(&mut entry.result) }),
        )
    }
}

impl IndexLeaf<0x12> for IntelCpuid {
    type Output<'a> = Leaf12<'a>;

    #[inline]
    fn index_leaf<'a>(&'a self) -> Self::Output<'a> {
        Leaf12(
            self.0
                .get(&CpuidKey::subleaf(0x12, 0x0))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a Leaf12Subleaf0>(&entry.result) }),
            self.0
                .get(&CpuidKey::subleaf(0x12, 0x1))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a Leaf12Subleaf1>(&entry.result) }),
            // SAFETY: Transmuting reference to same sized types is safe.
            unsafe {
                transmute_vec(
                    self.0
                        .range(CpuidKey::leaf(0x12)..CpuidKey::leaf(0x2))
                        .map(|(_, v)| transmute::<_, &'a Leaf12SubleafGt1>(&v.result))
                        .collect(),
                )
            },
        )
    }
}

impl IndexLeafMut<0x12> for IntelCpuid {
    type Output<'a> = Leaf12Mut<'a>;

    #[inline]
    fn index_leaf_mut<'a>(&'a mut self) -> Self::Output<'a> {
        Leaf12Mut(
            self.0
                .get_mut(&CpuidKey::subleaf(0x12, 0x0))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a mut Leaf12Subleaf0>(&mut entry.result) }),
            self.0
                .get_mut(&CpuidKey::subleaf(0x12, 0x1))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a mut Leaf12Subleaf1>(&mut entry.result) }),
            // SAFETY: Transmuting reference to same sized types is safe.
            unsafe {
                transmute_vec(
                    self.0
                        .range_mut(CpuidKey::leaf(0x12)..CpuidKey::leaf(0x2))
                        .map(|(_, v)| transmute::<_, &'a mut Leaf12SubleafGt1>(&mut v.result))
                        .collect(),
                )
            },
        )
    }
}

impl IndexLeaf<0x14> for IntelCpuid {
    type Output<'a> = Leaf14<'a>;

    #[inline]
    fn index_leaf<'a>(&'a self) -> Self::Output<'a> {
        Leaf14(
            self.0
                .get(&CpuidKey::subleaf(0x14, 0x0))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a Leaf14Subleaf0>(&entry.result) }),
            self.0
                .get(&CpuidKey::subleaf(0x14, 0x1))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a Leaf14Subleaf1>(&entry.result) }),
        )
    }
}

impl IndexLeafMut<0x14> for IntelCpuid {
    type Output<'a> = Leaf14Mut<'a>;

    #[inline]
    fn index_leaf_mut<'a>(&'a mut self) -> Self::Output<'a> {
        Leaf14Mut(
            self.0
                .get_mut(&CpuidKey::subleaf(0x14, 0x0))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a mut Leaf14Subleaf0>(&mut entry.result) }),
            self.0
                .get_mut(&CpuidKey::subleaf(0x14, 0x1))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a mut Leaf14Subleaf1>(&mut entry.result) }),
        )
    }
}

index_leaf!(0x15, Leaf15, IntelCpuid);

index_leaf!(0x16, Leaf16, IntelCpuid);

impl IndexLeaf<0x17> for IntelCpuid {
    type Output<'a> = Leaf17<'a>;

    #[inline]
    fn index_leaf<'a>(&'a self) -> Self::Output<'a> {
        Leaf17(
            self.0
                .get(&CpuidKey::subleaf(0x17, 0x0))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a Leaf17Subleaf0>(&entry.result) }),
            self.0
                .get(&CpuidKey::subleaf(0x17, 0x1))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a Leaf17Subleaf1>(&entry.result) }),
            self.0
                .get(&CpuidKey::subleaf(0x17, 0x2))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a Leaf17Subleaf2>(&entry.result) }),
            self.0
                .get(&CpuidKey::subleaf(0x17, 0x3))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a Leaf17Subleaf3>(&entry.result) }),
        )
    }
}

impl IndexLeafMut<0x17> for IntelCpuid {
    type Output<'a> = Leaf17Mut<'a>;

    #[inline]
    fn index_leaf_mut<'a>(&'a mut self) -> Self::Output<'a> {
        Leaf17Mut(
            self.0
                .get_mut(&CpuidKey::subleaf(0x17, 0x0))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a mut Leaf17Subleaf0>(&mut entry.result) }),
            self.0
                .get_mut(&CpuidKey::subleaf(0x17, 0x1))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a mut Leaf17Subleaf1>(&mut entry.result) }),
            self.0
                .get_mut(&CpuidKey::subleaf(0x17, 0x2))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a mut Leaf17Subleaf2>(&mut entry.result) }),
            self.0
                .get_mut(&CpuidKey::subleaf(0x17, 0x3))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a mut Leaf17Subleaf3>(&mut entry.result) }),
        )
    }
}

impl IndexLeaf<0x18> for IntelCpuid {
    type Output<'a> = Leaf18<'a>;

    #[inline]
    fn index_leaf<'a>(&'a self) -> Self::Output<'a> {
        Leaf18(
            self.0
                .get(&CpuidKey::subleaf(0x18, 0x0))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a Leaf18Subleaf0>(&entry.result) }),
            // SAFETY: Transmuting reference to same sized types is safe.
            unsafe {
                transmute_vec(
                    self.0
                        .range(CpuidKey::subleaf(0x18, 0x1)..CpuidKey::leaf(0x19))
                        .map(|(_, v)| transmute::<_, &'a Leaf18SubleafGt0>(&v.result))
                        .collect(),
                )
            },
        )
    }
}

impl IndexLeafMut<0x18> for IntelCpuid {
    type Output<'a> = Leaf18Mut<'a>;

    #[inline]
    fn index_leaf_mut<'a>(&'a mut self) -> Self::Output<'a> {
        Leaf18Mut(
            self.0
                .get_mut(&CpuidKey::subleaf(0x18, 0x0))
                // SAFETY: Transmuting reference to same sized types is safe.
                .map(|entry| unsafe { transmute::<_, &'a mut Leaf18Subleaf0>(&mut entry.result) }),
            // SAFETY: Transmuting reference to same sized types is safe.
            unsafe {
                transmute_vec(
                    self.0
                        .range_mut(CpuidKey::subleaf(0x18, 0x1)..CpuidKey::leaf(0x19))
                        .map(|(_, v)| transmute::<_, &'a mut Leaf18SubleafGt0>(&mut v.result))
                        .collect(),
                )
            },
        )
    }
}

index_leaf!(0x19, Leaf19, IntelCpuid);

index_leaf!(0x1A, Leaf1A, IntelCpuid);

index_leaf!(0x1C, Leaf1C, IntelCpuid);

impl IndexLeaf<0x1F> for IntelCpuid {
    type Output<'a> = Leaf1F<'a>;

    #[inline]
    fn index_leaf<'a>(&'a self) -> Self::Output<'a> {
        // SAFETY: Transmuting reference to same sized types is safe.
        Leaf1F(unsafe {
            transmute_vec(
                self.0
                    .range(CpuidKey::leaf(0x1F)..CpuidKey::leaf(0x20))
                    .map(|(_, v)| transmute::<_, &'a Leaf1FSubleaf>(&v.result))
                    .collect(),
            )
        })
    }
}

impl IndexLeafMut<0x1F> for IntelCpuid {
    type Output<'a> = Leaf1FMut<'a>;

    #[inline]
    fn index_leaf_mut<'a>(&'a mut self) -> Self::Output<'a> {
        // SAFETY: Transmuting reference to same sized types is safe.
        Leaf1FMut(unsafe {
            transmute_vec(
                self.0
                    .range_mut(CpuidKey::leaf(0x1F)..CpuidKey::leaf(0x20))
                    .map(|(_, v)| transmute::<_, &'a mut Leaf1FSubleaf>(&mut v.result))
                    .collect(),
            )
        })
    }
}

index_leaf!(0x20, Leaf20, IntelCpuid);

index_leaf!(0x80000000, Leaf80000000, IntelCpuid);

index_leaf!(0x80000001, Leaf80000001, IntelCpuid);

index_leaf!(0x80000005, Leaf80000005, IntelCpuid);

index_leaf!(0x80000006, Leaf80000006, IntelCpuid);

index_leaf!(0x80000007, Leaf80000007, IntelCpuid);

index_leaf!(0x80000008, Leaf80000008, IntelCpuid);
