// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::similar_names, clippy::module_name_repetitions)]

#[allow(clippy::wildcard_imports)]
use super::*;
// -------------------------------------------------------------------------------------------------
// Indexing traits
// -------------------------------------------------------------------------------------------------
/// Indexs leaf.
pub trait IndexLeaf<const INDEX: usize> {
    /// Leaf type.
    type Output;
    /// Indexs leaf.
    ///
    /// # TODO
    ///
    /// This should be `const` when `const_trait_impl` is stabilized.
    fn leaf(&self) -> &Self::Output;
}
impl IndexLeaf<0x0> for IntelCpuid {
    type Output = Leaf0;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_0
    }
}
impl IndexLeaf<0x1> for IntelCpuid {
    type Output = Leaf1;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_1
    }
}
impl IndexLeaf<0x2> for IntelCpuid {
    type Output = Leaf2;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_2
    }
}
impl IndexLeaf<0x3> for IntelCpuid {
    type Output = Leaf3;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_3
    }
}
impl IndexLeaf<0x4> for IntelCpuid {
    type Output = Leaf4;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_4
    }
}
impl IndexLeaf<0x5> for IntelCpuid {
    type Output = Leaf5;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_5
    }
}
impl IndexLeaf<0x6> for IntelCpuid {
    type Output = Leaf6;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_6
    }
}
impl IndexLeaf<0x7> for IntelCpuid {
    type Output = Leaf7;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_7
    }
}
impl IndexLeaf<0x9> for IntelCpuid {
    type Output = Leaf9;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_9
    }
}
impl IndexLeaf<0xA> for IntelCpuid {
    type Output = LeafA;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_a
    }
}
impl IndexLeaf<0xB> for IntelCpuid {
    type Output = LeafB;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_b
    }
}
impl IndexLeaf<0xD> for IntelCpuid {
    type Output = LeafD;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_d
    }
}
impl IndexLeaf<0xF> for IntelCpuid {
    type Output = LeafF;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_f
    }
}
impl IndexLeaf<0x10> for IntelCpuid {
    type Output = Leaf10;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_10
    }
}
impl IndexLeaf<0x12> for IntelCpuid {
    type Output = Option<Leaf12>;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_12
    }
}
impl IndexLeaf<0x14> for IntelCpuid {
    type Output = Leaf14;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_14
    }
}
impl IndexLeaf<0x15> for IntelCpuid {
    type Output = Leaf15;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_15
    }
}
impl IndexLeaf<0x16> for IntelCpuid {
    type Output = Leaf16;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_16
    }
}
impl IndexLeaf<0x17> for IntelCpuid {
    type Output = Option<Leaf17>;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_17
    }
}
#[cfg(feature = "leaf_18")]
impl IndexLeaf<0x18> for IntelCpuid {
    type Output = Option<Leaf18>;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_18
    }
}
impl IndexLeaf<0x19> for IntelCpuid {
    type Output = Option<Leaf19>;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_19
    }
}
impl IndexLeaf<0x1A> for IntelCpuid {
    type Output = Option<Leaf1A>;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_1a
    }
}
impl IndexLeaf<0x1B> for IntelCpuid {
    type Output = Option<Leaf1B>;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_1b
    }
}
impl IndexLeaf<0x1C> for IntelCpuid {
    type Output = Option<Leaf1C>;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_1c
    }
}
impl IndexLeaf<0x1F> for IntelCpuid {
    type Output = Leaf1F;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_1f
    }
}
impl IndexLeaf<0x20> for IntelCpuid {
    type Output = Option<Leaf20>;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_20
    }
}
impl IndexLeaf<0x8000_0000> for IntelCpuid {
    type Output = Leaf80000000;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_80000000
    }
}
impl IndexLeaf<0x8000_0001> for IntelCpuid {
    type Output = Leaf80000001;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_80000001
    }
}
impl IndexLeaf<0x8000_0002> for IntelCpuid {
    type Output = Leaf80000002;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_80000002
    }
}
impl IndexLeaf<0x8000_0003> for IntelCpuid {
    type Output = Leaf80000003;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_80000003
    }
}
impl IndexLeaf<0x8000_0004> for IntelCpuid {
    type Output = Leaf80000004;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_80000004
    }
}
impl IndexLeaf<0x8000_0005> for IntelCpuid {
    type Output = Leaf80000005;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_80000005
    }
}
impl IndexLeaf<0x8000_0006> for IntelCpuid {
    type Output = Leaf80000006;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_80000006
    }
}
impl IndexLeaf<0x8000_0007> for IntelCpuid {
    type Output = Leaf80000007;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_80000007
    }
}
impl IndexLeaf<0x8000_0008> for IntelCpuid {
    type Output = Leaf80000008;

    fn leaf(&self) -> &Self::Output {
        &self.leaf_80000008
    }
}

/// Indexes subleaf.
pub trait IndexSubLeaf<const INDEX: usize> {
    /// Subleaf type.
    type Output;
    /// Indexs subleaf.
    ///
    /// # TODO
    ///
    /// This should be `const` when `const_trait_impl` is stabilized.
    fn sub_leaf(&self) -> &Self::Output;
}
impl<A, B, C, D> IndexSubLeaf<0> for Leaf<A, B, C, D> {
    /// Subleaf type.
    type Output = Self;
    /// Indexes subleaf.
    fn sub_leaf(&self) -> &Self::Output {
        self
    }
}
impl<A, B, C, D> Leaf<A, B, C, D> {
    /// Indexes subleaf.
    pub fn sub_leaf<const N: usize>(&self) -> &<Self as IndexSubLeaf<N>>::Output
    where
        Self: IndexSubLeaf<N>,
    {
        <Self as IndexSubLeaf<N>>::sub_leaf(self)
    }
}
impl<const N: usize> IndexSubLeaf<N> for Leaf4 {
    /// Subleaf type.
    type Output = Leaf4Subleaf;
    /// Indexes subleaf.
    fn sub_leaf(&self) -> &Self::Output {
        &self.0[N]
    }
}
impl Leaf4 {
    /// Indexes subleaf.
    #[must_use]
    pub fn sub_leaf<const N: usize>(&self) -> &<Self as IndexSubLeaf<N>>::Output
    where
        Self: IndexSubLeaf<N>,
    {
        <Self as IndexSubLeaf<N>>::sub_leaf(self)
    }
}
impl IndexSubLeaf<0> for Leaf7 {
    type Output = Leaf7Subleaf0;
    /// Indexes subleaf.
    fn sub_leaf(&self) -> &Self::Output {
        &self.0
    }
}
impl IndexSubLeaf<1> for Leaf7 {
    type Output = Option<Leaf7Subleaf1>;
    /// Indexes subleaf.
    fn sub_leaf(&self) -> &Self::Output {
        &self.1
    }
}
impl Leaf7 {
    /// Indexes subleaf.
    #[must_use]
    pub fn sub_leaf<const N: usize>(&self) -> &<Self as IndexSubLeaf<N>>::Output
    where
        Self: IndexSubLeaf<N>,
    {
        <Self as IndexSubLeaf<N>>::sub_leaf(self)
    }
}
impl<const N: usize> IndexSubLeaf<N> for LeafB {
    type Output = LeafBSubleaf;
    /// Indexes subleaf.
    fn sub_leaf(&self) -> &Self::Output {
        &self.0[N]
    }
}
impl LeafB {
    /// Indexes subleaf.
    #[must_use]
    pub fn sub_leaf<const N: usize>(&self) -> &<Self as IndexSubLeaf<N>>::Output
    where
        Self: IndexSubLeaf<N>,
    {
        <Self as IndexSubLeaf<N>>::sub_leaf(self)
    }
}
/// This implementation is only present in the documentation, you cannot use it as at the moment it
/// cannot be correctly implemented.
///
/// We cannot implement `IndexSubLeaf` for `LeafD` without
/// [specialization](https://rust-lang.github.io/rfcs/1210-impl-specialization.html), implement it
/// like below when specialization is stabilized.
/// ```ignore
/// impl IndexSubLeaf<0> for LeafD {
///     type Output = LeafDSubleaf0;
///
///     fn sub_leaf(&self) -> &Self::Output {
///         &self.0
///     }
/// }
/// impl IndexSubLeaf<1> for LeafD {
///     type Output = LeafDSubleaf1;
///
///     fn sub_leaf(&self) -> &Self::Output {
///         &self.1
///     }
/// }
/// impl<const N: usize> IndexSubLeaf<N> for LeafD {
///     type Output = LeafDSubleafGt1;
///
///     default fn sub_leaf(&self) -> &Self::Output {
///         &self.2[N]
///     }
/// }
/// ```
#[cfg(doc)]
impl<const N: usize> IndexSubLeaf<N> for LeafD {
    type Output = Self;
    /// Indexes subleaf.
    fn sub_leaf(&self) -> &Self::Output {
        unimplemented!()
    }
}
impl LeafD {
    /// Indexes subleaf.
    #[must_use]
    pub fn sub_leaf<const N: usize>(&self) -> &<Self as IndexSubLeaf<N>>::Output
    where
        Self: IndexSubLeaf<N>,
    {
        <Self as IndexSubLeaf<N>>::sub_leaf(self)
    }
}
impl IndexSubLeaf<0> for LeafF {
    /// Subleaf type.
    type Output = LeafFSubleaf0;
    /// Indexes subleaf.
    fn sub_leaf(&self) -> &Self::Output {
        &self.0
    }
}
impl IndexSubLeaf<1> for LeafF {
    /// Subleaf type.
    type Output = Option<LeafFSubleaf1>;
    /// Indexes subleaf.
    fn sub_leaf(&self) -> &Self::Output {
        &self.1
    }
}
impl LeafF {
    /// Indexes subleaf.
    #[must_use]
    pub fn sub_leaf<const N: usize>(&self) -> &<Self as IndexSubLeaf<N>>::Output
    where
        Self: IndexSubLeaf<N>,
    {
        <Self as IndexSubLeaf<N>>::sub_leaf(self)
    }
}
impl IndexSubLeaf<0> for Leaf10 {
    /// Subleaf type.
    type Output = Leaf10Subleaf0;
    /// Indexes subleaf.
    fn sub_leaf(&self) -> &Self::Output {
        &self.0
    }
}
impl IndexSubLeaf<1> for Leaf10 {
    /// Subleaf type.
    type Output = Option<Leaf10Subleaf1>;
    /// Indexes subleaf.
    fn sub_leaf(&self) -> &Self::Output {
        &self.1
    }
}
impl IndexSubLeaf<2> for Leaf10 {
    /// Subleaf type.
    type Output = Option<Leaf10Subleaf2>;
    /// Indexes subleaf.
    fn sub_leaf(&self) -> &Self::Output {
        &self.2
    }
}
impl IndexSubLeaf<3> for Leaf10 {
    /// Subleaf type.
    type Output = Option<Leaf10Subleaf3>;
    /// Indexes subleaf.
    fn sub_leaf(&self) -> &Self::Output {
        &self.3
    }
}
impl Leaf10 {
    /// Indexes subleaf.
    #[must_use]
    pub fn sub_leaf<const N: usize>(&self) -> &<Self as IndexSubLeaf<N>>::Output
    where
        Self: IndexSubLeaf<N>,
    {
        <Self as IndexSubLeaf<N>>::sub_leaf(self)
    }
}
/// This implementation is only present in the documentation, you cannot use it as at the moment it
/// cannot be correctly implemented.
///
/// We cannot implement `IndexSubLeaf` for `LeafD` without
/// [specialization](https://rust-lang.github.io/rfcs/1210-impl-specialization.html), implement it
/// like below when specialization is stabilized.
/// ```ignore
/// impl IndexSubLeaf<0> for Leaf12 {
///     type Output = Leaf12Subleaf0;
///
///     fn sub_leaf(&self) -> &Self::Output {
///         &self.0
///     }
/// }
/// impl IndexSubLeaf<1> for Leaf12 {
///     type Output = Option<Leaf12Subleaf1>;
///
///     fn sub_leaf(&self) -> &Self::Output {
///         &self.1
///     }
/// }
/// impl<const N: usize> IndexSubLeaf<N> for Leaf12 {
///     type Output = Leaf12SubleafGt1;
///
///     default fn sub_leaf(&self) -> &Self::Output {
///         &self.2[N]
///     }
/// }
/// ```
#[cfg(doc)]
impl<const N: usize> IndexSubLeaf<N> for Leaf12 {
    /// Subleaf type.
    type Output = Self;
    /// Indexes subleaf.
    fn sub_leaf(&self) -> &Self::Output {
        unimplemented!()
    }
}
impl Leaf12 {
    /// Indexes subleaf.
    #[must_use]
    pub fn sub_leaf<const N: usize>(&self) -> &<Self as IndexSubLeaf<N>>::Output
    where
        Self: IndexSubLeaf<N>,
    {
        <Self as IndexSubLeaf<N>>::sub_leaf(self)
    }
}
impl IndexSubLeaf<0> for Leaf14 {
    /// Subleaf type.
    type Output = Leaf14Subleaf0;
    /// Indexes subleaf.
    fn sub_leaf(&self) -> &Self::Output {
        &self.0
    }
}
impl IndexSubLeaf<1> for Leaf14 {
    /// Subleaf type.
    type Output = Option<Leaf14Subleaf1>;
    /// Indexes subleaf.
    fn sub_leaf(&self) -> &Self::Output {
        &self.1
    }
}
impl Leaf14 {
    /// Indexes subleaf.
    #[must_use]
    pub fn sub_leaf<const N: usize>(&self) -> &<Self as IndexSubLeaf<N>>::Output
    where
        Self: IndexSubLeaf<N>,
    {
        <Self as IndexSubLeaf<N>>::sub_leaf(self)
    }
}
/// This implementation is only present in the documentation, you cannot use it as at the moment it
/// cannot be correctly implemented.
///
/// We cannot implement `IndexSubLeaf` for `Leaf17` without
/// [specialization](https://rust-lang.github.io/rfcs/1210-impl-specialization.html), implement it
/// like below when specialization is stabilized.
/// ```ignore
/// impl IndexSubLeaf<0> for Leaf17 {
///     type Output = Leaf17Subleaf0;
///
///     fn sub_leaf(&self) -> &Self::Output {
///         &self.0
///     }
/// }
/// impl IndexSubLeaf<1> for Leaf17 {
///     type Output = Leaf17Subleaf1;
///
///     fn sub_leaf(&self) -> &Self::Output {
///         &self.1
///     }
/// }
/// impl IndexSubLeaf<1> for Leaf17 {
///     type Output = Leaf17Subleaf2;
///
///     fn sub_leaf(&self) -> &Self::Output {
///         &self.2
///     }
/// }
/// impl IndexSubLeaf<1> for Leaf17 {
///     type Output = Leaf17Subleaf3;
///
///     fn sub_leaf(&self) -> &Self::Output {
///         &self.3
///     }
/// }
/// impl<const N: usize> IndexSubLeaf<N> for Leaf17 {
///     type Output = Leaf17SubleafGt3;
///
///     default fn sub_leaf(&self) -> &Self::Output {
///         &self.4[N]
///     }
/// }
/// ```
#[cfg(doc)]
impl<const N: usize> IndexSubLeaf<N> for Leaf17 {
    /// Subleaf type.
    type Output = Self;
    /// Indexes subleaf.
    fn sub_leaf(&self) -> &Self::Output {
        unimplemented!()
    }
}
impl Leaf17 {
    /// Indexes subleaf.
    #[must_use]
    pub fn sub_leaf<const N: usize>(&self) -> &<Self as IndexSubLeaf<N>>::Output
    where
        Self: IndexSubLeaf<N>,
    {
        <Self as IndexSubLeaf<N>>::sub_leaf(self)
    }
}
/// This implementation is only present in the documentation, you cannot use it as at the moment it
/// cannot be correctly implemented.
///
/// We cannot implement `IndexSubLeaf` for `Leaf18` without
/// [specialization](https://rust-lang.github.io/rfcs/1210-impl-specialization.html), implement it
/// like below when specialization is stabilized.
/// ```ignore
/// impl IndexSubLeaf<0> for Leaf18 {
///     type Output = Leaf18Subleaf0;
///
///     fn sub_leaf(&self) -> &Self::Output {
///         &self.0
///     }
/// }
/// impl<const N: usize> IndexSubLeaf<N> for Leaf18 {
///     type Output = Leaf18SubleafGt0;
///
///     default fn sub_leaf(&self) -> &Self::Output {
///         &self.1[N]
///     }
/// }
/// ```
#[cfg(doc)]
impl<const N: usize> IndexSubLeaf<N> for Leaf18 {
    /// Subleaf type.
    type Output = Self;
    /// Indexes subleaf.
    fn sub_leaf(&self) -> &Self::Output {
        unimplemented!()
    }
}
#[cfg(feature = "leaf_18")]
impl Leaf18 {
    /// Indexes subleaf.
    #[must_use]
    pub fn sub_leaf<const N: usize>(&self) -> &<Self as IndexSubLeaf<N>>::Output
    where
        Self: IndexSubLeaf<N>,
    {
        <Self as IndexSubLeaf<N>>::sub_leaf(self)
    }
}
impl<const N: usize> IndexSubLeaf<N> for Leaf1F {
    /// Subleaf type.
    type Output = Leaf1FSubleaf;
    /// Indexes subleaf.
    fn sub_leaf(&self) -> &Self::Output {
        &self.0[N]
    }
}
impl Leaf1F {
    /// Indexes subleaf.
    #[must_use]
    pub fn sub_leaf<const N: usize>(&self) -> &<Self as IndexSubLeaf<N>>::Output
    where
        Self: IndexSubLeaf<N>,
    {
        <Self as IndexSubLeaf<N>>::sub_leaf(self)
    }
}
/// Utility enum for coummicating register indexs.
#[allow(clippy::upper_case_acronyms)]
pub enum Register {
    /// EAX register index.
    EAX = 0,
    /// EBX register index.
    EBX = 1,
    /// ECX register index.
    ECX = 2,
    /// EDX register index.
    EDX = 3,
}
/// Indexes register.
///
/// # TODO
///
/// Use `Register` instead of `u8` here when `adt_const_params` is stabilized.
pub trait IndexRegister<const INDEX: u8> {
    /// Register type
    type Output;
    /// Indexs register
    fn register(&self) -> &Self::Output;
}
impl<A, B, C, D> IndexRegister<0> for Leaf<A, B, C, D> {
    /// Register type
    type Output = A;
    /// Indexs register
    fn register(&self) -> &Self::Output {
        &self.eax
    }
}
impl<A, B, C, D> IndexRegister<1> for Leaf<A, B, C, D> {
    /// Register type
    type Output = B;
    /// Indexs register
    fn register(&self) -> &Self::Output {
        &self.ebx
    }
}
impl<A, B, C, D> IndexRegister<2> for Leaf<A, B, C, D> {
    /// Register type
    type Output = C;
    /// Indexs register
    fn register(&self) -> &Self::Output {
        &self.ecx
    }
}
impl<A, B, C, D> IndexRegister<3> for Leaf<A, B, C, D> {
    /// Register type
    type Output = D;
    /// Indexs register
    fn register(&self) -> &Self::Output {
        &self.edx
    }
}
