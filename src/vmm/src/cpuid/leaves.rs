// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[allow(clippy::wildcard_imports)]
use crate::cpuid::registers::*;

/// A generic leaf formed of 4 members `eax`, `ebx`, `ecx` and `edx`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(C)]
pub struct Leaf<A, B, C, D> {
    /// EAX register.
    pub eax: A,
    /// EBX register.
    pub ebx: B,
    /// ECX register.
    pub ecx: C,
    /// EDX register.
    pub edx: D,
}

impl<A, B, C, D> From<(A, B, C, D)> for Leaf<A, B, C, D> {
    #[inline]
    fn from((a, b, c, d): (A, B, C, D)) -> Self {
        Leaf {
            eax: a,
            ebx: b,
            ecx: c,
            edx: d,
        }
    }
}

/// Leaf 00H
pub type Leaf0 = Leaf<u32, u32, u32, u32>;

/// Leaf 01H
pub type Leaf1 = Leaf<Leaf1Eax, Leaf1Ebx, Leaf1Ecx, Leaf1Edx>;

/// Leaf 0BH
#[derive(Debug, PartialEq, Eq)]
pub struct LeafB<'a>(pub Vec<&'a LeafBSubleaf>);

/// Leaf 0BH
#[derive(Debug, PartialEq, Eq)]
pub struct LeafBMut<'a>(pub Vec<&'a mut LeafBSubleaf>);

/// Leaf 0BH subleaf
pub type LeafBSubleaf = Leaf<LeafBEax, LeafBEbx, LeafBEcx, LeafBEdx>;

/// Leaf 80000002H
pub type Leaf80000002 = Leaf<Leaf80000002Eax, Leaf80000002Ebx, Leaf80000002Ecx, Leaf80000002Edx>;

/// Leaf 80000003H
pub type Leaf80000003 = Leaf80000002;

/// Leaf 80000004H
pub type Leaf80000004 = Leaf80000002;
