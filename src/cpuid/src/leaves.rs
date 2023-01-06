// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use bit_fields::Equal;

use super::cpuid_ffi::RawKvmCpuidEntry;
#[allow(clippy::wildcard_imports)]
use super::registers::*;

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

#[cfg(cpuid)]
impl<A: From<u32>, B: From<u32>, C: From<u32>, D: From<u32>> From<std::arch::x86_64::CpuidResult>
    for Leaf<A, B, C, D>
{
    #[inline]
    fn from(
        std::arch::x86_64::CpuidResult { eax, ebx, ecx, edx }: std::arch::x86_64::CpuidResult,
    ) -> Self {
        Leaf {
            eax: A::from(eax),
            ebx: B::from(ebx),
            ecx: C::from(ecx),
            edx: D::from(edx),
        }
    }
}

impl<A: From<u32>, B: From<u32>, C: From<u32>, D: From<u32>> From<&RawKvmCpuidEntry>
    for Leaf<A, B, C, D>
{
    #[inline]
    fn from(
        &RawKvmCpuidEntry {
            eax, ebx, ecx, edx, ..
        }: &RawKvmCpuidEntry,
    ) -> Self {
        Leaf {
            eax: A::from(eax),
            ebx: B::from(ebx),
            ecx: C::from(ecx),
            edx: D::from(edx),
        }
    }
}

impl<A: Equal, B: Equal, C: Equal, D: Equal> Equal for Leaf<A, B, C, D> {
    #[inline]
    fn equal(&self, other: &Self) -> bool {
        self.eax.equal(&other.eax)
            && self.ebx.equal(&other.ebx)
            && self.ecx.equal(&other.ecx)
            && self.edx.equal(&other.edx)
    }
}

// -------------------------------------------------------------------------------------------------
// Shared leaf types
// -------------------------------------------------------------------------------------------------

/// Leaf 00H
pub type Leaf0 = Leaf<u32, u32, u32, u32>;

/// Leaf 01H
pub type Leaf1 = Leaf<Leaf1Eax, Leaf1Ebx, Leaf1Ecx, Leaf1Edx>;

/// Leaf 80000002H
pub type Leaf80000002 = Leaf<Leaf80000002Eax, Leaf80000002Ebx, Leaf80000002Ecx, Leaf80000002Edx>;

/// Leaf 80000003H
pub type Leaf80000003 = Leaf80000002;

/// Leaf 80000004H
pub type Leaf80000004 = Leaf80000002;
