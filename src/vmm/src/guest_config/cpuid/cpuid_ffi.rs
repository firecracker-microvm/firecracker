// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::cmp::{Eq, PartialEq};

/// Definitions from `kvm/arch/x86/include/uapi/asm/kvm.h
#[derive(
    Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Copy,
)]
pub struct KvmCpuidFlags(pub u32);
impl KvmCpuidFlags {
    /// Zero.
    pub const EMPTY: Self = Self(0);
    /// Indicates if the `index` field is used for indexing sub-leaves (if false, this CPUID leaf
    /// has no subleaves).
    pub const SIGNIFICANT_INDEX: Self = Self(1 << 0);
    /// Deprecated.
    pub const STATEFUL_FUNC: Self = Self(1 << 1);
    /// Deprecated.
    pub const STATE_READ_NEXT: Self = Self(1 << 2);
}

#[allow(clippy::derivable_impls)]
impl Default for KvmCpuidFlags {
    #[inline]
    fn default() -> Self {
        Self(0)
    }
}
