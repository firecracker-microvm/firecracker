// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Classic BPF instructions used in seccomp filters.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zerocopy::{FromBytes, Immutable, IntoBytes};

use super::{SeccompFeatures, UnknownSeccompFeature};

/// Fit libc's opcode constants to the kernel's 16-bit instruction field.
pub const fn opcode(value: u32) -> u16 {
    assert!(value <= u16::MAX as u32);
    #[allow(clippy::cast_possible_truncation)]
    {
        value as u16
    }
}

pub const BPF_JMP_JA: u16 = opcode(libc::BPF_JMP | libc::BPF_JA);
pub const BPF_RET_K: u16 = opcode(libc::BPF_RET | libc::BPF_K);
pub const BPF_RET_A: u16 = opcode(libc::BPF_RET | libc::BPF_A);
pub const BPF_MAX_LEN: usize = libc::BPF_MAXINSNS as usize;

/// A classic BPF instruction, with the kernel's `sock_filter` layout.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, Immutable)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

const _: () = {
    assert!(size_of::<SockFilter>() == size_of::<libc::sock_filter>());
    assert!(align_of::<SockFilter>() == align_of::<libc::sock_filter>());
};

impl SockFilter {
    /// A statement without conditional jump offsets.
    pub const fn stmt(code: u16, k: u32) -> Self {
        Self {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }
}

// Bitcode stores each instruction as one little-endian word, not four struct fields.
impl Serialize for SockFilter {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let [c0, c1] = self.code.to_le_bytes();
        let [k0, k1, k2, k3] = self.k.to_le_bytes();
        serializer.serialize_u64(u64::from_le_bytes([
            c0, c1, self.jt, self.jf, k0, k1, k2, k3,
        ]))
    }
}

impl<'de> Deserialize<'de> for SockFilter {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let [c0, c1, jt, jf, k0, k1, k2, k3] = u64::deserialize(deserializer)?.to_le_bytes();
        Ok(Self {
            code: u16::from_le_bytes([c0, c1]),
            jt,
            jf,
            k: u32::from_le_bytes([k0, k1, k2, k3]),
        })
    }
}

/// One part of a compiled filter. The loader can retain raw tags to report unknown names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BpfPart<F = SeccompFeatures> {
    pub features: F,
    pub code: Vec<SockFilter>,
}

impl TryFrom<BpfPart<Vec<String>>> for BpfPart {
    type Error = UnknownSeccompFeature;

    fn try_from(part: BpfPart<Vec<String>>) -> Result<Self, Self::Error> {
        Ok(Self {
            features: SeccompFeatures::from_tags(&part.features)?,
            code: part.code,
        })
    }
}

/// Concatenate untagged parts and parts matching any enabled feature, in policy order.
pub fn compose(parts: &[BpfPart], enabled: SeccompFeatures) -> Vec<SockFilter> {
    let mut program = Vec::new();
    for part in parts {
        if part.features.is_empty() || part.features.intersects(enabled) {
            program.extend_from_slice(&part.code);
        }
    }
    program
}
