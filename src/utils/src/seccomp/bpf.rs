// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Classic BPF instructions used in seccomp filters.

use zerocopy::{FromBytes, Immutable, IntoBytes};

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
