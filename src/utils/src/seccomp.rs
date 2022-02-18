// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bincode::{DefaultOptions, Options};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;

/// Type that associates a thread category to an `Arc`-ed BPF program.
/// Useful for sharing the same filter across all vcpu threads.
pub type BpfThreadMap = HashMap<String, Arc<seccompiler::BpfProgram>>;

#[repr(C)]
#[derive(Serialize, Deserialize)]
/// We need to reimplement this type locally so that we may derive
/// `Serialize` and `Deserialize` for it.
pub struct sock_filter {
    /// Code of the instruction.
    pub code: ::std::os::raw::c_ushort,
    /// Jump if true offset.
    pub jt: ::std::os::raw::c_uchar,
    /// Jump if false offset.
    pub jf: ::std::os::raw::c_uchar,
    /// Immediate value.
    pub k: ::std::os::raw::c_uint,
}

/// BpfProgram reimplementation using the local sock_filter type.
type BpfProgram = Vec<sock_filter>;

// Implement casting between the our local sock_filter type and the upstream type.
impl From<seccompiler::sock_filter> for sock_filter {
    fn from(f: seccompiler::sock_filter) -> sock_filter {
        sock_filter {
            code: f.code,
            jt: f.jt,
            jf: f.jf,
            k: f.k,
        }
    }
}

// Implement casting between the upstream sock_filter type and our local one.
impl From<sock_filter> for seccompiler::sock_filter {
    fn from(f: sock_filter) -> seccompiler::sock_filter {
        seccompiler::sock_filter {
            code: f.code,
            jt: f.jt,
            jf: f.jf,
            k: f.k,
        }
    }
}

/// Deserialize a BPF file into a collection of usable BPF filters.
/// Has an optional `bytes_limit` that is passed to bincode to constrain the maximum amount of memory
/// that we can allocate while performing the deserialization.
pub fn deserialize_binary<R: Read>(
    reader: R,
    bytes_limit: Option<u64>,
) -> Result<BpfThreadMap, bincode::Error> {
    let result = match bytes_limit {
        // Also add the default options. These are not part of the `DefaultOptions` as per
        // this issue: https://github.com/servo/bincode/issues/333
        Some(limit) => DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_limit(limit)
            .deserialize_from::<R, HashMap<String, BpfProgram>>(reader),
        // No limit is the default.
        None => bincode::deserialize_from::<R, HashMap<String, BpfProgram>>(reader),
    };

    Ok(result?
        .into_iter()
        .map(|(k, v)| {
            (
                k.to_lowercase(),
                Arc::new(v.into_iter().map(|i| i.into()).collect()),
            )
        })
        .collect())
}
