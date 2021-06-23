// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Module that defines common data structures used by both the library crate
//! and seccompiler-bin.

use serde::{Deserialize, Serialize};

/// The maximum seccomp-BPF program length allowed by the linux kernel.
pub(crate) const BPF_MAX_LEN: usize = 4096;

/// BPF instruction structure definition.
/// See /usr/include/linux/filter.h .
#[repr(C)]
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[doc(hidden)]
pub struct sock_filter {
    pub code: ::std::os::raw::c_ushort,
    pub jt: ::std::os::raw::c_uchar,
    pub jf: ::std::os::raw::c_uchar,
    pub k: ::std::os::raw::c_uint,
}

/// Program made up of a sequence of BPF instructions.
pub type BpfProgram = Vec<sock_filter>;
