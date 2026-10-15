// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The compiled seccomp filter format shared by seccompiler, which writes it, and Firecracker,
//! which reads it, together with the microVM features the rules of a filter can be tagged with.
//!
//! Firecracker links this crate, so it must never depend on libseccomp, and therefore not on
//! seccompiler either.

mod features;
mod filter;
mod format;

pub use features::{SeccompFeature, SeccompFeatures, UnknownSeccompFeature};
pub use filter::{FilterError, FilterFragment, SeccompFilter};
pub use format::{
    BpfFilter, BpfFragment, BpfMap, FORMAT_MAGIC, FORMAT_VERSION, FormatError, MAX_ENCODED_SIZE,
    decode, encode,
};
