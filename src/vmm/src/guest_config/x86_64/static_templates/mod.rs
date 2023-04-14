// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Definition of static CPU templates using `struct CpuTemplate`.
//
// This crate is temporary until merging this into `vmm` crate.

/// Module with C3 CPU template for x86_64
#[cfg(target_arch = "x86_64")]
pub mod c3;
#[cfg(target_arch = "x86_64")]
pub use c3::c3;

/// Module with T2 CPU template for x86_64
#[cfg(target_arch = "x86_64")]
pub mod t2;
#[cfg(target_arch = "x86_64")]
pub use t2::t2;

/// Module with T2A CPU template for x86_64
#[cfg(target_arch = "x86_64")]
pub mod t2a;
#[cfg(target_arch = "x86_64")]
pub use t2a::t2a;

/// Module with T2CL CPU template for x86_64
#[cfg(target_arch = "x86_64")]
pub mod t2cl;
#[cfg(target_arch = "x86_64")]
pub use t2cl::t2cl;

/// Module with T2S CPU template for x86_64
#[cfg(target_arch = "x86_64")]
pub mod t2s;
#[cfg(target_arch = "x86_64")]
pub use t2s::t2s;
