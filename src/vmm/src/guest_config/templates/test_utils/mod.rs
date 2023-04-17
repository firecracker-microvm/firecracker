// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Aarch64 sub-module reference for "use" statements
#[cfg(target_arch = "aarch64")]
pub mod aarch64;
/// x86_64 sub-module reference for "use" statements
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

/// The following wildcard imports enables consumers of the test_utils module
/// to not be concerned with the architecture in question.

/// Test data unique to aarch64 platforms
#[cfg(target_arch = "aarch64")]
pub use aarch64::*;
/// Test data unique to x86_64 platforms
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;
