// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "aarch64")]
mod aarch64;

#[cfg(target_arch = "aarch64")]
pub use self::aarch64::{default_filter, set_seccomp_level};
#[cfg(target_arch = "x86_64")]
pub use self::x86_64::{default_filter, set_seccomp_level};
