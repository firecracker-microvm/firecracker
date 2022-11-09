// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use libc::c_int;
pub use vmm_sys_util::signal::*;

extern "C" {
    fn __libc_current_sigrtmin() -> c_int;
    fn __libc_current_sigrtmax() -> c_int;
}

pub fn sigrtmin() -> c_int {
    // SAFETY: Function has no invariants that can be broken.
    unsafe { __libc_current_sigrtmin() }
}

pub fn sigrtmax() -> c_int {
    // SAFETY: Function has no invariants that can be broken.
    unsafe { __libc_current_sigrtmax() }
}
