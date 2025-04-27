// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use libc::c_int;
pub use vmm_sys_util::signal::*;

// SAFETY: these are valid libc functions
unsafe extern "C" {
    // SAFETY: Function has no invariants that can be broken.
    safe fn __libc_current_sigrtmin() -> c_int;

    // SAFETY: Function has no invariants that can be broken.
    safe fn __libc_current_sigrtmax() -> c_int;
}

/// Sigrtmin
pub fn sigrtmin() -> c_int {
    __libc_current_sigrtmin()
}

/// Sigrtmax
pub fn sigrtmax() -> c_int {
    __libc_current_sigrtmax()
}
