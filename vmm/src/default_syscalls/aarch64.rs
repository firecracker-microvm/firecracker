// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use seccomp::{Error, SeccompFilterContext};

/// The default context containing the white listed syscall rules required by `Firecracker` to
/// function.
pub fn default_context() -> Result<SeccompFilterContext, Error> {
    Ok(seccomp::SeccompFilterContext::new(
        vec![].into_iter().collect(),
        seccomp::SeccompAction::Trap,
    )
    .unwrap())
}

/// Applies the configured level of seccomp filtering to the current thread.
pub fn set_seccomp_level(_seccomp_level: u32) -> Result<(), Error> {
    Ok(())
}
