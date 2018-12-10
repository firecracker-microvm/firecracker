// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use seccomp::{Error, SeccompFilterContext};

pub const ALLOWED_SYSCALLS: &[i64] = &[];

pub fn default_context() -> Result<SeccompFilterContext, Error> {
    Ok(seccomp::SeccompFilterContext::new(
        vec![].into_iter().collect(),
        seccomp::SeccompAction::Trap,
    )
    .unwrap())
}

pub fn set_seccomp_level(seccomp_level: u32) -> Result<(), Error> {
    Ok(())
}
