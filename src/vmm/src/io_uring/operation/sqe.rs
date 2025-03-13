// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{self};

use crate::io_uring::generated::io_uring_sqe;
use crate::vstate::memory::ByteValued;

// SAFETY: Struct is POD and contains no references or niches.
unsafe impl ByteValued for io_uring_sqe {}

/// Newtype wrapper over a raw sqe.
pub(crate) struct Sqe(pub(crate) io_uring_sqe);

impl fmt::Debug for Sqe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sqe").finish()
    }
}

impl Sqe {
    /// Construct a new sqe.
    pub(crate) fn new(inner: io_uring_sqe) -> Self {
        Self(inner)
    }

    /// Return the key to the `user_data` stored in slab.
    pub(crate) fn user_data(&self) -> u64 {
        self.0.user_data
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]
    use super::*;
    #[test]
    fn test_user_data() {
        let user_data = 10_u64;
        let mut inner: io_uring_sqe = unsafe { std::mem::zeroed() };
        inner.user_data = user_data;

        let sqe: Sqe = Sqe::new(inner);
        assert_eq!(sqe.user_data(), 10);
    }
}
