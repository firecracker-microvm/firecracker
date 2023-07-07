// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{self, Debug};

use utils::vm_memory::ByteValued;

use crate::io_uring::bindings::io_uring_sqe;

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

    /// Consume the sqe and return the `user_data`.
    ///
    /// # Safety
    /// Safe only if you guarantee that this is a valid pointer to some memory where there is a
    /// value of type T created from a Box<T>.
    pub(crate) unsafe fn user_data<T: Debug>(self) -> T {
        *Box::from_raw(self.0.user_data as *mut T)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]
    use super::*;
    #[test]
    fn test_user_data() {
        let user_data = Box::new(10u8);
        let mut inner: io_uring_sqe = unsafe { std::mem::zeroed() };
        inner.user_data = Box::into_raw(user_data) as u64;

        let sqe: Sqe = Sqe::new(inner);

        assert_eq!(unsafe { sqe.user_data::<u8>() }, 10);
    }
}
