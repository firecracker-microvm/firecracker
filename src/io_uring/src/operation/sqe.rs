// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vm_memory::ByteValued;

use crate::bindings::io_uring_sqe;

unsafe impl ByteValued for io_uring_sqe {}

pub(crate) struct Sqe(pub(crate) io_uring_sqe);

impl Sqe {
    pub(crate) fn new(inner: io_uring_sqe) -> Self {
        Self(inner)
    }

    /// # Safety
    /// Safe only if you guarantee that this is a valid pointer to some memory where there is a
    /// value of type T created from a Box<T>.
    pub(crate) unsafe fn user_data<T>(self) -> T {
        *Box::from_raw(self.0.user_data as *mut T)
    }
}

#[cfg(test)]
mod tests {
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
