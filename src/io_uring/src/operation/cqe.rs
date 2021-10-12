// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::bindings::io_uring_cqe;
use std::result::Result;
use vm_memory::ByteValued;

unsafe impl ByteValued for io_uring_cqe {}

pub struct Cqe<T> {
    inner: io_uring_cqe,
    user_data: Box<T>,
}

impl<T> Cqe<T> {
    /// # Safety
    /// Unsafe because we assume full ownership of the inner.user_data address.
    /// We assume that it points to a valid address created with a Box<T>, with the correct type T,
    /// and that ownership of that address is passed to this function.
    pub unsafe fn new(inner: io_uring_cqe) -> Self {
        Self {
            inner,
            user_data: Box::from_raw(inner.user_data as *mut T),
        }
    }

    pub fn result(&self) -> Result<u32, std::io::Error> {
        let res = self.inner.res;

        if res < 0 {
            Err(std::io::Error::from_raw_os_error(res))
        } else {
            Ok(res as u32)
        }
    }

    pub fn user_data(self) -> T {
        *self.user_data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_result() {
        // Check that `result()` returns an `Error` when `res` is negative.
        {
            let user_data = Box::new(10u8);

            let cqe: Cqe<u8> = unsafe {
                Cqe::new(io_uring_cqe {
                    user_data: Box::into_raw(user_data) as u64,
                    res: -22,
                    flags: 0,
                })
            };

            assert_eq!(
                cqe.result().unwrap_err().kind(),
                std::io::Error::from_raw_os_error(-22).kind()
            );
        }

        // Check that `result()` returns Ok() when `res` is positive.
        {
            let user_data = Box::new(10u8);

            let cqe: Cqe<u8> = unsafe {
                Cqe::new(io_uring_cqe {
                    user_data: Box::into_raw(user_data) as u64,
                    res: 128,
                    flags: 0,
                })
            };

            assert_eq!(cqe.result().unwrap(), 128);
        }
    }

    #[test]
    fn test_user_data() {
        let user_data = Box::new(10u8);

        let cqe: Cqe<u8> = unsafe {
            Cqe::new(io_uring_cqe {
                user_data: Box::into_raw(user_data) as u64,
                res: 0,
                flags: 0,
            })
        };

        assert_eq!(cqe.user_data(), 10);
    }
}
