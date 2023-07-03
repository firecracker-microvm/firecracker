// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;

use utils::vm_memory::ByteValued;

use crate::io_uring::bindings::io_uring_cqe;

// SAFETY: Struct is POD and contains no references or niches.
unsafe impl ByteValued for io_uring_cqe {}

/// Wrapper over a completed operation.
#[derive(Debug)]
pub struct Cqe<T> {
    res: i32,
    user_data: Box<T>,
}

impl<T: Debug> Cqe<T> {
    /// Construct a Cqe object from a raw `io_uring_cqe`.
    ///
    /// # Safety
    /// Unsafe because we assume full ownership of the inner.user_data address.
    /// We assume that it points to a valid address created with a Box<T>, with the correct type T,
    /// and that ownership of that address is passed to this function.
    pub(crate) unsafe fn new(inner: io_uring_cqe) -> Self {
        Self {
            res: inner.res,
            user_data: Box::from_raw(inner.user_data as *mut T),
        }
    }

    /// Return the number of bytes successfully transferred by this operation.
    pub fn count(&self) -> u32 {
        u32::try_from(self.res).unwrap_or(0)
    }

    /// Return the result associated to the IO operation.
    pub fn result(&self) -> Result<u32, std::io::Error> {
        let res = self.res;

        if res < 0 {
            Err(std::io::Error::from_raw_os_error(res))
        } else {
            Ok(u32::try_from(self.res).unwrap())
        }
    }

    /// Create a new Cqe, applying the passed function to the user_data.
    pub fn map_user_data<U: Debug, F: FnOnce(T) -> U>(self, op: F) -> Cqe<U> {
        Cqe {
            res: self.res,
            user_data: Box::new(op(self.user_data())),
        }
    }

    /// Consume the object and return the user_data.
    pub fn user_data(self) -> T {
        *self.user_data
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]
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
