// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;

use crate::io_uring::generated::io_uring_cqe;
use crate::vstate::memory::ByteValued;

// SAFETY: Struct is POD and contains no references or niches.
unsafe impl ByteValued for io_uring_cqe {}

/// Wrapper over a completed operation.
#[derive(Debug)]
pub struct Cqe<T> {
    res: i32,
    user_data: T,
}

impl<T: Debug> Cqe<T> {
    /// Construct a Cqe object.
    pub fn new(res: i32, user_data: T) -> Self {
        Self { res, user_data }
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
            user_data: op(self.user_data()),
        }
    }

    /// Consume the object and return the user_data.
    pub fn user_data(self) -> T {
        self.user_data
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
            let user_data = 10_u8;
            let cqe: Cqe<u8> = Cqe::new(-22, user_data);

            assert_eq!(
                cqe.result().unwrap_err().kind(),
                std::io::Error::from_raw_os_error(-22).kind()
            );
        }

        // Check that `result()` returns Ok() when `res` is positive.
        {
            let user_data = 10_u8;
            let cqe: Cqe<u8> = Cqe::new(128, user_data);

            assert_eq!(cqe.result().unwrap(), 128);
        }
    }

    #[test]
    fn test_user_data() {
        let user_data = 10_u8;
        let cqe: Cqe<u8> = Cqe::new(0, user_data);

        assert_eq!(cqe.user_data(), 10);
    }

    #[test]
    fn test_map_user_data() {
        let user_data = 10_u8;
        let cqe: Cqe<u8> = Cqe::new(0, user_data);
        let cqe = cqe.map_user_data(|x| x + 1);

        assert_eq!(cqe.user_data(), 11);
    }
}
