// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Seccomp-like restrictions for the allowed operations on an IoUring instance.
//!
//! One can configure the restrictions to only allow certain operations and/or allow only ops on
//! registered files.
//! If passed to the [`IoUring`] constructor, they take effect immediately and can never be
//! deactivated.
//!
//! [`IoUring`]: ../struct.IoUring.html

use std::convert::From;

use crate::io_uring::generated::{
    io_uring_register_restriction_op, io_uring_restriction, io_uring_sqe_flags_bit,
};
use crate::io_uring::operation::OpCode;

/// Adds support for restricting the operations allowed by io_uring.
#[derive(Debug)]
pub enum Restriction {
    /// Allow an operation.
    AllowOpCode(OpCode),
    /// Allow operations to be forced into the kernel's async worker pool (`IOSQE_ASYNC`).
    AllowAsync,
    /// Only allow operations on pre-registered fds.
    RequireFixedFds,
}

impl From<&Restriction> for io_uring_restriction {
    fn from(restriction: &Restriction) -> Self {
        use Restriction::*;

        // SAFETY: Safe because it only contains integer values.
        let mut instance: Self = unsafe { std::mem::zeroed() };

        match restriction {
            AllowOpCode(opcode) => {
                instance.opcode =
                    u16::try_from(io_uring_register_restriction_op::IORING_RESTRICTION_SQE_OP)
                        .unwrap();
                instance.__bindgen_anon_1.sqe_op = *opcode as u8;
            }
            AllowAsync => {
                instance.opcode = u16::try_from(
                    io_uring_register_restriction_op::IORING_RESTRICTION_SQE_FLAGS_ALLOWED,
                )
                .unwrap();
                instance.__bindgen_anon_1.sqe_flags = 1 << io_uring_sqe_flags_bit::IOSQE_ASYNC_BIT;
            }
            RequireFixedFds => {
                instance.opcode = u16::try_from(
                    io_uring_register_restriction_op::IORING_RESTRICTION_SQE_FLAGS_REQUIRED,
                )
                .unwrap();
                instance.__bindgen_anon_1.sqe_flags =
                    1 << io_uring_sqe_flags_bit::IOSQE_FIXED_FILE_BIT;
            }
        };

        instance
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]
    use super::*;

    #[test]
    fn test_allow_async() {
        let restriction = io_uring_restriction::from(&Restriction::AllowAsync);

        assert_eq!(
            u32::from(restriction.opcode),
            io_uring_register_restriction_op::IORING_RESTRICTION_SQE_FLAGS_ALLOWED
        );
        assert_eq!(
            unsafe { restriction.__bindgen_anon_1.sqe_flags },
            1 << io_uring_sqe_flags_bit::IOSQE_ASYNC_BIT
        );
    }
}
