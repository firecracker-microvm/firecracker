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

use crate::io_uring::bindings;
use crate::io_uring::operation::OpCode;

/// Adds support for restricting the operations allowed by io_uring.
#[derive(Debug)]
pub enum Restriction {
    /// Allow an operation.
    AllowOpCode(OpCode),
    /// Only allow operations on pre-registered fds.
    RequireFixedFds,
}

impl From<&Restriction> for bindings::io_uring_restriction {
    fn from(restriction: &Restriction) -> Self {
        use Restriction::*;

        // SAFETY: Safe because it only contains integer values.
        let mut instance: Self = unsafe { std::mem::zeroed() };

        match restriction {
            AllowOpCode(opcode) => {
                instance.opcode = bindings::IORING_RESTRICTION_SQE_OP as u16;
                instance.__bindgen_anon_1.sqe_op = *opcode as u8;
            }
            RequireFixedFds => {
                instance.opcode = bindings::IORING_RESTRICTION_SQE_FLAGS_REQUIRED as u16;
                instance.__bindgen_anon_1.sqe_flags = 1 << bindings::IOSQE_FIXED_FILE_BIT;
            }
        };

        instance
    }
}
