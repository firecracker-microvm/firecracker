// Copyright 2019 UCloud.cn, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use memory_model::GuestMemoryError;
use std::ffi::FromBytesWithNulError;
use std::io;

#[derive(Debug)]
pub enum ExecuteError {
    InvalidMethod,
    IllegalParameter,
    MemoryError,
    UnknownHandle,
    OSError(i32),
    UnknownError,
}

impl From<FromBytesWithNulError> for ExecuteError {
    fn from(_: FromBytesWithNulError) -> ExecuteError {
        ExecuteError::IllegalParameter
    }
}

impl From<io::Error> for ExecuteError {
    fn from(e: io::Error) -> ExecuteError {
        match e.raw_os_error() {
            Some(i) => ExecuteError::OSError(i),
            None => ExecuteError::UnknownError,
        }
    }
}

impl From<GuestMemoryError> for ExecuteError {
    fn from(_: GuestMemoryError) -> ExecuteError {
        ExecuteError::MemoryError
    }
}
