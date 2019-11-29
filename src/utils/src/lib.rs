// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
#[macro_use]
extern crate vmm_sys_util;

pub use vmm_sys_util::{errno, eventfd, ioctl, signal, terminal};

pub mod net;
pub mod rand;
pub mod structs;
pub mod time;
pub mod validators;

/// Wrapper to interpret syscall exit codes and provide a rustacean `io::Result`
pub struct SyscallReturnCode(pub std::os::raw::c_int);
impl SyscallReturnCode {
    /// Returns the last OS error if value is -1 or Ok(value) otherwise.
    pub fn into_result(self) -> std::io::Result<std::os::raw::c_int> {
        if self.0 == -1 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(self.0)
        }
    }

    /// Returns the last OS error if value is -1 or Ok(()) otherwise.
    pub fn into_empty_result(self) -> std::io::Result<()> {
        self.into_result().map(|_| ())
    }
}
