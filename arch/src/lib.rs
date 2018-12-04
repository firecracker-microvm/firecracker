// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate byteorder;
extern crate kvm_wrapper;
extern crate libc;

extern crate arch_gen;
extern crate kvm;
extern crate memory_model;
extern crate sys_util;

use std::result;

#[derive(Debug, PartialEq)]
pub enum Error {
    /// The zero page extends past the end of guest_mem.
    ZeroPagePastRamEnd,
    /// Error writing the zero page of guest memory.
    ZeroPageSetup,
    #[cfg(target_arch = "x86_64")]
    /// X86_64 specific error triggered during system configuration.
    X86_64Setup(x86_64::Error),
}
pub type Result<T> = result::Result<T, Error>;

// 1MB.  We don't put anything above here except the kernel itself.
pub const HIMEM_START: usize = 0x100000;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;
impl From<x86_64::Error> for Error {
    fn from(e: x86_64::Error) -> Error {
        Error::X86_64Setup(e)
    }
}
