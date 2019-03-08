// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate byteorder;
extern crate kvm_bindings;
extern crate libc;

extern crate arch_gen;
extern crate kvm;
extern crate memory_model;

use std::result;

#[derive(Debug, PartialEq)]
pub enum Error {
    #[cfg(target_arch = "x86_64")]
    /// X86_64 specific error triggered during system configuration.
    X86_64Setup(x86_64::Error),
}
pub type Result<T> = result::Result<T, Error>;

// 1MB.  We don't put anything above here except the kernel itself.
pub const HIMEM_START: usize = 0x0010_0000;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "aarch64")]
pub use aarch64::{
    arch_memory_regions, configure_system, get_reserved_mem_addr, layout::CMDLINE_MAX_SIZE,
    layout::CMDLINE_START,
};

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::{
    arch_memory_regions, configure_system, get_32bit_gap_start as get_reserved_mem_addr,
    layout::CMDLINE_MAX_SIZE, layout::CMDLINE_START, layout::IRQ_BASE, layout::IRQ_MAX,
};
