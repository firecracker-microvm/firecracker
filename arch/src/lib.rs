// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![deny(missing_docs)]
//! Implements platform specific functionality.
//! Supported platforms: x86_64 and aarch64.
extern crate byteorder;
extern crate kvm_bindings;
extern crate kvm_ioctls;
extern crate libc;

extern crate arch_gen;
extern crate memory_model;

use std::fmt;
use std::result;

/// Module for aarch64 related functionality.
#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "aarch64")]
pub use aarch64::{
    arch_memory_regions, configure_system, get_kernel_start, get_reserved_mem_addr,
    layout::CMDLINE_MAX_SIZE, layout::IRQ_BASE, layout::IRQ_MAX, Error,
};

/// Module for x86_64 related functionality.
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::{
    arch_memory_regions, configure_system, get_32bit_gap_start as get_reserved_mem_addr,
    get_kernel_start, layout::CMDLINE_MAX_SIZE, layout::IRQ_BASE, layout::IRQ_MAX, Error,
};

/// Type for returning public functions outcome.
pub type Result<T> = result::Result<T, Error>;

/// Types of devices that can get attached to this platform.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Copy)]
pub enum DeviceType {
    /// Device Type: Virtio.
    Virtio(u32),
    /// Device Type: Serial.
    #[cfg(target_arch = "aarch64")]
    Serial,
    /// Device Type: RTC.
    #[cfg(target_arch = "aarch64")]
    RTC,
}

impl fmt::Display for DeviceType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
