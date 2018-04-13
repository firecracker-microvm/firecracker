// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Small system utility modules for usage by other modules.

extern crate data_model;
extern crate libc;
extern crate syscall_defines;

#[macro_use]
pub mod ioctl;

mod mmap;
mod eventfd;
mod errno;
mod guest_address;
mod guest_memory;
mod struct_util;
mod tempdir;
mod terminal;
mod signal;

pub use mmap::*;
pub use eventfd::*;
pub use errno::{Error, Result};
pub use errno::errno_result;
pub use guest_address::*;
pub use guest_memory::*;
pub use struct_util::*;
pub use tempdir::*;
pub use terminal::*;
pub use signal::*;
pub use ioctl::*;
pub use libc_ioctl::*;

pub use mmap::Error as MmapError;
pub use guest_memory::Error as GuestMemoryError;

use libc::{c_long, pid_t, syscall};

use syscall_defines::linux::LinuxSyscall::SYS_getpid;

/// This bypasses `libc`'s caching `getpid(2)` wrapper which can be invalid if a raw clone was used
/// elsewhere.
/// TODO(dpopa@): get rid of this when syslog is gone too
#[inline(always)]
pub fn getpid() -> pid_t {
    // Safe because this syscall can never fail and we give it a valid syscall number.
    unsafe { syscall(SYS_getpid as c_long) as pid_t }
}
