// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Small system utility modules for usage by other modules.

extern crate data_model;
extern crate libc;
extern crate syscall_defines;

#[macro_use]
pub mod ioctl;

mod errno;
mod eventfd;
mod guest_address;
mod guest_memory;
mod mmap;
mod signal;
mod struct_util;
mod tempdir;
mod terminal;

pub use errno::{errno_result, Error, Result};
pub use eventfd::*;
pub use guest_address::*;
pub use guest_memory::*;
pub use ioctl::*;
pub use mmap::*;
pub use signal::*;
pub use struct_util::*;
pub use tempdir::*;
pub use terminal::*;

pub use guest_memory::Error as GuestMemoryError;
pub use mmap::Error as MmapError;
