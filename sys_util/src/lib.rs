// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Small system utility modules for usage by other modules.

extern crate data_model;
extern crate libc;
extern crate syscall_defines;

#[macro_use]
pub mod handle_eintr;
#[macro_use]
pub mod ioctl;
#[macro_use]
pub mod syslog;
mod mmap;
mod shm;
mod eventfd;
mod errno;
mod guest_address;
mod guest_memory;
mod poll;
mod struct_util;
mod tempdir;
mod terminal;
mod signal;
mod sock_ctrl_msg;
mod passwd;

pub use mmap::*;
pub use shm::*;
pub use eventfd::*;
pub use errno::{Error, Result};
pub use errno::errno_result;
pub use guest_address::*;
pub use guest_memory::*;
pub use poll::*;
pub use struct_util::*;
pub use tempdir::*;
pub use terminal::*;
pub use signal::*;
pub use ioctl::*;
pub use sock_ctrl_msg::*;
pub use passwd::*;

pub use mmap::Error as MmapError;
pub use guest_memory::Error as GuestMemoryError;

use std::ffi::CStr;
use std::ptr;

use libc::{c_long, gid_t, kill, pid_t, syscall, uid_t, waitpid, SIGKILL, WNOHANG};

use syscall_defines::linux::LinuxSyscall::SYS_getpid;

/// This bypasses `libc`'s caching `getpid(2)` wrapper which can be invalid if a raw clone was used
/// elsewhere.
#[inline(always)]
pub fn getpid() -> pid_t {
    // Safe because this syscall can never fail and we give it a valid syscall number.
    unsafe { syscall(SYS_getpid as c_long) as pid_t }
}

/// Safe wrapper for `geteuid(2)`.
#[inline(always)]
pub fn geteuid() -> uid_t {
    // trivially safe
    unsafe { libc::geteuid() }
}

/// Safe wrapper for `getegid(2)`.
#[inline(always)]
pub fn getegid() -> gid_t {
    // trivially safe
    unsafe { libc::getegid() }
}

/// Safe wrapper for chown(2).
#[inline(always)]
pub fn chown(path: &CStr, uid: uid_t, gid: gid_t) -> Result<()> {
    // Safe since we pass in a valid string pointer and check the return value.
    let ret = unsafe { libc::chown(path.as_ptr(), uid, gid) };

    if ret < 0 {
        errno_result()
    } else {
        Ok(())
    }
}

/// Reaps a child process that has terminated.
///
/// Returns `Ok(pid)` where `pid` is the process that was reaped or `Ok(0)` if none of the children
/// have terminated. An `Error` is with `errno == ECHILD` if there are no children left to reap.
///
/// # Examples
///
/// Reaps all child processes until there are no terminated children to reap.
///
/// ```
/// # extern crate libc;
/// # extern crate sys_util;
/// fn reap_children() {
///     loop {
///         match sys_util::reap_child() {
///             Ok(0) => println!("no children ready to reap"),
///             Ok(pid) => {
///                 println!("reaped {}", pid);
///                 continue
///             },
///             Err(e) if e.errno() == libc::ECHILD => println!("no children left"),
///             Err(e) => println!("error reaping children: {:?}", e),
///         }
///         break
///     }
/// }
/// ```
pub fn reap_child() -> Result<pid_t> {
    // Safe because we pass in no memory, prevent blocking with WNOHANG, and check for error.
    let ret = unsafe { waitpid(-1, ptr::null_mut(), WNOHANG) };
    if ret == -1 {
        errno_result()
    } else {
        Ok(ret)
    }
}

/// Kill all processes in the current process group.
///
/// On success, this kills all processes in the current process group, including the current
/// process, meaning this will not return. This is equivalent to a call to `kill(0, SIGKILL)`.
pub fn kill_process_group() -> Result<()> {
    let ret = unsafe { kill(0, SIGKILL) };
    if ret == -1 {
        errno_result()
    } else {
        // Kill succeeded, so this process never reaches here.
        unreachable!();
    }
}
