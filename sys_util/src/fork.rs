// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs;
use std::io;
use std::path::Path;
use std::process;
use std::result;

use errno_result;

use libc::{syscall, SIGCHLD, CLONE_NEWUSER, CLONE_NEWPID, c_long, pid_t};

use syscall_defines::linux::LinuxSyscall::SYS_clone;

/// Controls what namespace `clone_process` will have. See NAMESPACES(7).
#[repr(u32)]
pub enum CloneNamespace {
    /// The new process will inherit the namespace from the old process.
    Inherit = 0,
    /// The new process with be in a new user and PID namespace.
    NewUserPid = CLONE_NEWUSER as u32 | CLONE_NEWPID as u32,
}

#[derive(Debug)]
pub enum CloneError {
    /// There was an error trying to iterate this process's threads.
    IterateTasks(io::Error),
    /// There are multiple threads running. The `usize` indicates how many threads.
    Multithreaded(usize),
    /// There was an error while cloning.
    Sys(::Error),
}

unsafe fn do_clone(flags: i32) -> ::Result<pid_t> {
    // Forking is unsafe, this function must be unsafe as there is no way to guarantee safety
    // without more context about the state of the program.
    let pid = syscall(SYS_clone as c_long, flags | SIGCHLD as i32, 0);
    if pid < 0 {
        errno_result()
    } else {
        Ok(pid as pid_t)
    }
}

fn count_dir_entries<P: AsRef<Path>>(path: P) -> io::Result<usize> {
    Ok(fs::read_dir(path)?.count())
}

/// Clones this process and calls a closure in the new process.
///
/// After `post_clone_cb` returns or panics, the new process exits. Similar to how a `fork` syscall
/// works, the new process is the same as the current process with the exception of the namespace
/// controlled with the `ns` argument.
///
/// # Arguments
/// * `ns` - What namespace the new process will have (see NAMESPACES(7)).
/// * `post_clone_cb` - Callback to run in the new process
pub fn clone_process<F>(ns: CloneNamespace, post_clone_cb: F) -> result::Result<pid_t, CloneError>
    where F: FnOnce()
{
    match count_dir_entries("/proc/self/task") {
        Ok(1) => {}
        Ok(thread_count) => {
            // Test cfg gets a free pass on this because tests generally have multiple independent
            // test threads going.
            let _ = thread_count;
            #[cfg(not(test))]
            return Err(CloneError::Multithreaded(thread_count));
        }
        Err(e) => return Err(CloneError::IterateTasks(e)),
    }
    // Forking is considered unsafe in mutlithreaded programs, but we just checked for other threads
    // in this process. We also only allow valid flags from CloneNamespace and check the return
    // result for errors. We also never let the cloned process return from this function.
    let ret = unsafe { do_clone(ns as i32) }.map_err(CloneError::Sys)?;
    if ret == 0 {
        struct ExitGuard;
        impl Drop for ExitGuard {
            fn drop(&mut self) {
                process::exit(101);
            }
        }
        // Prevents a panic in post_clone_cb from bypassing the process::exit.
        #[allow(unused_variables)]
        let exit_guard = ExitGuard {};
        post_clone_cb();
        // ! Never returns
        process::exit(0);
    }

    Ok(ret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libc;
    use {getpid, EventFd};

    fn wait_process() -> libc::c_int {
        let mut status: libc::c_int = 0;
        unsafe {
            libc::wait(&mut status as *mut libc::c_int);
            libc::WEXITSTATUS(status)
        }
    }

    #[test]
    fn pid_diff() {
        let evt_fd = EventFd::new().expect("failed to create EventFd");
        let evt_fd_fork = evt_fd.try_clone().expect("failed to clone EventFd");
        let pid = getpid();
        clone_process(CloneNamespace::Inherit, || {
            // checks that this is a genuine fork with a new PID
            if pid != getpid() {
                evt_fd_fork.write(1).unwrap()
            } else {
                evt_fd_fork.write(2).unwrap()
            }
        })
                .expect("failed to clone");
        assert_eq!(evt_fd.read(), Ok(1));
    }

    #[test]
    fn panic_safe() {
        let pid = getpid();
        assert_ne!(pid, 0);

        clone_process(CloneNamespace::Inherit, || {
            assert!(false);
        })
                .expect("failed to clone");

        // This should never happen;
        if pid != getpid() {
            process::exit(2);
        }

        let status = wait_process();
        assert!(status == 101 || status == 0);
    }
}
