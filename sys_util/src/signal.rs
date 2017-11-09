// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use libc::{c_int, pthread_t, signal, pthread_kill, SIG_ERR, EINVAL};

use std::thread::JoinHandle;
use std::os::unix::thread::JoinHandleExt;

use {Error, Result, errno_result};

#[link(name = "c")]
extern "C" {
    fn __libc_current_sigrtmin() -> c_int;
    fn __libc_current_sigrtmax() -> c_int;
}

/// Returns the minimum (inclusive) real-time signal number.
#[allow(non_snake_case)]
pub fn SIGRTMIN() -> c_int {
    unsafe { __libc_current_sigrtmin() }
}

/// Returns the maximum (inclusive) real-time signal number.
#[allow(non_snake_case)]
pub fn SIGRTMAX() -> c_int {
    unsafe { __libc_current_sigrtmax() }
}

fn valid_signal_num(num: u8) -> bool {
    (num as c_int) + SIGRTMIN() <= SIGRTMAX()
}

/// Registers `handler` as the signal handler of signum `num + SIGRTMIN`.
///
/// The value of `num + SIGRTMIN` must not exceed `SIGRTMAX`.
///
/// This is considered unsafe because the given handler will be called asynchronously, interrupting
/// whatever the thread was doing and therefore must only do async-signal-safe operations.
pub unsafe fn register_signal_handler(num: u8, handler: extern "C" fn() -> ()) -> Result<()> {
    if !valid_signal_num(num) {
        return Err(Error::new(EINVAL));
    }
    let ret = signal((num as i32) + SIGRTMIN(), handler as *const () as usize);
    if ret == SIG_ERR {
        return errno_result();
    }

    Ok(())
}

/// Trait for threads that can be signalled via `pthread_kill`.
///
/// Note that this is only useful for signals between SIGRTMIN and SIGRTMAX because these are
/// guaranteed to not be used by the C runtime.
///
/// This is marked unsafe because the implementation of this trait must guarantee that the returned
/// pthread_t is valid and has a lifetime at least that of the trait object.
pub unsafe trait Killable {
    fn pthread_handle(&self) -> pthread_t;

    /// Sends the signal `num + SIGRTMIN` to this killable thread.
    ///
    /// The value of `num + SIGRTMIN` must not exceed `SIGRTMAX`.
    fn kill(&self, num: u8) -> Result<()> {
        if !valid_signal_num(num) {
            return Err(Error::new(EINVAL));
        }

        // Safe because we ensure we are using a valid pthread handle, a valid signal number, and
        // check the return result.
        let ret = unsafe { pthread_kill(self.pthread_handle(), (num as i32) + SIGRTMIN()) };
        if ret < 0 {
            return errno_result();
        }
        Ok(())
    }
}

// Safe because we fulfill our contract of returning a genuine pthread handle.
unsafe impl<T> Killable for JoinHandle<T> {
    fn pthread_handle(&self) -> pthread_t {
        self.as_pthread_t()
    }
}
