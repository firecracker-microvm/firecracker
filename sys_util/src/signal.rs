// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use libc::{c_int, pthread_kill, pthread_t, signal, EINVAL, SIG_ERR};

use std::thread::JoinHandle;
use std::os::unix::thread::JoinHandleExt;

use {errno_result, Error, Result};

#[link(name = "c")]
extern "C" {
    fn __libc_current_sigrtmin() -> c_int;
    fn __libc_current_sigrtmax() -> c_int;
}

/// Returns the minimum (inclusive) real-time signal number.
#[allow(non_snake_case)]
fn SIGRTMIN() -> c_int {
    unsafe { __libc_current_sigrtmin() }
}

/// Returns the maximum (inclusive) real-time signal number.
#[allow(non_snake_case)]
fn SIGRTMAX() -> c_int {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    extern "C" fn handle_signal() {}

    #[test]
    fn test_register_signal_handler() {
        // testing bad value
        unsafe {
            assert!(register_signal_handler(SIGRTMAX() as u8, handle_signal).is_err());
            format!(
                "{:?}",
                register_signal_handler(SIGRTMAX() as u8, handle_signal)
            );
        }

        unsafe {
            assert!(register_signal_handler(0, handle_signal).is_ok());
        }
    }

    #[test]
    fn test_killing_thread() {
        let killable = thread::spawn(|| thread::current().id());
        let killable_id = killable.join().unwrap();
        assert!(killable_id != thread::current().id());
        let killable = thread::spawn(|| loop {});
        let res = killable.kill(SIGRTMAX() as u8);
        assert!(res.is_err());
        format!("{:?}", res);
        assert!(killable.kill(0).is_ok());
    }
}
