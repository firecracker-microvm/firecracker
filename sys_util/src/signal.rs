// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::{errno_result, Error, Result};
use libc::{c_int, c_void, pthread_kill, pthread_t, sigaction, siginfo_t, signal, EINVAL,
           SA_SIGINFO, SIGHUP, SIGSYS, SIG_ERR};
use std::mem;
use std::os::unix::thread::JoinHandleExt;
use std::thread::JoinHandle;

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

fn valid_rt_signal_num(num: u8) -> bool {
    (num as c_int) + SIGRTMIN() <= SIGRTMAX()
}

/// Registers `handler` as the signal handler of signum `num + SIGRTMIN`.
///
/// The value of `num + SIGRTMIN` must not exceed `SIGRTMAX`.
///
/// This is considered unsafe because the given handler will be called asynchronously, interrupting
/// whatever the thread was doing and therefore must only do async-signal-safe operations.
pub unsafe fn register_signal_handler(num: u8, handler: extern "C" fn() -> ()) -> Result<()> {
    if !valid_rt_signal_num(num) {
        return Err(Error::new(EINVAL));
    }
    let ret = signal((num as i32) + SIGRTMIN(), handler as *const () as usize);
    if ret == SIG_ERR {
        return errno_result();
    }

    Ok(())
}

fn valid_signal_num(num: c_int) -> bool {
    SIGHUP <= num && num <= SIGSYS
}

/// Registers `handler` as the signal handler of signum `num`.
///
/// Uses `sigaction` to register the handler.
///
/// This is considered unsafe because the given handler will be called asynchronously, interrupting
/// whatever the thread was doing and therefore must only do async-signal-safe operations.
pub unsafe fn register_signal_handler_sigaction(
    num: i32,
    handler: extern "C" fn(num: c_int, info: *mut siginfo_t, _unused: *mut c_void) -> (),
) -> Result<()> {
    if !valid_signal_num(num) {
        return Err(Error::new(EINVAL));
    }
    let mut act: sigaction = mem::zeroed();
    act.sa_sigaction = handler as *const () as usize;
    act.sa_flags = SA_SIGINFO;
    match sigaction(num, &act, ::std::ptr::null_mut()) {
        0 => Ok(()),
        _ => errno_result(),
    }
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
        if !valid_rt_signal_num(num) {
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
    use libc;
    use std::thread;
    use std::time::Duration;

    static mut SIGNAL_HANDLER_CALLED: bool = false;
    static mut SIGNAL_CAUGHT: c_int = -1;

    extern "C" fn handle_signal() {
        unsafe {
            SIGNAL_HANDLER_CALLED = true;
        }
    }

    extern "C" fn handle_signal_sigaction(num: c_int, _: *mut siginfo_t, _: *mut c_void) {
        unsafe {
            SIGNAL_CAUGHT = num;
        }
    }

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
    fn test_register_signal_handler_sigaction() {
        unsafe {
            assert!(
                register_signal_handler_sigaction(libc::SIGSYS, handle_signal_sigaction).is_ok()
            );
        }
    }

    #[test]
    fn test_killing_thread() {
        let killable = thread::spawn(|| thread::current().id());
        let killable_id = killable.join().unwrap();
        assert_ne!(killable_id, thread::current().id());

        // We install a signal handler for the specified signal; otherwise the whole process will
        // be brought down when the signal is received, as part of the default behaviour. Signal
        // handlers are global, so we install this before starting the thread.
        unsafe {
            register_signal_handler(0, handle_signal)
                .expect("failed to register vcpu signal handler");
        }

        let killable = thread::spawn(|| loop {});

        let res = killable.kill(SIGRTMAX() as u8);
        assert!(res.is_err());
        format!("{:?}", res);

        unsafe {
            assert!(!SIGNAL_HANDLER_CALLED);
        }

        assert!(killable.kill(0).is_ok());

        // We're waiting to detect that the signal handler has been called.
        const MAX_WAIT_ITERS: u32 = 20;
        let mut iter_count = 0;
        loop {
            thread::sleep(Duration::from_millis(100));

            if unsafe { SIGNAL_HANDLER_CALLED } {
                break;
            }

            iter_count += 1;
            // timeout if we wait too long
            assert!(iter_count <= MAX_WAIT_ITERS);
        }

        // Our signal handler doesn't do anything which influences the killable thread, so the
        // previous signal is effectively ignored. If we were to join killable here, we would block
        // forever as the loop keeps running. Since we don't join, the thread will become detached
        // as the handle is dropped, and will be killed when the process/main thread exits.
    }
}
