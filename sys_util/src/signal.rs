// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use super::SyscallReturnCode;
use libc::{
    c_int, c_void, pthread_kill, pthread_t, sigaction, sigfillset, siginfo_t, sigset_t, EINVAL,
};
use std::io;
use std::mem;
use std::os::unix::thread::JoinHandleExt;
use std::ptr::null_mut;
use std::thread::JoinHandle;

/// Type that represents a signal handler function.
pub type SignalHandler =
    extern "C" fn(num: c_int, info: *mut siginfo_t, _unused: *mut c_void) -> ();

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

/// Verifies that a signal number is valid.
///
/// VCPU signals need to have values enclosed within the OS limits for realtime signals.
///
/// Will return Ok(num) or Err(EINVAL).
pub fn validate_vcpu_signal_num(num: c_int) -> io::Result<c_int> {
    let actual_num = num + SIGRTMIN();
    if actual_num <= SIGRTMAX() {
        Ok(actual_num)
    } else {
        Err(io::Error::from_raw_os_error(EINVAL))
    }
}

/// Registers `handler` as the vCPU's signal handler of signum `num`.
///
/// This is considered unsafe because the given handler will be called asynchronously, interrupting
/// whatever the thread was doing and therefore must only do async-signal-safe operations.
pub unsafe fn register_vcpu_signal_handler(num: i32, handler: SignalHandler) -> io::Result<()> {
    let num = validate_vcpu_signal_num(num)?;
    // Safe, because this is a POD struct.
    let mut sigact: sigaction = mem::zeroed();
    sigact.sa_flags = libc::SA_SIGINFO;
    sigact.sa_sigaction = handler as usize;
    SyscallReturnCode(sigaction(num, &sigact, null_mut())).into_empty_result()
}

/// Registers the specified signal handler for `SIGSYS`.
pub fn register_sigsys_handler(sigsys_handler: SignalHandler) -> Result<(), io::Error> {
    // Safe, because this is a POD struct.
    let mut sigact: sigaction = unsafe { mem::zeroed() };
    sigact.sa_flags = libc::SA_SIGINFO;
    sigact.sa_sigaction = sigsys_handler as usize;

    // We set all the bits of sa_mask, so all signals are blocked on the current thread while the
    // SIGSYS handler is executing. Safe because the parameter is valid and we check the return
    // value.
    if unsafe { sigfillset(&mut sigact.sa_mask as *mut sigset_t) } < 0 {
        return Err(io::Error::last_os_error());
    }

    // Safe because the parameters are valid and we check the return value.
    unsafe { SyscallReturnCode(sigaction(libc::SIGSYS, &sigact, null_mut())).into_empty_result() }
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
    fn kill(&self, num: i32) -> io::Result<()> {
        let num = validate_vcpu_signal_num(num)?;

        // Safe because we ensure we are using a valid pthread handle, a valid signal number, and
        // check the return result.
        SyscallReturnCode(unsafe { pthread_kill(self.pthread_handle(), num) }).into_empty_result()
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
    use std::time::Duration;

    static mut SIGNAL_HANDLER_CALLED: bool = false;

    extern "C" fn handle_signal(_: c_int, _: *mut siginfo_t, _: *mut c_void) {
        unsafe {
            SIGNAL_HANDLER_CALLED = true;
        }
    }

    #[test]
    fn test_register_signal_handler() {
        unsafe {
            // testing bad value
            assert!(register_vcpu_signal_handler(SIGRTMAX(), handle_signal).is_err());
            assert!(register_vcpu_signal_handler(0, handle_signal).is_ok());
            assert!(register_sigsys_handler(handle_signal).is_ok());
        }
    }

    #[test]
    #[allow(clippy::empty_loop)]
    fn test_killing_thread() {
        let killable = thread::spawn(|| thread::current().id());
        let killable_id = killable.join().unwrap();
        assert_ne!(killable_id, thread::current().id());

        // We install a signal handler for the specified signal; otherwise the whole process will
        // be brought down when the signal is received, as part of the default behaviour. Signal
        // handlers are global, so we install this before starting the thread.
        unsafe {
            register_vcpu_signal_handler(0, handle_signal)
                .expect("failed to register vcpu signal handler");
        }

        let killable = thread::spawn(|| loop {});

        let res = killable.kill(SIGRTMAX());
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
