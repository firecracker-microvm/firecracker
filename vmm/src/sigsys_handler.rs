// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate logger;
extern crate sys_util;

use std::io;
use std::mem;
use std::ptr::null_mut;
use std::result::Result;

use libc::{sigaction, sigfillset, sigset_t};

use logger::{Metric, LOGGER, METRICS};

// The offset of `si_syscall` (offending syscall identifier) within the siginfo structure
// expressed as an `(u)int*`.
// Offset `6` for an `i32` field means that the needed information is located at `6 * sizeof(i32)`.
// See /usr/include/linux/signal.h for the C struct definition.
// See https://github.com/rust-lang/libc/issues/716 for why the offset is different in Rust.
const SI_OFF_SYSCALL: isize = 6;

const SYS_SECCOMP_CODE: i32 = 1;

// This no longer relies on sys_util::register_signal_handler(), which is a lot weirder than it
// should be (at least for this use case). Also, we want to change the sa_mask field of the
// sigaction struct.
/// Sets up the specified signal handler for `SIGSYS`.
pub fn setup_sigsys_handler() -> Result<(), io::Error> {
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
    if unsafe { sigaction(libc::SIGSYS, &sigact, null_mut()) } < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

extern "C" fn sigsys_handler(
    num: libc::c_int,
    info: *mut libc::siginfo_t,
    _unused: *mut libc::c_void,
) {
    // Safe because we're just reading some fields from a supposedly valid argument.
    let si_signo = unsafe { (*info).si_signo };
    let si_code = unsafe { (*info).si_code };

    // Sanity check. The condition should never be true.
    if num != si_signo || num != libc::SIGSYS || si_code != SYS_SECCOMP_CODE as i32 {
        // Safe because we're terminating the process anyway.
        unsafe { libc::_exit(i32::from(super::FC_EXIT_CODE_UNEXPECTED_ERROR)) };
    }

    // Other signals which might do async unsafe things incompatible with the rest of this
    // function are blocked due to the sa_mask used when registering the signal handler.
    let syscall = unsafe { *(info as *const i32).offset(SI_OFF_SYSCALL) as usize };
    METRICS.seccomp.num_faults.inc();
    METRICS.seccomp.bad_syscalls[syscall].inc();
    error!(
        "Shutting down VM after intercepting a bad syscall ({}).",
        syscall
    );
    // Log the metrics before exiting.
    if let Err(e) = LOGGER.log_metrics() {
        error!("Failed to log metrics while stopping: {}", e);
    }

    // Safe because we're terminating the process anyway. We don't actually do anything when
    // running unit tests.
    #[cfg(not(test))]
    unsafe {
        libc::_exit(i32::from(super::FC_EXIT_CODE_BAD_SYSCALL))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::mem;
    use std::process;

    use libc::cpu_set_t;

    use seccomp::{setup_seccomp, SeccompLevel};

    // This function is used when running unit tests, so all the unsafes are safe.
    fn cpu_count() -> usize {
        let mut cpuset: cpu_set_t = unsafe { mem::zeroed() };
        unsafe {
            libc::CPU_ZERO(&mut cpuset);
        }
        let ret = unsafe {
            libc::sched_getaffinity(
                0,
                mem::size_of::<cpu_set_t>(),
                &mut cpuset as *mut cpu_set_t,
            )
        };
        assert_eq!(ret, 0);

        let mut num = 0;
        for i in 0..libc::CPU_SETSIZE as usize {
            if unsafe { libc::CPU_ISSET(i, &cpuset) } {
                num += 1;
            }
        }
        num
    }

    #[test]
    fn test_signal_handler() {
        assert!(setup_sigsys_handler().is_ok());

        // Syscalls that have to be allowed in order for the test to work.
        const REQUIRED_SYSCALLS: &[i64] = &[
            libc::SYS_brk,
            libc::SYS_exit,
            libc::SYS_futex,
            libc::SYS_munmap,
            libc::SYS_rt_sigprocmask,
            libc::SYS_rt_sigreturn,
            libc::SYS_sched_getaffinity,
            libc::SYS_set_tid_address,
            libc::SYS_sigaltstack,
            libc::SYS_write,
        ];

        assert!(setup_seccomp(SeccompLevel::Basic(REQUIRED_SYSCALLS)).is_ok());
        let sys_idx = libc::SYS_getpid as usize;
        assert_eq!(METRICS.seccomp.bad_syscalls[sys_idx].count(), 0);

        // Calls the blacklisted SYS_getpid.
        let _pid = process::id();

        assert!(cpu_count() > 0);

        // Kcov somehow messes with our handler getting the SIGSYS signal when a bad syscall
        // is caught, so the following assertion no longer holds. Ideally, we'd have a surefire
        // way of either preventing this behaviour, or detecting for certain whether this test is
        // run by kcov or not. The best we could do so far is to look at the perceived number of
        // available CPUs. Kcov seems to make a single CPU available to the process running the
        // tests, so we use this as an heuristic to decide if we check the assertion.
        if cpu_count() > 1 {
            // The signal handler should let the program continue during unit tests.
            assert_eq!(METRICS.seccomp.bad_syscalls[sys_idx].count(), 1);
        }
    }
}
