// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate libc;

extern crate logger;
extern crate sys_util;

use logger::{Metric, METRICS};

// The offset of `si_syscall` (offending syscall identifier) within the siginfo structure
// expressed as an `(u)int*`.
// Offset `6` for an `i32` field means that the needed information is located at `6 * sizeof(i32)`.
// See /usr/include/linux/signal.h for the C struct definition.
// See https://github.com/rust-lang/libc/issues/716 for why the offset is different in Rust.
const SI_OFF_SYSCALL: isize = 6;

/// Sets up the specified signal handler for `SIGSYS`.
///
pub fn setup_sigsys_handler() -> Result<(), sys_util::Error> {
    return unsafe {
        sys_util::register_signal_handler(
            libc::SIGSYS,
            sys_util::SignalHandler::Siginfo(sigsys_handler),
            false,
        )
    };
}

extern "C" fn sigsys_handler(
    num: libc::c_int,
    info: *mut libc::siginfo_t,
    _unused: *mut libc::c_void,
) {
    if num != libc::SIGSYS {
        return;
    }
    let syscall = unsafe { *(info as *const i32).offset(SI_OFF_SYSCALL) as usize };
    METRICS.seccomp.num_faults.inc();
    METRICS.seccomp.bad_syscalls[syscall].inc();
}

#[cfg(test)]
mod tests {
    use super::*;
    use seccomp::{setup_seccomp, SeccompLevel};
    use std::process;

    #[test]
    fn test_signal_handler() {
        assert!(setup_sigsys_handler().is_ok());

        // Syscalls that have to be allowed in order for the test to work.
        const REQUIRED_SYSCALLS: &[i64] = &[
            libc::SYS_exit,
            libc::SYS_futex,
            libc::SYS_munmap,
            libc::SYS_rt_sigprocmask,
            libc::SYS_rt_sigreturn,
            libc::SYS_set_tid_address,
            libc::SYS_sigaltstack,
        ];
        assert!(setup_seccomp(SeccompLevel::Basic(REQUIRED_SYSCALLS)).is_ok());

        // Calls the blacklisted SYS_getpid.
        let _pid = process::id();

        // The signal handler should let the program continue.
        assert!(true);

        // The reason this test doesn't check the failure metrics as well is that the signal handler
        // doesn't work right with kcov - possibly because the process is being pinned to 1 core.
    }
}
