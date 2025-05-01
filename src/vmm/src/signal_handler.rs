// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use libc::{
    SIGBUS, SIGHUP, SIGILL, SIGPIPE, SIGSEGV, SIGSYS, SIGXCPU, SIGXFSZ, c_int, c_void, siginfo_t,
};
use log::error;

use crate::FcExitCode;
use crate::logger::{IncMetric, METRICS, StoreMetric};
use crate::utils::signal::register_signal_handler;

// The offset of `si_syscall` (offending syscall identifier) within the siginfo structure
// expressed as an `(u)int*`.
// Offset `6` for an `i32` field means that the needed information is located at `6 * sizeof(i32)`.
// See /usr/include/linux/signal.h for the C struct definition.
// See https://github.com/rust-lang/libc/issues/716 for why the offset is different in Rust.
const SI_OFF_SYSCALL: isize = 6;

const SYS_SECCOMP_CODE: i32 = 1;

#[inline]
fn exit_with_code(exit_code: FcExitCode) {
    // Write the metrics before exiting.
    if let Err(err) = METRICS.write() {
        error!("Failed to write metrics while stopping: {}", err);
    }
    // SAFETY: Safe because we're terminating the process anyway.
    unsafe { libc::_exit(exit_code as i32) };
}

macro_rules! generate_handler {
    ($fn_name:ident ,$signal_name:ident, $exit_code:ident, $signal_metric:expr, $body:ident) => {
        #[inline(always)]
        extern "C" fn $fn_name(num: c_int, info: *mut siginfo_t, _unused: *mut c_void) {
            // SAFETY: Safe because we're just reading some fields from a supposedly valid argument.
            let si_signo = unsafe { (*info).si_signo };
            // SAFETY: Safe because we're just reading some fields from a supposedly valid argument.
            let si_code = unsafe { (*info).si_code };

            if num != si_signo || num != $signal_name {
                exit_with_code(FcExitCode::UnexpectedError);
            }
            $signal_metric.store(1);

            error!(
                "Shutting down VM after intercepting signal {}, code {}.",
                si_signo, si_code
            );

            $body(si_code, info);

            match si_signo {
                $signal_name => exit_with_code(crate::FcExitCode::$exit_code),
                _ => exit_with_code(FcExitCode::UnexpectedError),
            };
        }
    };
}

fn log_sigsys_err(si_code: c_int, info: *mut siginfo_t) {
    if si_code != SYS_SECCOMP_CODE {
        // We received a SIGSYS for a reason other than `bad syscall`.
        exit_with_code(FcExitCode::UnexpectedError);
    }

    // SAFETY: Other signals which might do async unsafe things incompatible with the rest of this
    // function are blocked due to the sa_mask used when registering the signal handler.
    let syscall = unsafe { *(info as *const i32).offset(SI_OFF_SYSCALL) };
    error!(
        "Shutting down VM after intercepting a bad syscall ({}).",
        syscall
    );
}

fn empty_fn(_si_code: c_int, _info: *mut siginfo_t) {}

generate_handler!(
    sigxfsz_handler,
    SIGXFSZ,
    SIGXFSZ,
    METRICS.signals.sigxfsz,
    empty_fn
);

generate_handler!(
    sigxcpu_handler,
    SIGXCPU,
    SIGXCPU,
    METRICS.signals.sigxcpu,
    empty_fn
);

generate_handler!(
    sigbus_handler,
    SIGBUS,
    SIGBUS,
    METRICS.signals.sigbus,
    empty_fn
);

generate_handler!(
    sigsegv_handler,
    SIGSEGV,
    SIGSEGV,
    METRICS.signals.sigsegv,
    empty_fn
);

generate_handler!(
    sigsys_handler,
    SIGSYS,
    BadSyscall,
    METRICS.seccomp.num_faults,
    log_sigsys_err
);

generate_handler!(
    sighup_handler,
    SIGHUP,
    SIGHUP,
    METRICS.signals.sighup,
    empty_fn
);
generate_handler!(
    sigill_handler,
    SIGILL,
    SIGILL,
    METRICS.signals.sigill,
    empty_fn
);

#[inline(always)]
extern "C" fn sigpipe_handler(num: c_int, info: *mut siginfo_t, _unused: *mut c_void) {
    // Just record the metric and allow the process to continue, the EPIPE error needs
    // to be handled at caller level.

    // SAFETY: Safe because we're just reading some fields from a supposedly valid argument.
    let si_signo = unsafe { (*info).si_signo };
    // SAFETY: Safe because we're just reading some fields from a supposedly valid argument.
    let si_code = unsafe { (*info).si_code };

    if num != si_signo || num != SIGPIPE {
        error!("Received invalid signal {}, code {}.", si_signo, si_code);
        return;
    }

    METRICS.signals.sigpipe.inc();

    error!("Received signal {}, code {}.", si_signo, si_code);
}

/// Registers all the required signal handlers.
///
/// Custom handlers are installed for: `SIGBUS`, `SIGSEGV`, `SIGSYS`
/// `SIGXFSZ` `SIGXCPU` `SIGPIPE` `SIGHUP` and `SIGILL`.
pub fn register_signal_handlers() -> vmm_sys_util::errno::Result<()> {
    // Call to unsafe register_signal_handler which is considered unsafe because it will
    // register a signal handler which will be called in the current thread and will interrupt
    // whatever work is done on the current thread, so we have to keep in mind that the registered
    // signal handler must only do async-signal-safe operations.
    register_signal_handler(SIGSYS, sigsys_handler)?;
    register_signal_handler(SIGBUS, sigbus_handler)?;
    register_signal_handler(SIGSEGV, sigsegv_handler)?;
    register_signal_handler(SIGXFSZ, sigxfsz_handler)?;
    register_signal_handler(SIGXCPU, sigxcpu_handler)?;
    register_signal_handler(SIGPIPE, sigpipe_handler)?;
    register_signal_handler(SIGHUP, sighup_handler)?;
    register_signal_handler(SIGILL, sigill_handler)?;
    Ok(())
}
