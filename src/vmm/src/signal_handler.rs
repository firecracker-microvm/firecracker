// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use libc::{
    _exit, c_int, signalfd_siginfo, sigset_t, SFD_CLOEXEC, SFD_NONBLOCK, SIGBUS, SIGHUP, SIGILL,
    SIGPIPE, SIGSEGV, SIGSYS, SIGXCPU, SIGXFSZ, SIG_BLOCK,
};
use logger::{error, IncMetric, METRICS};
use polly::event_manager::{EventManager, Subscriber};
use std::fs::File;
use std::io::Read;
use std::mem;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::ptr;
use utils::epoll::{EpollEvent, EventSet};
use utils::errno::Error as ErrnoError;
use utils::signal::{create_sigset, validate_signal_num};
use utils::syscall::SyscallReturnCode;
use vm_memory::ByteValued;

// We need this wrapper in order to be able to implement the `ByteValued` trait,
// since the `signalfd_siginfo` type is foreign.
// We need repr(transparent) so that the wrapper has the same ABI as the inner value.
#[derive(Copy, Clone)]
#[repr(transparent)]
struct SignalInfoWrapper(signalfd_siginfo);

// This is a requirement for the `ByteValued` trait and unfortunately the `signalfd_siginfo`
// type does not implement it, so we provide an implementation that initializes all fields
// with 0. This is ok since all fields are integer types.
impl Default for SignalInfoWrapper {
    fn default() -> SignalInfoWrapper {
        let inner: signalfd_siginfo = unsafe { mem::zeroed() };
        SignalInfoWrapper(inner)
    }
}

unsafe impl ByteValued for SignalInfoWrapper {}

const HANDLED_SIGNALS: [c_int; 8] = [
    SIGBUS, SIGHUP, SIGILL, SIGPIPE, SIGSEGV, SIGSYS, SIGXCPU, SIGXFSZ,
];

const SYS_SECCOMP_CODE: i32 = 1;

#[derive(Debug)]
/// Error manipulating signal handlers.
pub enum Error {
    /// A syscall returning negative value.
    SyscallError(std::io::Error),
    /// Error wrapping an error number.
    Errno(ErrnoError),
}

type Result<T> = std::result::Result<T, Error>;

/// Install the default signal mask so that the signals are no longer picked up by any default handlers.
/// This must be installed on the VMM thread because otherwise, the default signal handler will run before
/// we get to wait for any epoll events.
/// On the API thread, this is installed to make sure that the VMM thread is the only one handling the
/// signal.
/// On VPCU threads, this mask is automatically inherited from the VMM thread, since at the time they
/// are spawned, the mask was already installed on their parent. The API thread is however spawned before
/// that and needs explicit masking.
pub fn mask_handled_signals() -> Result<()> {
    let mask = get_mask()?;

    // Install the block mask.
    SyscallReturnCode(
        // Safe because we check the return code.
        unsafe { libc::pthread_sigmask(SIG_BLOCK, &mask as *const sigset_t, ptr::null_mut()) },
    )
    .into_empty_result()
    .map_err(Error::SyscallError)?;

    Ok(())
}

/// Struct responsible for processing signalfd events.
pub struct SignalManager {
    /// The file associated to the current signalfd.
    signal_fd: File,
}

#[inline]
fn exit_unexpected() {
    // Safe because we're terminating the process anyway.
    unsafe { _exit(i32::from(super::FC_EXIT_CODE_UNEXPECTED_ERROR)) };
}

// Given a signal number, return the respective metric and exit code.
fn get_metric_and_exitcode(signo: c_int) -> Option<(&'static dyn IncMetric, Option<i32>)> {
    match signo {
        SIGXFSZ => Some((
            &METRICS.signals.sigxfsz,
            Some(super::FC_EXIT_CODE_SIGXFSZ as i32),
        )),
        SIGXCPU => Some((
            &METRICS.signals.sigxcpu,
            Some(super::FC_EXIT_CODE_SIGXCPU as i32),
        )),
        SIGBUS => Some((
            &METRICS.signals.sigbus,
            Some(super::FC_EXIT_CODE_SIGBUS as i32),
        )),
        SIGSEGV => Some((
            &METRICS.signals.sigsegv,
            Some(super::FC_EXIT_CODE_SIGSEGV as i32),
        )),
        // Dummy entry, never going to exit due to SIGPIPE.
        SIGPIPE => Some((&METRICS.signals.sigpipe, None)),
        SIGSYS => Some((
            &METRICS.seccomp.num_faults,
            Some(super::FC_EXIT_CODE_BAD_SYSCALL as i32),
        )),
        SIGHUP => Some((
            &METRICS.signals.sighup,
            Some(super::FC_EXIT_CODE_SIGHUP as i32),
        )),
        SIGILL => Some((
            &METRICS.signals.sigill,
            Some(super::FC_EXIT_CODE_SIGILL as i32),
        )),
        _ => None,
    }
}

// Special handling of logging for the SIGSYS signal.
fn log_sigsys_err(info: signalfd_siginfo) {
    if info.ssi_code != SYS_SECCOMP_CODE {
        // We received a SIGSYS for a reason other than `bad syscall`.
        error!(
            "Shutting down VM after intercepting signal {}, code {}.",
            info.ssi_signo, info.ssi_code
        );
        exit_unexpected();
    }

    let syscall = info.ssi_syscall;
    error!(
        "Shutting down VM after intercepting a bad syscall ({}).",
        syscall
    );
}

// Create and return the signal mask corresponding to the signals we want to handle.
fn get_mask() -> Result<sigset_t> {
    // Validate that all signals are valid.
    for signal in HANDLED_SIGNALS.iter() {
        validate_signal_num(*signal).map_err(Error::Errno)?;
    }

    let mask = create_sigset(&HANDLED_SIGNALS).map_err(Error::Errno)?;

    Ok(mask)
}

impl SignalManager {
    /// Create a SignalManager instance, wrapping a new signalfd.
    pub fn new() -> Result<Self> {
        let mask = get_mask()?;

        // Create a new signalfd. Safe because we are checking the return code.
        let sfd = SyscallReturnCode(unsafe {
            libc::signalfd(-1, &mask as *const sigset_t, SFD_CLOEXEC | SFD_NONBLOCK)
        })
        .into_result()
        .map_err(Error::SyscallError)?;

        Ok(Self {
            // Create a File instance so that we can leverage safe Read abstractions.
            // Safe because the fd is valid.
            signal_fd: unsafe { File::from_raw_fd(sfd) },
        })
    }

    /// Generic signal handler: log signal, inc metric and exit.
    fn handle_signal(info: signalfd_siginfo) {
        let si_signo = info.ssi_signo as i32;
        let si_code = info.ssi_code;

        match si_signo {
            // For SIGSYS, we have some special logging.
            SIGSYS => log_sigsys_err(info),
            // For SIGPIPE we just log the signal and code.
            SIGPIPE => error!("Received signal {}, code {}.", si_signo, si_code),
            _ => error!(
                "Shutting down VM after intercepting signal {}, code {}.",
                si_signo, si_code
            ),
        }

        let result = get_metric_and_exitcode(si_signo);
        if result.is_none() {
            // This should never be reached since we'll only receive the signals in the signalfd mask.
            error!(
                "Received unexpected signal: {} which is not in signalfd mask.",
                si_signo
            );
            exit_unexpected();
        }

        // This `unwrap` is safe because we would have exited the process if it was a None value.
        let (metric, exit_code) = result.unwrap();

        // Increment the right metric.
        metric.inc();

        if exit_code.is_none() {
            // No exit_code means we need to bail out before flushing metrics & terminating.
            return;
        }

        // Write the metrics before exiting.
        if let Err(e) = METRICS.write() {
            error!("Failed to write metrics while stopping: {}", e);
        }

        // Safe because we're terminating the process anyway. We don't actually do anything when
        // running unit tests.
        #[cfg(not(test))]
        unsafe {
            // Unwrap will not panic as we checked it above.
            _exit(exit_code.unwrap())
        };
    }
}

impl Subscriber for SignalManager {
    fn process(&mut self, event: &EpollEvent, _evmgr: &mut EventManager) {
        let event_set = event.event_set();
        let source_fd = event.fd();

        if event_set != EventSet::IN || source_fd != self.signal_fd.as_raw_fd() {
            error!("Spurious EventManager event for handler: SignalManager");
            return;
        }

        let siginfo_size = mem::size_of::<signalfd_siginfo>();
        let mut read_buf: Vec<u8> = vec![0; siginfo_size];

        // Even though we currently kill the process during signal handling, we should in theory
        // read from the signalfd all the signals for future-proofing.
        loop {
            match self.signal_fd.read(&mut read_buf[..]) {
                Ok(size) if size == siginfo_size => {
                    match SignalInfoWrapper::from_slice(&read_buf) {
                        Some(wrapper) => Self::handle_signal(wrapper.0),
                        None => {
                            error!("Error reading signalfd_siginfo data.");
                            break;
                        }
                    }
                }
                Ok(_) => {
                    error!("Signalfd read operation returned wrong amount of bytes.");
                    break;
                }
                Err(error) => {
                    error!("Signalfd read error: {}", error);
                    break;
                }
            }
        }
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        vec![EpollEvent::new(
            EventSet::IN,
            self.signal_fd.as_raw_fd() as u64,
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libc::{c_void, cpu_set_t, siginfo_t};
    use seccompiler::sock_filter;
    use std::convert::TryInto;
    use std::sync::{Arc, Mutex};
    use std::{mem, thread};
    use utils::signal::register_signal_handler;

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
        // Test all signal handlers (except for SIGSYS, which has its own test),
        // by running an EventManager loop, similar to how the VMM thread operates.
        thread::spawn(|| {
            let mut event_manager = EventManager::new().unwrap();

            // Right before creating the signalfd,
            // mask the handled signals so that the default handlers are bypassed.
            mask_handled_signals().unwrap();
            let signal_manager = Arc::new(Mutex::new(SignalManager::new().unwrap()));

            // Register the signal handler event fd.
            event_manager
                .add_subscriber(signal_manager)
                .expect("Cannot register the signal handler fd to the event manager.");

            let thread_id = unsafe { libc::pthread_self() };
            assert_eq!(METRICS.signals.sigbus.count(), 0);
            unsafe {
                libc::pthread_kill(thread_id, SIGBUS);
            }

            assert_eq!(METRICS.signals.sigsegv.count(), 0);
            unsafe {
                libc::pthread_kill(thread_id, SIGSEGV);
            }

            assert_eq!(METRICS.signals.sigxfsz.count(), 0);
            unsafe {
                libc::pthread_kill(thread_id, SIGXFSZ);
            }

            assert_eq!(METRICS.signals.sigxcpu.count(), 0);
            unsafe {
                libc::pthread_kill(thread_id, SIGXCPU);
            }

            assert_eq!(METRICS.signals.sigpipe.count(), 0);
            unsafe {
                libc::pthread_kill(thread_id, SIGPIPE);
            }

            assert_eq!(METRICS.signals.sighup.count(), 0);
            unsafe {
                libc::pthread_kill(thread_id, SIGHUP);
            }

            assert_eq!(METRICS.signals.sigill.count(), 0);
            unsafe {
                libc::pthread_kill(thread_id, SIGILL);
            }

            event_manager.run_with_timeout(2000).unwrap();
        })
        .join()
        .unwrap();

        assert!(METRICS.signals.sigbus.count() >= 1);
        assert!(METRICS.signals.sigsegv.count() >= 1);
        assert!(METRICS.signals.sigxfsz.count() >= 1);
        assert!(METRICS.signals.sigxcpu.count() >= 1);
        assert!(METRICS.signals.sigpipe.count() >= 1);
        assert!(METRICS.signals.sighup.count() >= 1);
        // Workaround to GitHub issue 2216.
        #[cfg(not(target_arch = "aarch64"))]
        assert!(METRICS.signals.sigill.count() >= 1);
    }

    fn make_test_seccomp_bpf_filter() -> Vec<sock_filter> {
        // Create seccomp filter that allows all syscalls, except for `SYS_mkdirat`.
        // For some reason, directly calling `SYS_kill` with SIGSYS, like we do with the
        // other signals, results in an error. Probably because of the way `cargo test` is
        // handling signals.
        #[cfg(target_arch = "aarch64")]
        #[allow(clippy::unreadable_literal)]
        let bpf_filter = vec![
            sock_filter {
                code: 32,
                jt: 0,
                jf: 0,
                k: 4,
            },
            sock_filter {
                code: 21,
                jt: 1,
                jf: 0,
                k: 3221225655,
            },
            sock_filter {
                code: 6,
                jt: 0,
                jf: 0,
                k: 0,
            },
            sock_filter {
                code: 32,
                jt: 0,
                jf: 0,
                k: 0,
            },
            sock_filter {
                code: 21,
                jt: 0,
                jf: 1,
                k: 34,
            },
            sock_filter {
                code: 5,
                jt: 0,
                jf: 0,
                k: 1,
            },
            sock_filter {
                code: 5,
                jt: 0,
                jf: 0,
                k: 2,
            },
            sock_filter {
                code: 6,
                jt: 0,
                jf: 0,
                k: 196608,
            },
            sock_filter {
                code: 6,
                jt: 0,
                jf: 0,
                k: 2147418112,
            },
            sock_filter {
                code: 6,
                jt: 0,
                jf: 0,
                k: 2147418112,
            },
        ];
        #[cfg(target_arch = "x86_64")]
        #[allow(clippy::unreadable_literal)]
        let bpf_filter = vec![
            sock_filter {
                code: 32,
                jt: 0,
                jf: 0,
                k: 4,
            },
            sock_filter {
                code: 21,
                jt: 1,
                jf: 0,
                k: 3221225534,
            },
            sock_filter {
                code: 6,
                jt: 0,
                jf: 0,
                k: 0,
            },
            sock_filter {
                code: 32,
                jt: 0,
                jf: 0,
                k: 0,
            },
            sock_filter {
                code: 21,
                jt: 0,
                jf: 1,
                k: 258,
            },
            sock_filter {
                code: 5,
                jt: 0,
                jf: 0,
                k: 1,
            },
            sock_filter {
                code: 5,
                jt: 0,
                jf: 0,
                k: 2,
            },
            sock_filter {
                code: 6,
                jt: 0,
                jf: 0,
                k: 196608,
            },
            sock_filter {
                code: 6,
                jt: 0,
                jf: 0,
                k: 2147418112,
            },
            sock_filter {
                code: 6,
                jt: 0,
                jf: 0,
                k: 2147418112,
            },
        ];

        bpf_filter
    }

    // The `cargo test` process somehow receives the SIGSYS, before we get a chance to listen on the signalfd
    // (even if we explicitly direct it to the current thread).
    // This is likely because the test process does a `wait4()` for the test thread, and looks for a potential
    // SIGSYS exit reason. This is why we have to test SIGSYS handling differently.
    // In order to be able to test the behaviour, we install a regular signal handler, that calls
    // under the hood the same function that the SignalManager would call.
    #[test]
    fn test_sigsys_handler() {
        // Sanity check.
        assert!(cpu_count() > 0);
        // Kcov somehow messes with our handler getting the SIGSYS signal when a bad syscall
        // is caught, so the following test no longer holds. Ideally, we'd have a surefire
        // way of either preventing this behaviour, or detecting for certain whether this test is
        // run by kcov or not. The best we could do so far is to look at the perceived number of
        // available CPUs. Kcov seems to make a single CPU available to the process running the
        // tests, so we use this as an heuristic to decide if we run the test.
        if cpu_count() == 1 {
            // We are running under kcov so don't run the test.
            return;
        }

        let child = thread::spawn(move || {
            extern "C" fn signal_handler(_: c_int, siginfo: *mut siginfo_t, _: *mut c_void) {
                // The offset of `si_syscall` (offending syscall identifier) within the siginfo structure
                // expressed as an `(u)int*`.
                // Offset `6` for an `i32` field means that the needed information is located at `6 * sizeof(i32)`.
                // See /usr/include/linux/signal.h for the C struct definition.
                // See https://github.com/rust-lang/libc/issues/716 for why the offset is different in Rust.
                const SI_OFF_SYSCALL: isize = 6;

                // Transfer the important information from the siginfo_t struct to a signalfd_siginfo struct.
                let mut signalfd_info: signalfd_siginfo = unsafe { mem::zeroed() };
                signalfd_info.ssi_signo = unsafe { (*siginfo).si_signo.try_into().unwrap() };
                signalfd_info.ssi_code = unsafe { (*siginfo).si_code };
                signalfd_info.ssi_syscall =
                    unsafe { *(siginfo as *const i32).offset(SI_OFF_SYSCALL) as i32 };

                SignalManager::handle_signal(signalfd_info);
            }
            assert!(register_signal_handler(SIGSYS, signal_handler).is_ok());
            let filter = make_test_seccomp_bpf_filter();
            assert!(seccompiler::apply_filter(&filter).is_ok());
            assert_eq!(METRICS.seccomp.num_faults.count(), 0);

            // Call the forbidden `SYS_mkdirat`.
            unsafe { libc::syscall(libc::SYS_mkdirat, "/foo/bar\0") };
        });
        assert!(child.join().is_ok());

        assert!(METRICS.seccomp.num_faults.count() >= 1);
    }
}
