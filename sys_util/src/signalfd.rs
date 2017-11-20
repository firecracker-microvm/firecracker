// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem;
use std::result;
use std::fs::File;
use std::os::raw::c_int;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::ptr::null_mut;

use libc::{read, sigaddset, sigemptyset, sigismember, sigset_t, c_void, signalfd,
           signalfd_siginfo, pthread_sigmask};
use libc::{EAGAIN, SIG_BLOCK, SIG_UNBLOCK, SFD_NONBLOCK, SFD_CLOEXEC};

use errno;
use errno::errno_result;

#[derive(Debug)]
pub enum Error {
    /// Couldn't create a sigset from the given signal.
    CreateSigset(errno::Error),
    /// Failed to create a new signalfd.
    CreateSignalFd(errno::Error),
    /// The wrapped signal has already been blocked.
    SignalAlreadyBlocked(c_int),
    /// Failed to check if the requested signal is in the blocked set already.
    CompareBlockedSignals(errno::Error),
    /// The signal could not be blocked.
    BlockSignal(errno::Error),
    /// Unable to read from signalfd.
    SignalFdRead(errno::Error),
    /// Signalfd could be read, but didn't return a full siginfo struct.
    /// This wraps the number of bytes that were actually read.
    SignalFdPartialRead(usize),
}

pub type Result<T> = result::Result<T, Error>;

/// A safe wrapper around a Linux signalfd (man 2 signalfd).
///
/// A signalfd can be used for non-synchronous signals (such as SIGCHLD) so that
/// signals can be processed without the use of a signal handler.
pub struct SignalFd {
    signalfd: File,
    signal: c_int,
    sigset: sigset_t,
}

impl SignalFd {
    fn create_sigset(signal: c_int) -> errno::Result<sigset_t> {
        // sigset will actually be initialized by sigemptyset below.
        let mut sigset: sigset_t = unsafe { mem::zeroed() };

        // Safe - return value is checked.
        let ret = unsafe { sigemptyset(&mut sigset as *mut sigset_t) };
        if ret < 0 {
            return errno_result();
        }

        let ret = unsafe { sigaddset(&mut sigset as *mut sigset_t, signal) };
        if ret < 0 {
            return errno_result();
        }
        Ok(sigset)
    }

    /// Creates a new SignalFd for the given signal, blocking the normal handler
    /// for the signal as well. Since we mask out the normal handler, this is
    /// a risky operation - signal masking will persist across fork and even
    /// **exec** so the user of SignalFd should think long and hard about
    /// when to mask signals.
    pub fn new(signal: c_int) -> Result<SignalFd> {
        // This unsafe block will create a signalfd that watches for the
        // supplied signal, and then block the normal handler. At each
        // step, we check return values.
        unsafe {
            let sigset = SignalFd::create_sigset(signal).map_err(Error::CreateSigset)?;
            let fd = signalfd(-1, &sigset, SFD_CLOEXEC | SFD_NONBLOCK);
            if fd < 0 {
                return Err(Error::CreateSignalFd(errno::Error::last()));
            }

            // Mask out the normal handler for the signal.
            let mut old_sigset: sigset_t = mem::zeroed();
            let ret = pthread_sigmask(SIG_BLOCK, &sigset, &mut old_sigset as *mut sigset_t);
            if ret < 0 {
                return Err(Error::BlockSignal(errno::Error::last()));
            }

            let ret = sigismember(&old_sigset, signal);
            if ret < 0 {
                return Err(Error::CompareBlockedSignals(errno::Error::last()));
            } else if ret > 0 {
                return Err(Error::SignalAlreadyBlocked(signal));
            }

            // This is safe because we checked fd for success and know the
            // kernel gave us an fd that we own.
            Ok(SignalFd {
                signalfd: File::from_raw_fd(fd),
                signal: signal,
                sigset: sigset,
            })
        }
    }

    /// Read a siginfo struct from the signalfd, if available.
    pub fn read(&self) -> Result<Option<signalfd_siginfo>> {
        // signalfd_siginfo doesn't have a default, so just zero it.
        let mut siginfo: signalfd_siginfo = unsafe { mem::zeroed() };
        let siginfo_size = mem::size_of::<signalfd_siginfo>();

        // This read is safe since we've got the space allocated for a
        // single signalfd_siginfo, and that's exactly how much we're
        // reading. Handling of EINTR is not required since SFD_NONBLOCK
        // was specified. signalfds will always read in increments of
        // sizeof(signalfd_siginfo); see man 2 signalfd.
        let ret = unsafe {
            read(
                self.signalfd.as_raw_fd(),
                &mut siginfo as *mut signalfd_siginfo as *mut c_void,
                siginfo_size,
            )
        };

        if ret < 0 {
            let err = errno::Error::last();
            if err.errno() == EAGAIN {
                Ok(None)
            } else {
                Err(Error::SignalFdRead(err))
            }
        } else if ret == (siginfo_size as isize) {
            Ok(Some(siginfo))
        } else {
            Err(Error::SignalFdPartialRead(ret as usize))
        }
    }
}

// Safe since the signalfd lifetime lasts as long as this trait object, and the
// signalfd is pollable.
unsafe impl ::Pollable for SignalFd {
    fn pollable_fd(&self) -> RawFd {
        self.signalfd.as_raw_fd()
    }
}

impl Drop for SignalFd {
    fn drop(&mut self) {
        // This is thread-safe and safe in the sense that we're doing what
        // was promised - unmasking the signal when we go out of scope.
        let ret =
            unsafe { pthread_sigmask(SIG_UNBLOCK, &mut self.sigset as *mut sigset_t, null_mut()) };

        // drop can't return a Result, so just print an error to syslog.
        if ret < 0 {
            error!("signalfd failed to unblock signal {}: {}", self.signal, ret);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use libc::{raise, sigismember};
    use signal::SIGRTMIN;
    use std::ptr::null;

    #[test]
    fn new() {
        SignalFd::new(SIGRTMIN()).unwrap();
    }

    #[test]
    fn read() {
        let sigid = SIGRTMIN() + 1;
        let sigrt_fd = SignalFd::new(sigid).unwrap();

        let ret = unsafe { raise(sigid) };
        assert_eq!(ret, 0);

        let siginfo = sigrt_fd.read().unwrap().unwrap();
        assert_eq!(siginfo.ssi_signo, sigid as u32);
    }

    #[test]
    fn drop() {
        let sigid = SIGRTMIN() + 2;

        // Put the SignalFd in a block where it will be dropped at the end.
        #[allow(unused_variables)]
        {
            let sigrt_fd = SignalFd::new(sigid).unwrap();
            unsafe {
                let mut sigset: sigset_t = mem::zeroed();
                pthread_sigmask(0, null(), &mut sigset as *mut sigset_t);
                assert_eq!(sigismember(&sigset, sigid), 1);
            }
        }

        // The signal should no longer be masked.
        unsafe {
            let mut sigset: sigset_t = mem::zeroed();
            pthread_sigmask(0, null(), &mut sigset as *mut sigset_t);
            assert_eq!(sigismember(&sigset, sigid), 0);
        }
    }
}
