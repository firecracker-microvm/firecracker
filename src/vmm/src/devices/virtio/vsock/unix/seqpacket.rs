// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::io::{ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, IntoRawFd, RawFd};
use std::os::unix::net::UnixListener;

use libc::{
    EINVAL, F_DUPFD_CLOEXEC, FIOCLEX, FIONCLEX, MSG_EOR, MSG_NOSIGNAL, MSG_PEEK, SO_ERROR,
    SOCK_CLOEXEC, SOCK_NONBLOCK, SOCK_SEQPACKET, SOL_SOCKET, c_void, close, dup, fcntl, getsockopt,
    recv, send,
};
use uds::{UnixSeqpacketConn, UnixSeqpacketListener};
use vm_memory::{ReadVolatile, VolatileMemoryError, WriteVolatile};

use crate::devices::virtio::vsock::csm::VsockConnectionBackend;

#[derive(Debug)]
pub struct SeqpacketConn(std::os::fd::RawFd);

impl SeqpacketConn {
    pub fn new(fd: RawFd) -> Self {
        SeqpacketConn(fd)
    }
}

/// Get errno as io::Error on -1 and retry on EINTR.
macro_rules! cvt_r {
    ($syscall:expr) => {
        loop {
            let result = $syscall;
            if result != -1 {
                break Ok(result);
            }
            let err = io::Error::last_os_error();
            if err.kind() != ErrorKind::Interrupted {
                break Err(err);
            }
        }
    };
}

impl AsRawFd for SeqpacketConn {
    fn as_raw_fd(&self) -> i32 {
        self.0.as_raw_fd()
    }
}

impl Read for SeqpacketConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let ptr = buf.as_mut_ptr().cast::<c_void>();
        // SAFETY: The file descriptor is valid and open. The buffer pointer is valid for writing `buf.len()` bytes.
        let received = cvt_r!(unsafe { recv(self.0.as_raw_fd(), ptr, buf.len(), MSG_NOSIGNAL) })?;
        Ok(received.try_into().unwrap())
    }
}

impl Write for SeqpacketConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let ptr = buf.as_ptr().cast::<c_void>();
        let flags = MSG_NOSIGNAL | MSG_EOR;
        // SAFETY: The file descriptor is valid and open. The buffer pointer is valid for reading `buf.len()` bytes.
        let sent = cvt_r!(unsafe { send(self.0.as_raw_fd(), ptr, buf.len(), flags) })?;
        Ok(sent.try_into().unwrap())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl ReadVolatile for SeqpacketConn {
    fn read_volatile<B: vm_memory::bitmap::BitmapSlice>(
        &mut self,
        buf: &mut vm_memory::VolatileSlice<B>,
    ) -> Result<usize, vm_memory::VolatileMemoryError> {
        let fd = self.0.as_raw_fd();
        let guard = buf.ptr_guard_mut();

        let dst = guard.as_ptr().cast::<libc::c_void>();

        // SAFETY: Rust's I/O safety invariants ensure that BorrowedFd contains a valid file
        // descriptor`. The memory pointed to by `dst` is valid for writes of length
        // `buf.len() by the invariants upheld by the constructor of `VolatileSlice`.
        let bytes_read = unsafe { libc::read(fd, dst, buf.len()) };

        if bytes_read < 0 {
            // We don't know if a partial read might have happened, so mark everything as dirty
            buf.bitmap().mark_dirty(0, buf.len());

            Err(VolatileMemoryError::IOError(std::io::Error::last_os_error()))
        } else {
            let bytes_read = bytes_read.try_into().unwrap();
            buf.bitmap().mark_dirty(0, bytes_read);
            Ok(bytes_read)
        }
    }
}

impl WriteVolatile for SeqpacketConn {
    fn write_volatile<B: vm_memory::bitmap::BitmapSlice>(
        &mut self,
        buf: &vm_memory::VolatileSlice<B>,
    ) -> Result<usize, vm_memory::VolatileMemoryError> {
        let fd = self.0.as_raw_fd();
        let guard = buf.ptr_guard();

        let src = guard.as_ptr().cast::<libc::c_void>();

        // SAFETY: Rust's I/O safety invariants ensure that BorrowedFd contains a valid file
        // descriptor`. The memory pointed to by `src` is valid for reads of length
        // `buf.len() by the invariants upheld by the constructor of `VolatileSlice`.
        let bytes_written = unsafe { libc::write(fd, src, buf.len()) };

        if bytes_written < 0 {
            Err(VolatileMemoryError::IOError(std::io::Error::last_os_error()))
        } else {
            Ok(bytes_written.try_into().unwrap())
        }
    }
}

#[derive(Debug)]
pub struct SeqpacketListener(uds::UnixSeqpacketListener);

impl SeqpacketListener {
    pub fn new(uds_listener: uds::UnixSeqpacketListener) -> Self {
        SeqpacketListener(uds_listener)
    }
}

impl AsRawFd for SeqpacketListener {
    fn as_raw_fd(&self) -> i32 {
        self.0.as_raw_fd()
    }
}

pub trait Socket: AsRawFd + std::fmt::Debug {
    fn accept(&self) -> Result<RawFd, io::Error>;
}

impl Socket for SeqpacketListener {
    fn accept(&self) -> Result<RawFd, io::Error> {
        let (sock, _) = self.0.accept_unix_addr()?;
        sock.set_nonblocking(true);
        Ok(sock.into_raw_fd())
    }
}

impl Socket for UnixListener {
    fn accept(&self) -> Result<RawFd, io::Error> {
        let (conn, _) = self.accept()?;
        conn.set_nonblocking(true);
        Ok(conn.into_raw_fd())
    }
}
