// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::cast_possible_truncation)]

use std::io;
use std::io::{Error, ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixListener;

use vm_memory::{ReadVolatile, VolatileMemoryError, WriteVolatile};

use crate::devices::virtio::vsock::unix::ConnBackend;

const LISTEN_BACKLOG: libc::c_int = 10; // what std uses, I think

#[derive(Debug)]
pub struct SeqpacketConn(std::os::fd::OwnedFd);

impl SeqpacketConn {
    pub fn connect(path: &str) -> Result<Self, io::Error> {
        let (addr_ptr, addr_len) = build_addr(path)?;

        // SAFETY: Valid flags and socket type.
        let fd = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        };
        if fd == -1 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: Valid file descriptor and errors checked.
        unsafe {
            if libc::connect(fd, addr_ptr, addr_len) == -1 {
                let err = io::Error::last_os_error();
                libc::close(fd);
                return Err(err);
            }
        };

        // SAFETY: Valid file descriptor and errors checked.
        Ok(unsafe { SeqpacketConn(OwnedFd::from_raw_fd(fd)) })
    }
}

impl AsRawFd for SeqpacketConn {
    fn as_raw_fd(&self) -> i32 {
        self.0.as_raw_fd()
    }
}

impl Read for SeqpacketConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let ptr = buf.as_mut_ptr().cast::<libc::c_void>();
        // SAFETY: The file descriptor is valid and open. The buffer pointer is valid for writing
        // `buf.len()` bytes.
        let received =
            unsafe { libc::recv(self.0.as_raw_fd(), ptr, buf.len(), libc::MSG_NOSIGNAL) };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(received.try_into().unwrap())
    }
}

impl Write for SeqpacketConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let ptr = buf.as_ptr().cast::<libc::c_void>();
        let flags = libc::MSG_NOSIGNAL | libc::MSG_EOR;
        // SAFETY: The file descriptor is valid and open. The buffer pointer is valid for reading
        // `buf.len()` bytes.
        let sent = unsafe { libc::send(self.0.as_raw_fd(), ptr, buf.len(), flags) };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }

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
pub struct SeqpacketListener(OwnedFd);

impl SeqpacketListener {
    pub fn bind(path: &str) -> Result<Self, io::Error> {
        // SAFETY: Valid socket() parameters, error checked
        let fd = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        };

        if fd == -1 {
            return Err(io::Error::last_os_error());
        }

        let (addr_ptr, addr_len) = build_addr(path)?;

        // SAFETY: Valid fd and addr pointer, closes fd on error
        unsafe {
            if libc::bind(fd, addr_ptr, addr_len) == -1 {
                let err = io::Error::last_os_error();
                libc::close(fd);
                return Err(err);
            }
        };

        // SAFETY: Valid bound socket, closes fd on error
        unsafe {
            if libc::listen(fd, LISTEN_BACKLOG) == -1 {
                let err = io::Error::last_os_error();
                libc::close(fd);
                return Err(err);
            }
        };

        // SAFETY: Transferring unique ownership of valid fd to OwnedFd
        unsafe { Ok(SeqpacketListener(OwnedFd::from_raw_fd(fd))) }
    }
}

impl AsRawFd for SeqpacketListener {
    fn as_raw_fd(&self) -> i32 {
        self.0.as_raw_fd()
    }
}

pub trait Socket: AsRawFd + std::fmt::Debug {
    fn accept(&self) -> Result<ConnBackend, io::Error>;
}

impl Socket for SeqpacketListener {
    fn accept(&self) -> Result<ConnBackend, io::Error> {
        let flags = libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK;
        let mut addr: libc::sockaddr_un = uninitialized_addres();
        let mut addr_len: libc::socklen_t = std::mem::size_of_val(&addr) as libc::socklen_t;

        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        // SAFETY: Valid fd, errors checked.
        let fd = unsafe {
            libc::accept4(
                self.0.as_raw_fd(),
                (&mut addr as *mut libc::sockaddr_un).cast::<libc::sockaddr>(),
                &mut addr_len,
                flags,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: Transferring unique ownership of valid fd to OwnedFd
        unsafe {
            Ok(ConnBackend::Seqpacket(SeqpacketConn(OwnedFd::from_raw_fd(
                fd,
            ))))
        }
    }
}

impl Socket for UnixListener {
    fn accept(&self) -> Result<ConnBackend, io::Error> {
        let (conn, _) = self.accept()?;
        conn.set_nonblocking(true);
        Ok(ConnBackend::Stream(conn))
    }
}

fn build_addr(path: &str) -> Result<(*const libc::sockaddr, u32), io::Error> {
    let mut addr: libc::sockaddr_un = uninitialized_addres();
    addr.sun_family = libc::AF_UNIX as _;
    let max_addr = std::mem::size_of_val(&addr.sun_path);
    if path.len() > std::mem::size_of_val(&addr.sun_path) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!(
                "the path has length higher than maximum allowed: {}, got: {}",
                path.len(),
                max_addr
            ),
        ));
    };

    // SAFETY: Bounded copy, non-overlapping pointers
    unsafe {
        std::ptr::copy_nonoverlapping(
            path.as_ptr().cast::<libc::c_char>(),
            addr.sun_path.as_mut_ptr(),
            path.len().min(addr.sun_path.len()),
        );
    };
    Ok((
        (&addr as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
        std::mem::size_of::<libc::sockaddr_un>() as u32,
    ))
}

fn uninitialized_addres() -> libc::sockaddr_un {
    // SAFETY: sockaddr_un has no invalid bit patterns
    unsafe { std::mem::zeroed() }
}
