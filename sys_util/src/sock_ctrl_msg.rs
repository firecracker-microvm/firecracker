// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::os::unix::io::{AsRawFd, RawFd, FromRawFd};
use std::os::unix::net::{UnixDatagram, UnixStream};

use libc::{c_void, iovec};

use data_model::VolatileSlice;

use {Result, Error};

// These functions are implemented in C because each of them requires complicated setup with CMSG
// macros. These macros are part of the system headers and are required to be used for portability
// reasons. In practice, the control message ABI can't change but using them is much easier and less
// error prone than trying to port these macros to rust.
extern "C" {
    fn scm_cmsg_buffer_len(fd_count: usize) -> usize;
    fn scm_sendmsg(fd: RawFd,
                   outv: *const iovec,
                   outv_count: usize,
                   cmsg_buffer: *mut u8,
                   fds: *const RawFd,
                   fd_count: usize)
                   -> isize;
    fn scm_recvmsg(fd: RawFd,
                   outv: *mut iovec,
                   outv_count: usize,
                   cmsg_buffer: *mut u8,
                   fds: *mut RawFd,
                   fd_count: *mut usize)
                   -> isize;
}

fn cmsg_buffer_len(fd_count: usize) -> usize {
    // Safe because this function has no side effects, touches no pointers, and never fails.
    unsafe { scm_cmsg_buffer_len(fd_count) }
}

/// Trait for file descriptors can send and receive socket control messages via `sendmsg` and
/// `recvmsg`.
pub trait ScmSocket {
    /// Gets the file descriptor of this socket.
    fn socket_fd(&self) -> RawFd;
}

impl ScmSocket for UnixDatagram {
    fn socket_fd(&self) -> RawFd {
        self.as_raw_fd()
    }
}

impl ScmSocket for UnixStream {
    fn socket_fd(&self) -> RawFd {
        self.as_raw_fd()
    }
}

/// Trait for types that can be converted into an `iovec` that can be referenced by a syscall for
/// the lifetime of this object.
///
/// This trait is unsafe because interfaces that use this trait depend on the base pointer and size
/// being accurate.
pub unsafe trait IntoIovec {
    /// Gets the base pointer of this `iovec`.
    fn as_ptr(&self) -> *const c_void;

    /// Gets the size in bytes of this `iovec`.
    fn size(&self) -> usize;
}

// Safe because this slice can not have another mutable reference and it's pointer and size are
// guaranteed to be valid.
unsafe impl<'a> IntoIovec for &'a [u8] {
    fn as_ptr(&self) -> *const c_void {
        self.as_ref().as_ptr() as *const c_void
    }

    fn size(&self) -> usize {
        self.len()
    }
}

// Safe because volatile slices are only ever accessed with other volatile interfaces and the
// pointer and size are guaranteed to be accurate.
unsafe impl<'a> IntoIovec for VolatileSlice<'a> {
    fn as_ptr(&self) -> *const c_void {
        self.as_ptr() as *const c_void
    }

    fn size(&self) -> usize {
        self.size()
    }
}

/// Used to send and receive messages with file descriptors on sockets that accept control messages
/// (e.g. Unix domain sockets).
pub struct Scm {
    cmsg_buffer: Vec<u8>,
    vecs: Vec<iovec>,
    fds: Vec<RawFd>,
}

impl Scm {
    /// Constructs a new Scm object with pre-allocated structures.
    ///
    /// # Arguments
    ///
    /// * `fd_count` - The maximum number of files that can be received per `recv` call.
    pub fn new(fd_count: usize) -> Scm {
        Scm {
            cmsg_buffer: Vec::with_capacity(cmsg_buffer_len(fd_count)),
            vecs: Vec::new(),
            fds: vec![-1; fd_count],
        }
    }

    /// Sends the given data and file descriptors over the given `socket`.
    ///
    /// On success, returns the number of bytes sent.
    ///
    /// # Arguments
    ///
    /// * `socket` - A socket that supports socket control messages.
    /// * `bufs` - A list of buffers to send on the `socket`.
    /// * `fds` - A list of file descriptors to be sent.
    pub fn send<T: ScmSocket, D: IntoIovec>(&mut self,
                              socket: &T,
                              bufs: &[D],
                              fds: &[RawFd])
                              -> Result<usize> {
        let cmsg_buf_len = cmsg_buffer_len(fds.len());
        self.cmsg_buffer.reserve(cmsg_buf_len);
        self.vecs.clear();
        for ref buf in bufs {
            self.vecs
                .push(iovec {
                    iov_base: buf.as_ptr() as *mut c_void,
                    iov_len: buf.size(),
              });
        }
        let write_count = unsafe {
            // Safe because we are giving scm_sendmsg only valid pointers and lengths and we check
            // the return value.
            self.cmsg_buffer.set_len(cmsg_buf_len);
            scm_sendmsg(socket.socket_fd(),
                        self.vecs.as_ptr(),
                        self.vecs.len(),
                        self.cmsg_buffer.as_mut_ptr(),
                        fds.as_ptr(),
                        fds.len())
        };

        if write_count < 0 {
            Err(Error::new(write_count as i32))
        } else {
            Ok(write_count as usize)
        }
    }

    /// Receives data and file descriptors from the given `socket` into the list of buffers.
    ///
    /// On success, returns the number of bytes received.
    ///
    /// # Arguments
    ///
    /// * `socket` - A socket that supports socket control messages.
    /// * `bufs` - A list of buffers to receive data from the `socket`. The `recvmsg` call fills
    ///            these directly.
    /// * `files` - A vector of `File`s to put the received file descriptors into. This vector is
    ///             not cleared and will have at most `fd_count` (specified in `Scm::new`) `File`s
    ///             added to it.
    pub fn recv<T: ScmSocket>(&mut self,
                              socket: &T,
                              bufs: &mut [&mut [u8]],
                              files: &mut Vec<File>)
                              -> Result<usize> {
        let cmsg_buf_len = cmsg_buffer_len(files.len());
        self.cmsg_buffer.reserve(cmsg_buf_len);
        self.vecs.clear();
        for buf in bufs {
            self.vecs
                .push(iovec {
                          iov_base: buf.as_mut_ptr() as *mut c_void,
                          iov_len: buf.len(),
                      });
        }
        let mut fd_count = self.fds.len();
        let read_count = unsafe {
            // Safe because we are giving scm_recvmsg only valid pointers and lengths and we check
            // the return value.
            self.cmsg_buffer.set_len(cmsg_buf_len);
            scm_recvmsg(socket.socket_fd(),
                        self.vecs.as_mut_ptr(),
                        self.vecs.len(),
                        self.cmsg_buffer.as_mut_ptr(),
                        self.fds.as_mut_ptr(),
                        &mut fd_count as *mut usize)
        };

        if read_count < 0 {
            Err(Error::new(read_count as i32))
        } else {
            // Safe because we have unqiue ownership of each fd we wrap with File.
            for &fd in &self.fds[0..fd_count] {
                files.push(unsafe { File::from_raw_fd(fd) });
            }
            Ok(read_count as usize)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write;
    use std::mem::size_of;
    use std::os::raw::c_long;
    use std::os::unix::net::UnixDatagram;
    use std::slice::from_raw_parts;

    use libc::cmsghdr;

    use EventFd;

    #[test]
    fn buffer_len() {
        assert_eq!(cmsg_buffer_len(0), size_of::<cmsghdr>());
        assert_eq!(cmsg_buffer_len(1),
                   size_of::<cmsghdr>() + size_of::<c_long>());
        if size_of::<RawFd>() == 4 {
            assert_eq!(cmsg_buffer_len(2),
                       size_of::<cmsghdr>() + size_of::<c_long>());
            assert_eq!(cmsg_buffer_len(3),
                       size_of::<cmsghdr>() + size_of::<c_long>() * 2);
            assert_eq!(cmsg_buffer_len(4),
                       size_of::<cmsghdr>() + size_of::<c_long>() * 2);
        } else if size_of::<RawFd>() == 8 {
            assert_eq!(cmsg_buffer_len(2),
                       size_of::<cmsghdr>() + size_of::<c_long>() * 2);
            assert_eq!(cmsg_buffer_len(3),
                       size_of::<cmsghdr>() + size_of::<c_long>() * 3);
            assert_eq!(cmsg_buffer_len(4),
                       size_of::<cmsghdr>() + size_of::<c_long>() * 4);
        }
    }

    #[test]
    fn send_recv_no_fd() {
        let (s1, s2) = UnixDatagram::pair().expect("failed to create socket pair");

        let mut scm = Scm::new(1);
        let write_count = scm.send(&s1,
                                   [[1u8, 1, 2].as_ref(), [21, 34, 55].as_ref()].as_ref(),
                                   &[])
            .expect("failed to send data");

        assert_eq!(write_count, 6);

        let mut buf1 = [0; 3];
        let mut buf2 = [0; 3];
        let mut bufs = [buf1.as_mut(), buf2.as_mut()];
        let mut files = Vec::new();
        let read_count = scm.recv(&s2, &mut bufs[..], &mut files)
            .expect("failed to recv data");

        assert_eq!(read_count, 6);
        assert!(files.is_empty());
        assert_eq!(bufs[0], [1, 1, 2]);
        assert_eq!(bufs[1], [21, 34, 55]);
    }

    #[test]
    fn send_recv_only_fd() {
        let (s1, s2) = UnixDatagram::pair().expect("failed to create socket pair");

        let mut scm = Scm::new(1);
        let evt = EventFd::new().expect("failed to create eventfd");
        let write_count = scm.send(&s1, &[[].as_ref()], &[evt.as_raw_fd()])
            .expect("failed to send fd");

        assert_eq!(write_count, 0);

        let mut files = Vec::new();
        let read_count = scm.recv(&s2, &mut [&mut []], &mut files)
            .expect("failed to recv fd");

        assert_eq!(read_count, 0);
        assert_eq!(files.len(), 1);
        assert!(files[0].as_raw_fd() >= 0);
        assert_ne!(files[0].as_raw_fd(), s1.as_raw_fd());
        assert_ne!(files[0].as_raw_fd(), s2.as_raw_fd());
        assert_ne!(files[0].as_raw_fd(), evt.as_raw_fd());

        files[0]
            .write(unsafe { from_raw_parts(&1203u64 as *const u64 as *const u8, 8) })
            .expect("failed to write to sent fd");

        assert_eq!(evt.read().expect("failed to read from eventfd"), 1203);
    }

    #[test]
    fn send_recv_with_fd() {
        let (s1, s2) = UnixDatagram::pair().expect("failed to create socket pair");

        let mut scm = Scm::new(1);
        let evt = EventFd::new().expect("failed to create eventfd");
        let write_count = scm.send(&s1, &[[237].as_ref()], &[evt.as_raw_fd()])
            .expect("failed to send fd");

        assert_eq!(write_count, 1);

        let mut files = Vec::new();
        let mut buf = [0u8];
        let read_count = scm.recv(&s2, &mut [&mut buf], &mut files)
            .expect("failed to recv fd");

        assert_eq!(read_count, 1);
        assert_eq!(buf[0], 237);
        assert_eq!(files.len(), 1);
        assert!(files[0].as_raw_fd() >= 0);
        assert_ne!(files[0].as_raw_fd(), s1.as_raw_fd());
        assert_ne!(files[0].as_raw_fd(), s2.as_raw_fd());
        assert_ne!(files[0].as_raw_fd(), evt.as_raw_fd());

        files[0]
            .write(unsafe { from_raw_parts(&1203u64 as *const u64 as *const u8, 8) })
            .expect("failed to write to sent fd");

        assert_eq!(evt.read().expect("failed to read from eventfd"), 1203);
    }
}
