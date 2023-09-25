// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::fmt::Debug;
use std::io::ErrorKind;
use std::os::unix::io::AsRawFd;

use vm_memory::bitmap::BitmapSlice;
use vm_memory::Bytes;
pub use vm_memory::{VolatileMemory, VolatileMemoryError, VolatileSlice};

/// A version of the standard library's [`Read`] trait that operates on volatile memory instead of
/// slices
///
/// This trait is needed as rust slices (`&[u8]` and `&mut [u8]`) cannot be used when operating on
/// guest memory [1].
///
/// [1]: https://github.com/rust-vmm/vm-memory/pull/217
pub trait ReadVolatile {
    /// Tries to read some bytes into the given [`VolatileSlice`] buffer, returning how many bytes
    /// were read.
    ///
    /// The behavior of implementations should be identical to [`Read::read`]
    fn read_volatile<B: BitmapSlice>(
        &mut self,
        buf: &mut VolatileSlice<B>,
    ) -> Result<usize, VolatileMemoryError>;

    /// Tries to fill the given [`VolatileSlice`] buffer by reading from `self` returning an error
    /// if insufficient bytes could be read.
    ///
    /// The default implementation is identical to that of [`Read::read_exact`]
    fn read_exact_volatile<B: BitmapSlice>(
        &mut self,
        buf: &mut VolatileSlice<B>,
    ) -> Result<(), VolatileMemoryError> {
        // Implementation based on https://github.com/rust-lang/rust/blob/7e7483d26e3cec7a44ef00cf7ae6c9c8c918bec6/library/std/src/io/mod.rs#L465

        let mut partial_buf = buf.offset(0)?;

        while !partial_buf.is_empty() {
            match self.read_volatile(&mut partial_buf) {
                Err(VolatileMemoryError::IOError(err)) if err.kind() == ErrorKind::Interrupted => {
                    continue
                }
                Ok(0) => {
                    return Err(VolatileMemoryError::IOError(std::io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "failed to fill whole buffer",
                    )))
                }
                Ok(bytes_read) => partial_buf = partial_buf.offset(bytes_read)?,
                Err(err) => return Err(err),
            }
        }

        Ok(())
    }
}

/// A version of the standard library's [`Write`] trait that operates on volatile memory instead of
/// slices
///
/// This trait is needed as rust slices (`&[u8]` and `&mut [u8]`) cannot be used when operating on
/// guest memory [1].
///
/// [1]: https://github.com/rust-vmm/vm-memory/pull/217
pub trait WriteVolatile: Debug {
    /// Tries to write some bytes from the given [`VolatileSlice`] buffer, returning how many bytes
    /// were written.
    ///
    /// The behavior of implementations should be identical to [`Write::write`]
    fn write_volatile<B: BitmapSlice>(
        &mut self,
        buf: &VolatileSlice<B>,
    ) -> Result<usize, VolatileMemoryError>;

    /// Tries write the entire content of the given [`VolatileSlice`] buffer to `self` returning an
    /// error if not all bytes could be written.
    ///
    /// The default implementation is identical to that of [`Write::write_all`]
    fn write_all_volatile<B: BitmapSlice>(
        &mut self,
        buf: &VolatileSlice<B>,
    ) -> Result<(), VolatileMemoryError> {
        // Based on https://github.com/rust-lang/rust/blob/7e7483d26e3cec7a44ef00cf7ae6c9c8c918bec6/library/std/src/io/mod.rs#L1570

        let mut partial_buf = buf.offset(0)?;

        while !partial_buf.is_empty() {
            match self.write_volatile(&partial_buf) {
                Err(VolatileMemoryError::IOError(err)) if err.kind() == ErrorKind::Interrupted => {
                    continue
                }
                Ok(0) => {
                    return Err(VolatileMemoryError::IOError(std::io::Error::new(
                        ErrorKind::WriteZero,
                        "failed to write whole buffer",
                    )))
                }
                Ok(bytes_written) => partial_buf = partial_buf.offset(bytes_written)?,
                Err(err) => return Err(err),
            }
        }

        Ok(())
    }
}

// We explicitly implement our traits for [`std::fs::File`] and [`std::os::unix::net::UnixStream`]
// instead of providing blanket implementation for [`AsRawFd`] due to trait coherence limitations: A
// blanket implementation would prevent us from providing implementations for `&mut [u8]` below, as
// "an upstream crate could implement AsRawFd for &mut [u8]`.

impl ReadVolatile for std::fs::File {
    fn read_volatile<B: BitmapSlice>(
        &mut self,
        buf: &mut VolatileSlice<B>,
    ) -> Result<usize, VolatileMemoryError> {
        read_volatile_raw_fd(self, buf)
    }
}

impl ReadVolatile for std::os::unix::net::UnixStream {
    fn read_volatile<B: BitmapSlice>(
        &mut self,
        buf: &mut VolatileSlice<B>,
    ) -> Result<usize, VolatileMemoryError> {
        read_volatile_raw_fd(self, buf)
    }
}

/// Tries to do a single `read` syscall on the provided file descriptor, storing the data raed in
/// the given [`VolatileSlice`].
///
/// Returns the numbers of bytes read.
fn read_volatile_raw_fd<Fd: AsRawFd + Debug>(
    raw_fd: &mut Fd,
    buf: &mut VolatileSlice<impl BitmapSlice>,
) -> Result<usize, VolatileMemoryError> {
    let fd = raw_fd.as_raw_fd();
    let guard = buf.ptr_guard_mut();
    let dst = guard.as_ptr().cast::<libc::c_void>();

    // SAFETY: We got a valid file descriptor from `AsRawFd`. The memory pointed to by `dst` is
    // valid for writes of length `buf.len() by the invariants upheld by the constructor
    // of `VolatileSlice`.
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

impl WriteVolatile for std::fs::File {
    fn write_volatile<B: BitmapSlice>(
        &mut self,
        buf: &VolatileSlice<B>,
    ) -> Result<usize, VolatileMemoryError> {
        write_volatile_raw_fd(self, buf)
    }
}

impl WriteVolatile for std::os::unix::net::UnixStream {
    fn write_volatile<B: BitmapSlice>(
        &mut self,
        buf: &VolatileSlice<B>,
    ) -> Result<usize, VolatileMemoryError> {
        write_volatile_raw_fd(self, buf)
    }
}

/// Tries to do a single `write` syscall on the provided file descriptor, attempting to write the
/// data stored in the given [`VolatileSlice`].
///
/// Returns the numbers of bytes written.
fn write_volatile_raw_fd<Fd: AsRawFd + Debug>(
    raw_fd: &mut Fd,
    buf: &VolatileSlice<impl BitmapSlice>,
) -> Result<usize, VolatileMemoryError> {
    let fd = raw_fd.as_raw_fd();
    let guard = buf.ptr_guard();
    let src = guard.as_ptr().cast::<libc::c_void>();

    // SAFETY: We got a valid file descriptor from `AsRawFd`. The memory pointed to by `src` is
    // valid for reads of length `buf.len() by the invariants upheld by the constructor
    // of `VolatileSlice`.
    let bytes_written = unsafe { libc::write(fd, src, buf.len()) };

    if bytes_written < 0 {
        Err(VolatileMemoryError::IOError(std::io::Error::last_os_error()))
    } else {
        Ok(bytes_written.try_into().unwrap())
    }
}

impl WriteVolatile for &mut [u8] {
    fn write_volatile<B: BitmapSlice>(
        &mut self,
        buf: &VolatileSlice<B>,
    ) -> Result<usize, VolatileMemoryError> {
        // NOTE: The duality of read <-> write here is correct. This is because we translate a call
        // "slice.write(buf)" (e.g. write into slice from buf) into "buf.read(slice)" (e.g. read
        // from buffer into slice). Both express data transfer from the buffer to the slice
        let read = buf.read(self, 0)?;

        // Advance the slice, just like the stdlib: https://doc.rust-lang.org/src/std/io/impls.rs.html#335
        *self = std::mem::take(self).split_at_mut(read).1;

        Ok(read)
    }

    fn write_all_volatile<B: BitmapSlice>(
        &mut self,
        buf: &VolatileSlice<B>,
    ) -> Result<(), VolatileMemoryError> {
        // Based on https://github.com/rust-lang/rust/blob/f7b831ac8a897273f78b9f47165cf8e54066ce4b/library/std/src/io/impls.rs#L376-L382
        if self.write_volatile(buf)? == buf.len() {
            Ok(())
        } else {
            Err(VolatileMemoryError::IOError(std::io::Error::new(
                ErrorKind::WriteZero,
                "failed to write whole buffer",
            )))
        }
    }
}

impl ReadVolatile for &[u8] {
    fn read_volatile<B: BitmapSlice>(
        &mut self,
        buf: &mut VolatileSlice<B>,
    ) -> Result<usize, VolatileMemoryError> {
        // NOTE: the duality of read <-> write here is correct. This is because we translate a call
        // "slice.read(buf)" (e.g. "read from slice into buf") into "buf.write(slice)" (e.g. write
        // into buf from slice)
        let written = buf.write(self, 0)?;

        // Advance the slice, just like the stdlib: https://doc.rust-lang.org/src/std/io/impls.rs.html#232-310
        *self = self.split_at(written).1;

        Ok(written)
    }

    fn read_exact_volatile<B: BitmapSlice>(
        &mut self,
        buf: &mut VolatileSlice<B>,
    ) -> Result<(), VolatileMemoryError> {
        // Based on https://github.com/rust-lang/rust/blob/f7b831ac8a897273f78b9f47165cf8e54066ce4b/library/std/src/io/impls.rs#L282-L302
        if buf.len() > self.len() {
            return Err(VolatileMemoryError::IOError(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "failed to fill whole buffer",
            )));
        }

        self.read_volatile(buf).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]
    use std::io::{Read, Seek, Write};

    use utils::tempfile::TempFile;

    use super::*;

    #[test]
    fn test_read_volatile() {
        let test_cases = [
            (vec![1u8, 2], [1u8, 2, 0, 0, 0]),
            (vec![1, 2, 3, 4], [1, 2, 3, 4, 0]),
            // ensure we don't have a buffer overrun
            (vec![5, 6, 7, 8, 9], [5, 6, 7, 8, 0]),
        ];

        for (input, output) in test_cases {
            // ---- Test ReadVolatile for &[u8] ----
            //
            // Test read_volatile for &[u8] works
            let mut memory = vec![0u8; 5];

            assert_eq!(
                (&input[..])
                    .read_volatile(&mut VolatileSlice::from(&mut memory[..4]))
                    .unwrap(),
                input.len().min(4)
            );
            assert_eq!(&memory, &output);

            // Test read_exact_volatile for &[u8] works
            let mut memory = vec![0u8; 5];
            let result =
                (&input[..]).read_exact_volatile(&mut VolatileSlice::from(&mut memory[..4]));

            // read_exact fails if there are not enough bytes in input to completely fill
            // memory[..4]
            if input.len() < 4 {
                match result.unwrap_err() {
                    VolatileMemoryError::IOError(ioe) => {
                        assert_eq!(ioe.kind(), ErrorKind::UnexpectedEof)
                    }
                    err => panic!("{:?}", err),
                }
                assert_eq!(memory, vec![0u8; 5]);
            } else {
                result.unwrap();
                assert_eq!(&memory, &output);
            }

            // ---- Test ReadVolatile for File ----

            let mut temp_file = TempFile::new().unwrap().into_file();
            temp_file.write_all(input.as_ref()).unwrap();
            temp_file.rewind().unwrap();

            // Test read_volatile for File works
            let mut memory = vec![0u8; 5];

            assert_eq!(
                temp_file
                    .read_volatile(&mut VolatileSlice::from(&mut memory[..4]))
                    .unwrap(),
                input.len().min(4)
            );
            assert_eq!(&memory, &output);

            temp_file.rewind().unwrap();

            // Test read_exact_volatile for File works
            let mut memory = vec![0u8; 5];

            let read_exact_result =
                temp_file.read_exact_volatile(&mut VolatileSlice::from(&mut memory[..4]));

            if input.len() < 4 {
                read_exact_result.unwrap_err();
            } else {
                read_exact_result.unwrap();
            }
            assert_eq!(&memory, &output);
        }
    }

    #[test]
    fn test_write_volatile() {
        let test_cases = [
            (vec![1u8, 2], [1u8, 2, 0, 0, 0]),
            (vec![1, 2, 3, 4], [1, 2, 3, 4, 0]),
            // ensure we don't have a buffer overrun
            (vec![5, 6, 7, 8, 9], [5, 6, 7, 8, 0]),
        ];

        for (mut input, output) in test_cases {
            // ---- Test WriteVolatile for &mut [u8] ----
            //
            // Test write_volatile for &mut [u8] works
            let mut memory = vec![0u8; 5];

            assert_eq!(
                (&mut memory[..4])
                    .write_volatile(&VolatileSlice::from(input.as_mut_slice()))
                    .unwrap(),
                input.len().min(4)
            );
            assert_eq!(&memory, &output);

            // Test write_all_volatile for &mut [u8] works
            let mut memory = vec![0u8; 5];

            let result =
                (&mut memory[..4]).write_all_volatile(&VolatileSlice::from(input.as_mut_slice()));

            if input.len() > 4 {
                match result.unwrap_err() {
                    VolatileMemoryError::IOError(ioe) => {
                        assert_eq!(ioe.kind(), ErrorKind::WriteZero)
                    }
                    err => panic!("{:?}", err),
                }
                // This quirky behavior of writing to the slice even in the case of failure is also
                // exhibited by the stdlib
                assert_eq!(&memory, &output);
            } else {
                result.unwrap();
                assert_eq!(&memory, &output);
            }

            // ---- Test ẂriteVolatile for File works
            // Test write_volatile for File works
            let mut temp_file = TempFile::new().unwrap().into_file();

            temp_file
                .write_volatile(&VolatileSlice::from(input.as_mut_slice()))
                .unwrap();
            temp_file.rewind().unwrap();

            let mut written = vec![0u8; input.len()];
            temp_file.read_exact(written.as_mut_slice()).unwrap();

            assert_eq!(input, written);
            // check no excess bytes were written to the file
            assert_eq!(temp_file.read(&mut [0u8]).unwrap(), 0);

            // Test write_all_volatile for File works
            let mut temp_file = TempFile::new().unwrap().into_file();

            temp_file
                .write_all_volatile(&VolatileSlice::from(input.as_mut_slice()))
                .unwrap();
            temp_file.rewind().unwrap();

            let mut written = vec![0u8; input.len()];
            temp_file.read_exact(written.as_mut_slice()).unwrap();

            assert_eq!(input, written);
            // check no excess bytes were written to the file
            assert_eq!(temp_file.read(&mut [0u8]).unwrap(), 0);
        }
    }
}
