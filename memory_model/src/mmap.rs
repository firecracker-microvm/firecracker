// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! The mmap module provides a safe interface to mmap memory and ensures unmap is called when the
//! mmap object leaves scope.

use std;
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::ptr::null_mut;

use libc;

use sys_util;
use DataInit;

#[derive(Debug)]
pub enum Error {
    /// Requested memory out of range.
    InvalidAddress,
    /// Requested memory range spans past the end of the region.
    InvalidRange(usize, usize),
    /// Couldn't read from the given source.
    ReadFromSource(std::io::Error),
    /// `mmap` returned the given error.
    SystemCallFailed(sys_util::Error),
    /// Writing to memory failed
    WriteToMemory(std::io::Error),
    /// Reading from memory failed
    ReadFromMemory(std::io::Error),
}
type Result<T> = std::result::Result<T, Error>;

/// Wraps an anonymous shared memory mapping in the current process.
pub struct MemoryMapping {
    addr: *mut u8,
    size: usize,
}

// Send and Sync aren't automatically inherited for the raw address pointer.
// Accessing that pointer is only done through the stateless interface which
// allows the object to be shared by multiple threads without a decrease in
// safety.
unsafe impl Send for MemoryMapping {}
unsafe impl Sync for MemoryMapping {}

impl MemoryMapping {
    /// Creates an anonymous shared mapping of `size` bytes.
    ///
    /// # Arguments
    /// * `size` - Size of memory region in bytes.
    pub fn new(size: usize) -> Result<MemoryMapping> {
        // This is safe because we are creating an anonymous mapping in a place not already used by
        // any other area in this process.
        let addr = unsafe {
            libc::mmap(
                null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if addr.is_null() {
            return Err(Error::SystemCallFailed(sys_util::Error::last()));
        }
        Ok(MemoryMapping {
            addr: addr as *mut u8,
            size,
        })
    }

    /// Maps the first `size` bytes of the given `fd`.
    ///
    /// # Arguments
    /// * `fd` - File descriptor to mmap from.
    /// * `size` - Size of memory region in bytes.
    pub fn from_fd(fd: &AsRawFd, size: usize) -> Result<MemoryMapping> {
        // This is safe because we are creating a mapping in a place not already used by any other
        // area in this process.
        let addr = unsafe {
            libc::mmap(
                null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if addr.is_null() {
            return Err(Error::SystemCallFailed(sys_util::Error::last()));
        }
        Ok(MemoryMapping {
            addr: addr as *mut u8,
            size,
        })
    }

    /// Returns a pointer to the beginning of the memory region.  Should only be
    /// used for passing this region to ioctls for setting guest memory.
    pub fn as_ptr(&self) -> *mut u8 {
        self.addr
    }

    /// Returns the size of the memory region in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Writes a slice to the memory region at the specified offset.
    /// Returns the number of bytes written.  The number of bytes written can
    /// be less than the length of the slice if there isn't enough room in the
    /// memory region.
    ///
    /// # Examples
    /// * Write a slice at offset 256.
    ///
    /// ```
    /// #   use memory_model::MemoryMapping;
    /// #   let mut mem_map = MemoryMapping::new(1024).unwrap();
    ///     let res = mem_map.write_slice(&[1,2,3,4,5], 256);
    ///     assert!(res.is_ok());
    ///     assert_eq!(res.unwrap(), 5);
    /// ```
    pub fn write_slice(&self, buf: &[u8], offset: usize) -> Result<usize> {
        if offset >= self.size {
            return Err(Error::InvalidAddress);
        }
        unsafe {
            // Guest memory can't strictly be modeled as a slice because it is
            // volatile.  Writing to it with what compiles down to a memcpy
            // won't hurt anything as long as we get the bounds checks right.
            let mut slice: &mut [u8] = &mut self.as_mut_slice()[offset..];
            Ok(slice.write(buf).map_err(Error::WriteToMemory)?)
        }
    }

    /// Reads to a slice from the memory region at the specified offset.
    /// Returns the number of bytes read.  The number of bytes read can
    /// be less than the length of the slice if there isn't enough room in the
    /// memory region.
    ///
    /// # Examples
    /// * Read a slice of size 16 at offset 256.
    ///
    /// ```
    /// #   use memory_model::MemoryMapping;
    /// #   let mut mem_map = MemoryMapping::new(1024).unwrap();
    ///     let buf = &mut [0u8; 16];
    ///     let res = mem_map.read_slice(buf, 256);
    ///     assert!(res.is_ok());
    ///     assert_eq!(res.unwrap(), 16);
    /// ```
    pub fn read_slice(&self, mut buf: &mut [u8], offset: usize) -> Result<usize> {
        if offset >= self.size {
            return Err(Error::InvalidAddress);
        }
        unsafe {
            // Guest memory can't strictly be modeled as a slice because it is
            // volatile.  Writing to it with what compiles down to a memcpy
            // won't hurt anything as long as we get the bounds checks right.
            let slice: &[u8] = &self.as_slice()[offset..];
            Ok(buf.write(slice).map_err(Error::ReadFromMemory)?)
        }
    }

    /// Writes an object to the memory region at the specified offset.
    /// Returns Ok(()) if the object fits, or Err if it extends past the end.
    ///
    /// # Examples
    /// * Write a u64 at offset 16.
    ///
    /// ```
    /// #   use memory_model::MemoryMapping;
    /// #   let mut mem_map = MemoryMapping::new(1024).unwrap();
    ///     let res = mem_map.write_obj(55u64, 16);
    ///     assert!(res.is_ok());
    /// ```
    pub fn write_obj<T: DataInit>(&self, val: T, offset: usize) -> Result<()> {
        unsafe {
            // Guest memory can't strictly be modeled as a slice because it is
            // volatile.  Writing to it with what compiles down to a memcpy
            // won't hurt anything as long as we get the bounds checks right.
            if offset + std::mem::size_of::<T>() > self.size {
                return Err(Error::InvalidAddress);
            }
            std::ptr::write_volatile(&mut self.as_mut_slice()[offset..] as *mut _ as *mut T, val);
            Ok(())
        }
    }

    /// Reads on object from the memory region at the given offset.
    /// Reading from a volatile area isn't strictly safe as it could change
    /// mid-read.  However, as long as the type T is plain old data and can
    /// handle random initialization, everything will be OK.
    ///
    /// # Examples
    /// * Read a u64 written to offset 32.
    ///
    /// ```
    /// #   use memory_model::MemoryMapping;
    /// #   let mut mem_map = MemoryMapping::new(1024).unwrap();
    ///     let res = mem_map.write_obj(55u64, 32);
    ///     assert!(res.is_ok());
    ///     let num: u64 = mem_map.read_obj(32).unwrap();
    ///     assert_eq!(55, num);
    /// ```
    pub fn read_obj<T: DataInit>(&self, offset: usize) -> Result<T> {
        if offset + std::mem::size_of::<T>() > self.size {
            return Err(Error::InvalidAddress);
        }
        unsafe {
            // This is safe because by definition Copy types can have their bits
            // set arbitrarily and still be valid.
            Ok(std::ptr::read_volatile(
                &self.as_slice()[offset..] as *const _ as *const T,
            ))
        }
    }

    /// Reads data from a readable object like a File and writes it to guest memory.
    ///
    /// # Arguments
    /// * `mem_offset` - Begin writing memory at this offset.
    /// * `src` - Read from `src` to memory.
    /// * `count` - Read `count` bytes from `src` to memory.
    ///
    /// # Examples
    ///
    /// * Read bytes from /dev/urandom
    ///
    /// ```
    /// # use memory_model::MemoryMapping;
    /// # use std::fs::File;
    /// # use std::path::Path;
    /// # fn test_read_random() -> Result<u32, ()> {
    /// #     let mut mem_map = MemoryMapping::new(1024).unwrap();
    ///       let mut file = File::open(Path::new("/dev/urandom")).map_err(|_| ())?;
    ///       mem_map.read_to_memory(32, &mut file, 128).map_err(|_| ())?;
    ///       let rand_val: u32 =  mem_map.read_obj(40).map_err(|_| ())?;
    /// #     Ok(rand_val)
    /// # }
    /// ```
    pub fn read_to_memory<F>(&self, mem_offset: usize, src: &mut F, count: usize) -> Result<()>
    where
        F: Read,
    {
        let mem_end = mem_offset + count;
        if mem_end > self.size() {
            return Err(Error::InvalidRange(mem_offset, count));
        }
        unsafe {
            // It is safe to overwrite the volatile memory. Accessing the guest
            // memory as a mutable slice is OK because nothing assumes another
            // thread won't change what is loaded.
            let dst = &mut self.as_mut_slice()[mem_offset..mem_end];
            src.read_exact(dst).map_err(Error::ReadFromSource)?;
        }
        Ok(())
    }

    /// Writes data from memory to a writable object.
    ///
    /// # Arguments
    /// * `mem_offset` - Begin reading memory from this offset.
    /// * `dst` - Write from memory to `dst`.
    /// * `count` - Read `count` bytes from memory to `src`.
    ///
    /// # Examples
    ///
    /// * Write 128 bytes to /dev/null
    ///
    /// ```
    /// # use memory_model::MemoryMapping;
    /// # use std::fs::File;
    /// # use std::path::Path;
    /// # fn test_write_null() -> Result<(), ()> {
    /// #     let mut mem_map = MemoryMapping::new(1024).unwrap();
    ///       let mut file = File::open(Path::new("/dev/null")).map_err(|_| ())?;
    ///       mem_map.write_from_memory(32, &mut file, 128).map_err(|_| ())?;
    /// #     Ok(())
    /// # }
    /// ```
    pub fn write_from_memory<F>(&self, mem_offset: usize, dst: &mut F, count: usize) -> Result<()>
    where
        F: Write,
    {
        let mem_end = match mem_offset.checked_add(count) {
            None => return Err(Error::InvalidRange(mem_offset, count)),
            Some(m) => m,
        };
        if mem_end > self.size() {
            return Err(Error::InvalidRange(mem_offset, count));
        }
        unsafe {
            // It is safe to read from volatile memory. Accessing the guest
            // memory as a slice is OK because nothing assumes another thread
            // won't change what is loaded.
            let src = &self.as_mut_slice()[mem_offset..mem_end];
            dst.write_all(src).map_err(Error::ReadFromSource)?;
        }
        Ok(())
    }

    unsafe fn as_slice(&self) -> &[u8] {
        // This is safe because we mapped the area at addr ourselves, so this slice will not
        // overflow. However, it is possible to alias.
        std::slice::from_raw_parts(self.addr, self.size)
    }

    unsafe fn as_mut_slice(&self) -> &mut [u8] {
        // This is safe because we mapped the area at addr ourselves, so this slice will not
        // overflow. However, it is possible to alias.
        std::slice::from_raw_parts_mut(self.addr, self.size)
    }
}

impl Drop for MemoryMapping {
    fn drop(&mut self) {
        // This is safe because we mmap the area at addr ourselves, and nobody
        // else is holding a reference to it.
        unsafe {
            libc::munmap(self.addr as *mut libc::c_void, self.size);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate tempfile;

    use self::tempfile::tempfile;
    use super::*;
    use std::fs::File;
    use std::mem;
    use std::path::Path;

    #[test]
    fn basic_map() {
        let m = MemoryMapping::new(1024).unwrap();
        assert_eq!(1024, m.size());
    }

    #[test]
    fn test_write_past_end() {
        let m = MemoryMapping::new(5).unwrap();
        let res = m.write_slice(&[1, 2, 3, 4, 5, 6], 0);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), 5);
    }

    #[test]
    fn slice_read_and_write() {
        let mem_map = MemoryMapping::new(5).unwrap();
        let sample_buf = [1, 2, 3];
        assert!(mem_map.write_slice(&sample_buf, 5).is_err());
        assert!(mem_map.write_slice(&sample_buf, 2).is_ok());
        let mut buf = [0u8; 3];
        assert!(mem_map.read_slice(&mut buf, 5).is_err());
        assert!(mem_map.read_slice(&mut buf, 2).is_ok());
        assert_eq!(buf, sample_buf);
    }

    #[test]
    fn obj_read_and_write() {
        let mem_map = MemoryMapping::new(5).unwrap();
        assert!(mem_map.write_obj(55u16, 4).is_err());
        assert!(mem_map.write_obj(55u16, 2).is_ok());
        assert_eq!(mem_map.read_obj::<u16>(2).unwrap(), 55u16);
        assert!(mem_map.read_obj::<u16>(4).is_err());
    }

    #[test]
    fn mem_read_and_write() {
        let mem_map = MemoryMapping::new(5).unwrap();
        assert!(mem_map.write_obj(!0u32, 1).is_ok());
        let mut file = File::open(Path::new("/dev/zero")).unwrap();
        assert!(mem_map
            .read_to_memory(2, &mut file, mem::size_of::<u32>())
            .is_err());

        assert!(mem_map
            .read_to_memory(1, &mut file, mem::size_of::<u32>())
            .is_ok());

        let mut f = tempfile().unwrap();
        assert!(mem_map
            .read_to_memory(1, &mut f, mem::size_of::<u32>())
            .is_err());
        format!(
            "{:?}",
            mem_map.read_to_memory(1, &mut f, mem::size_of::<u32>())
        );

        assert_eq!(mem_map.read_obj::<u32>(1).unwrap(), 0);

        let mut sink = Vec::new();
        assert!(mem_map
            .write_from_memory(1, &mut sink, mem::size_of::<u32>())
            .is_ok());
        assert!(mem_map
            .write_from_memory(2, &mut sink, mem::size_of::<u32>())
            .is_err());
        format!(
            "{:?}",
            mem_map.write_from_memory(2, &mut sink, mem::size_of::<u32>())
        );
        assert_eq!(sink, vec![0; mem::size_of::<u32>()]);
    }

    #[test]
    fn mapped_file_read() {
        let mut f = tempfile().unwrap();
        let sample_buf = &[1, 2, 3, 4, 5];
        assert!(f.write_all(sample_buf).is_ok());

        let mem_map = MemoryMapping::from_fd(&f, sample_buf.len()).unwrap();
        let buf = &mut [0u8; 16];
        assert_eq!(mem_map.read_slice(buf, 0).unwrap(), sample_buf.len());
        assert_eq!(buf[0..sample_buf.len()], sample_buf[..]);
    }
}
