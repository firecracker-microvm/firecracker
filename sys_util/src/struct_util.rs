// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std;
use std::io::Read;
use std::mem;

#[derive(Debug)]
pub enum Error {
    ReadStruct,
}
pub type Result<T> = std::result::Result<T, Error>;

/// Reads a struct from an input buffer.
/// This is unsafe because the struct is initialized to unverified data read from the input.
/// `read_struct` should only be called to fill plain old data structs.  It is not endian safe.
///
/// # Arguments
///
/// * `f` - The input to read from.  Often this is a file.
/// * `out` - The struct to fill with data read from `f`.
pub unsafe fn read_struct<T: Copy, F: Read>(f: &mut F, out: &mut T) -> Result<()> {
    let out_slice = std::slice::from_raw_parts_mut(out as *mut T as *mut u8, mem::size_of::<T>());
    f.read_exact(out_slice).map_err(|_| Error::ReadStruct)?;
    Ok(())
}

/// Reads an array of structs from an input buffer.  Returns a Vec of structs initialized with data
/// from the specified input.
/// This is unsafe because the structs are initialized to unverified data read from the input.
/// `read_struct_slice` should only be called for plain old data structs.  It is not endian safe.
///
/// # Arguments
///
/// * `f` - The input to read from.  Often this is a file.
/// * `len` - The number of structs to fill with data read from `f`.
pub unsafe fn read_struct_slice<T: Copy, F: Read>(f: &mut F, len: usize) -> Result<Vec<T>> {
    let mut out: Vec<T> = Vec::with_capacity(len);
    out.set_len(len);
    let out_slice = std::slice::from_raw_parts_mut(
        out.as_ptr() as *mut T as *mut u8,
        mem::size_of::<T>() * len,
    );
    f.read_exact(out_slice).map_err(|_| Error::ReadStruct)?;
    Ok(out)
}

#[cfg(test)]
mod test {
    use std::io::Cursor;
    use std::mem;
    use super::*;

    #[derive(Clone, Copy, Debug, Default, PartialEq)]
    struct TestRead {
        a: u64,
        b: u8,
        c: u8,
        d: u8,
        e: u8,
    }

    #[test]
    fn struct_basic_read() {
        let orig = TestRead {
            a: 0x7766554433221100,
            b: 0x88,
            c: 0x99,
            d: 0xaa,
            e: 0xbb,
        };
        let source = unsafe {
            // Don't worry it's a test
            std::slice::from_raw_parts(
                &orig as *const _ as *const u8,
                std::mem::size_of::<TestRead>(),
            )
        };
        assert_eq!(mem::size_of::<TestRead>(), mem::size_of_val(&source));
        let mut tr: TestRead = Default::default();
        unsafe {
            read_struct(&mut Cursor::new(source), &mut tr).unwrap();
        }
        assert_eq!(orig, tr);
    }

    #[test]
    fn struct_read_past_end() {
        let orig = TestRead {
            a: 0x7766554433221100,
            b: 0x88,
            c: 0x99,
            d: 0xaa,
            e: 0xbb,
        };
        let source = unsafe {
            // Don't worry it's a test
            std::slice::from_raw_parts(
                &orig as *const _ as *const u8,
                std::mem::size_of::<TestRead>() - 1,
            )
        };
        let mut tr: TestRead = Default::default();
        unsafe {
            assert!(read_struct(&mut Cursor::new(source), &mut tr).is_err());
        }
    }

    #[test]
    fn struct_slice_read() {
        let orig = vec![
            TestRead {
                a: 0x7766554433221100,
                b: 0x88,
                c: 0x99,
                d: 0xaa,
                e: 0xbb,
            },
            TestRead {
                a: 0x7867564534231201,
                b: 0x02,
                c: 0x13,
                d: 0x24,
                e: 0x35,
            },
            TestRead {
                a: 0x7a69584736251403,
                b: 0x04,
                c: 0x15,
                d: 0x26,
                e: 0x37,
            },
        ];
        let source = unsafe {
            // Don't worry it's a test
            std::slice::from_raw_parts(
                orig.as_ptr() as *const u8,
                std::mem::size_of::<TestRead>() * 3,
            )
        };

        let tr: Vec<TestRead> = unsafe { read_struct_slice(&mut Cursor::new(source), 3).unwrap() };
        assert_eq!(orig, tr);
    }
}
