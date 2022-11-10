// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//
//! Helper for creating valid kernel command line strings.

use std::ffi::CString;
use std::fmt;
use std::result;

use vm_memory::{Address, GuestAddress, GuestUsize};

const INIT_ARGS_SEPARATOR: &str = " -- ";

/// The error type for command line building operations.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Null terminator identified in the command line.
    NullTerminator,
    /// No boot args inserted into cmdline.
    NoBootArgsInserted,
    /// Invalid capacity provided.
    InvalidCapacity,
    /// Operation would have resulted in a non-printable ASCII character.
    InvalidAscii,
    /// Key/Value Operation would have had a space in it.
    HasSpace,
    /// Key/Value Operation would have had an equals sign in it.
    HasEquals,
    /// Key/Value Operation was not passed a value.
    MissingVal(String),
    /// 0-sized virtio MMIO device passed to the kernel command line builder.
    MmioSize,
    /// Operation would have made the command line too large.
    TooLarge,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::NullTerminator => {
                write!(f, "Null terminator detected in the command line structure.")
            }
            Error::NoBootArgsInserted => write!(f, "Cmdline cannot contain only init args."),
            Error::InvalidCapacity => write!(f, "Invalid cmdline capacity provided."),
            Error::InvalidAscii => write!(f, "String contains a non-printable ASCII character."),
            Error::HasSpace => write!(f, "String contains a space."),
            Error::HasEquals => write!(f, "String contains an equals sign."),
            Error::MissingVal(ref k) => write!(f, "Missing value for key {}.", k),
            Error::MmioSize => write!(
                f,
                "0-sized virtio MMIO device passed to the kernel command line builder."
            ),
            Error::TooLarge => write!(f, "Inserting string would make command line too long."),
        }
    }
}

impl std::error::Error for Error {}

/// Specialized [`Result`] type for command line operations.
///
/// [`Result`]: https://doc.rust-lang.org/std/result/enum.Result.html
pub type Result<T> = result::Result<T, Error>;

fn valid_char(c: char) -> bool {
    matches!(c, ' '..='~')
}

fn valid_str(s: &str) -> Result<()> {
    if s.chars().all(valid_char) {
        Ok(())
    } else {
        Err(Error::InvalidAscii)
    }
}

fn valid_element(s: &str) -> Result<()> {
    if !s.chars().all(valid_char) {
        Err(Error::InvalidAscii)
    } else if s.contains(' ') {
        Err(Error::HasSpace)
    } else if s.contains('=') {
        Err(Error::HasEquals)
    } else {
        Ok(())
    }
}

/// A builder for a kernel command line string that validates the string as it's being built.
///
/// # Examples
///
/// ```rust
/// # use linux_loader::cmdline::*;
/// # use std::ffi::CString;
/// let mut cl = Cmdline::new(100).unwrap();
/// cl.insert_str("foobar").unwrap();
/// assert_eq!(cl.as_cstring().unwrap().as_bytes_with_nul(), b"foobar\0");
/// ```
#[derive(Clone, Debug)]
pub struct Cmdline {
    boot_args: String,
    init_args: String,
    capacity: usize,
}

impl Cmdline {
    /// Constructs an empty [`Cmdline`] with the given capacity, including the nul terminator.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Command line capacity. Must be greater than 0.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use linux_loader::cmdline::*;
    /// let cl = Cmdline::new(100).unwrap();
    /// ```
    /// [`Cmdline`]: struct.Cmdline.html
    pub fn new(capacity: usize) -> Result<Cmdline> {
        if capacity == 0 {
            return Err(Error::InvalidCapacity);
        }

        Ok(Cmdline {
            boot_args: String::new(),
            init_args: String::new(),
            capacity,
        })
    }

    /// Validates and inserts a key-value pair representing a boot
    /// arg of the command line.
    ///
    /// # Arguments
    ///
    /// * `key` - Key to be inserted in the command line string.
    /// * `val` - Value corresponding to `key`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use linux_loader::cmdline::*;
    /// let mut cl = Cmdline::new(100).unwrap();
    /// cl.insert("foo", "bar");
    /// assert_eq!(cl.as_cstring().unwrap().as_bytes_with_nul(), b"foo=bar\0");
    /// ```
    pub fn insert<T: AsRef<str>>(&mut self, key: T, val: T) -> Result<()> {
        let k = key.as_ref();
        let v = val.as_ref();

        valid_element(k)?;
        valid_element(v)?;

        let kv_str = format!("{}={}", k, v);

        self.insert_str(kv_str)
    }

    /// Validates and inserts a key-value1,...,valueN pair representing a
    /// boot arg of the command line.
    ///
    /// # Arguments
    ///
    /// * `key` - Key to be inserted in the command line string.
    /// * `vals` - Values corresponding to `key`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use linux_loader::cmdline::*;
    /// # use std::ffi::CString;
    /// let mut cl = Cmdline::new(100).unwrap();
    /// cl.insert_multiple("foo", &["bar", "baz"]);
    /// assert_eq!(
    ///     cl.as_cstring().unwrap().as_bytes_with_nul(),
    ///     b"foo=bar,baz\0"
    /// );
    /// ```
    pub fn insert_multiple<T: AsRef<str>>(&mut self, key: T, vals: &[T]) -> Result<()> {
        let k = key.as_ref();

        valid_element(k)?;
        if vals.is_empty() {
            return Err(Error::MissingVal(k.to_string()));
        }

        let kv_str = format!(
            "{}={}",
            k,
            vals.iter()
                .map(|v| -> Result<&str> {
                    valid_element(v.as_ref())?;
                    Ok(v.as_ref())
                })
                .collect::<Result<Vec<&str>>>()?
                .join(",")
        );

        self.insert_str(kv_str)
    }

    /// Inserts a string in the boot args; returns an error if the string
    /// is invalid.
    ///
    /// # Arguments
    ///
    /// * `slug` - String to be appended to the command line.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use linux_loader::cmdline::*;
    /// # use std::ffi::CString;
    /// let mut cl = Cmdline::new(100).unwrap();
    /// cl.insert_str("foobar").unwrap();
    /// assert_eq!(cl.as_cstring().unwrap().as_bytes_with_nul(), b"foobar\0");
    /// ```
    pub fn insert_str<T: AsRef<str>>(&mut self, slug: T) -> Result<()> {
        // Step 1: Check if the string provided is a valid boot arg string and remove any
        // leading or trailing whitespaces.
        let s = slug.as_ref().trim();
        valid_str(s)?;

        // Step 2: Check if cmdline capacity is not exceeded when inserting the boot arg
        // string provided.
        let mut cmdline_size = self.get_null_terminated_representation_size();

        // Count extra space required if this is not the first boot arg of the cmdline.
        if !self.boot_args.is_empty() {
            cmdline_size = cmdline_size.checked_add(1).ok_or(Error::TooLarge)?;
        }

        // Count extra space required for the insertion of the new boot arg string.
        cmdline_size = cmdline_size.checked_add(s.len()).ok_or(Error::TooLarge)?;

        if cmdline_size > self.capacity {
            return Err(Error::TooLarge);
        }

        // Step 3: Insert the string as boot args to the cmdline.
        if !self.boot_args.is_empty() {
            self.boot_args.push(' ');
        }

        self.boot_args.push_str(s);

        Ok(())
    }

    /// Inserts a string in the init args; returns an error if the string
    /// is invalid.
    ///
    /// # Arguments
    ///
    /// * `slug` - String to be appended to the command line.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use linux_loader::cmdline::*;
    /// # use std::ffi::CString;
    /// let mut cl = Cmdline::new(100).unwrap();
    /// cl.insert_str("foo").unwrap();
    /// cl.insert_init_args("bar").unwrap();
    /// assert_eq!(
    ///     cl.as_cstring().unwrap().as_bytes_with_nul(),
    ///     b"foo -- bar\0"
    /// );
    /// ```
    pub fn insert_init_args<T: AsRef<str>>(&mut self, slug: T) -> Result<()> {
        // Step 1: Check if the string provided is a valid init arg string and remove any
        // leading or trailing whitespaces.
        let s = slug.as_ref().trim();
        valid_str(s)?;

        // Step 2: Check if cmdline capacity is not exceeded when inserting the init arg
        // string provided.
        let mut cmdline_size = self.get_null_terminated_representation_size();

        // Count extra space required if this is not the first init arg of the cmdline.
        cmdline_size = cmdline_size
            .checked_add(if self.init_args.is_empty() {
                INIT_ARGS_SEPARATOR.len()
            } else {
                1
            })
            .ok_or(Error::TooLarge)?;

        // Count extra space required for the insertion of the new init arg string.
        cmdline_size = cmdline_size.checked_add(s.len()).ok_or(Error::TooLarge)?;

        if cmdline_size > self.capacity {
            return Err(Error::TooLarge);
        }

        // Step 3: Insert the string as init args to the cmdline.
        if !self.init_args.is_empty() {
            self.init_args.push(' ');
        }

        self.init_args.push_str(s);

        Ok(())
    }

    fn get_null_terminated_representation_size(&self) -> usize {
        // Counting current size of the cmdline (no overflows are possible as long as the cmdline
        // size is always smaller or equal to the cmdline capacity provided in constructor)
        let mut cmdline_size = self.boot_args.len() + 1; // for null terminator

        if !self.init_args.is_empty() {
            cmdline_size += INIT_ARGS_SEPARATOR.len() + self.init_args.len();
        }

        cmdline_size
    }

    /// Returns a C compatible representation of the command line
    /// The Linux kernel expects a null terminated cmdline according to the source:
    /// https://elixir.bootlin.com/linux/v5.10.139/source/kernel/params.c#L179
    ///
    /// To get bytes of the cmdline to be written in guest's memory (including the
    /// null terminator) from this representation, use CString::as_bytes_with_nul()
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use linux_loader::cmdline::*;
    /// let mut cl = Cmdline::new(20).unwrap();
    /// cl.insert_str("foo").unwrap();
    /// cl.insert_init_args("bar").unwrap();
    /// assert_eq!(
    ///     cl.as_cstring().unwrap().as_bytes_with_nul(),
    ///     b"foo -- bar\0"
    /// );
    /// ```
    pub fn as_cstring(&self) -> Result<CString> {
        if self.boot_args.is_empty() && self.init_args.is_empty() {
            CString::new("".to_string()).map_err(|_| Error::NullTerminator)
        } else if self.boot_args.is_empty() {
            Err(Error::NoBootArgsInserted)
        } else if self.init_args.is_empty() {
            CString::new(self.boot_args.to_string()).map_err(|_| Error::NullTerminator)
        } else {
            CString::new(format!(
                "{}{}{}",
                self.boot_args, INIT_ARGS_SEPARATOR, self.init_args
            ))
            .map_err(|_| Error::NullTerminator)
        }
    }

    /// Adds a virtio MMIO device to the kernel command line.
    ///
    /// Multiple devices can be specified, with multiple `virtio_mmio.device=` options. This
    /// function must be called once per device.
    /// The function appends a string of the following format to the kernel command line:
    /// `<size>@<baseaddr>:<irq>[:<id>]`.
    /// For more details see the [documentation] (section `virtio_mmio.device=`).
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the slot the device occupies on the MMIO bus.
    /// * `baseaddr` - Physical base address of the device.
    /// * `irq` - Interrupt number to be used by the device.
    /// * `id` - Optional platform device ID.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use linux_loader::cmdline::*;
    /// # use std::ffi::CString;
    /// # use vm_memory::{GuestAddress, GuestUsize};
    /// let mut cl = Cmdline::new(100).unwrap();
    /// cl.add_virtio_mmio_device(1 << 12, GuestAddress(0x1000), 5, Some(42))
    ///     .unwrap();
    /// assert_eq!(
    ///     cl.as_cstring().unwrap().as_bytes_with_nul(),
    ///     b"virtio_mmio.device=4K@0x1000:5:42\0"
    /// );
    /// ```
    ///
    /// [documentation]: https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html
    pub fn add_virtio_mmio_device(
        &mut self,
        size: GuestUsize,
        baseaddr: GuestAddress,
        irq: u32,
        id: Option<u32>,
    ) -> Result<()> {
        if size == 0 {
            return Err(Error::MmioSize);
        }

        let mut device_str = format!(
            "virtio_mmio.device={}@0x{:x?}:{}",
            Self::guestusize_to_str(size),
            baseaddr.raw_value(),
            irq
        );
        if let Some(id) = id {
            device_str.push_str(format!(":{}", id).as_str());
        }
        self.insert_str(&device_str)
    }

    // Converts a `GuestUsize` to a concise string representation, with multiplier suffixes.
    fn guestusize_to_str(size: GuestUsize) -> String {
        const KB_MULT: u64 = 1 << 10;
        const MB_MULT: u64 = KB_MULT << 10;
        const GB_MULT: u64 = MB_MULT << 10;

        if size % GB_MULT == 0 {
            return format!("{}G", size / GB_MULT);
        }
        if size % MB_MULT == 0 {
            return format!("{}M", size / MB_MULT);
        }
        if size % KB_MULT == 0 {
            return format!("{}K", size / KB_MULT);
        }
        size.to_string()
    }

    fn check_outside_double_quotes(slug: &str) -> bool {
        slug.matches('\"').count() % 2 == 0
    }

    /// Tries to build a [`Cmdline`] with a given capacity from a str. The format of the
    /// str provided must be one of the followings:
    /// -> <boot args> -- <init args>
    /// -> <boot args>
    /// where <boot args> and <init args> can contain '--' only if double quoted and
    /// <boot args> and <init args> contain at least one non-whitespace char each.
    ///
    /// Providing a str not following these rules might end up in undefined behaviour of
    /// the resulting `Cmdline`.
    ///
    /// # Arguments
    ///
    /// * `cmdline_raw` - Contains boot params and init params of the cmdline.
    /// * `capacity` - Capacity of the cmdline.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use linux_loader::cmdline::*;
    /// let cl = Cmdline::try_from("foo -- bar", 100).unwrap();
    /// assert_eq!(
    ///     cl.as_cstring().unwrap().as_bytes_with_nul(),
    ///     b"foo -- bar\0"
    /// );
    /// ```
    pub fn try_from(cmdline_raw: &str, capacity: usize) -> Result<Cmdline> {
        // The cmdline_raw argument should contain no more than one INIT_ARGS_SEPARATOR sequence
        // that is not double quoted; in case the INIT_ARGS_SEPARATOR is found all chars following
        // it will be parsed as init args.

        if capacity == 0 {
            return Err(Error::InvalidCapacity);
        }

        // Step 1: Extract boot args and init args from input by searching for INIT_ARGS_SEPARATOR.

        // Check first occurrence of the INIT_ARGS_SEPARATOR that is not between double quotes.
        // All chars following the INIT_ARGS_SEPARATOR will be parsed as init args.
        let (mut boot_args, mut init_args) = match cmdline_raw
            .match_indices(INIT_ARGS_SEPARATOR)
            .find(|&separator_occurrence| {
                Self::check_outside_double_quotes(&cmdline_raw[..(separator_occurrence.0)])
            }) {
            None => (cmdline_raw, ""),
            Some((delimiter_index, _)) => (
                &cmdline_raw[..delimiter_index],
                // This does not overflow as long as `delimiter_index + INIT_ARGS_SEPARATOR.len()`
                // is pointing to the first char after the INIT_ARGS_SEPARATOR which always exists;
                // as a result, `delimiter_index + INIT_ARGS_SEPARATOR.len()` is less or equal to the
                // length of the initial string.
                &cmdline_raw[(delimiter_index + INIT_ARGS_SEPARATOR.len())..],
            ),
        };

        boot_args = boot_args.trim();
        init_args = init_args.trim();

        // Step 2: Check if capacity provided for the cmdline is not exceeded and create a new `Cmdline`
        // if size check passes.
        let mut cmdline_size = boot_args.len().checked_add(1).ok_or(Error::TooLarge)?;

        if !init_args.is_empty() {
            cmdline_size = cmdline_size
                .checked_add(INIT_ARGS_SEPARATOR.len())
                .ok_or(Error::TooLarge)?;

            cmdline_size = cmdline_size
                .checked_add(init_args.len())
                .ok_or(Error::TooLarge)?;
        }

        if cmdline_size > capacity {
            return Err(Error::InvalidCapacity);
        }

        Ok(Cmdline {
            boot_args: boot_args.to_string(),
            init_args: init_args.to_string(),
            capacity,
        })
    }
}

impl TryFrom<Cmdline> for Vec<u8> {
    type Error = Error;

    fn try_from(cmdline: Cmdline) -> result::Result<Self, Self::Error> {
        cmdline
            .as_cstring()
            .map(|cmdline_cstring| cmdline_cstring.into_bytes_with_nul())
    }
}

impl PartialEq for Cmdline {
    fn eq(&self, other: &Self) -> bool {
        self.as_cstring() == other.as_cstring()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    const CMDLINE_MAX_SIZE: usize = 4096;

    #[test]
    fn test_insert_hello_world() {
        let mut cl = Cmdline::new(100).unwrap();
        assert_eq!(cl.as_cstring().unwrap().as_bytes_with_nul(), b"\0");
        assert!(cl.insert("hello", "world").is_ok());
        assert_eq!(
            cl.as_cstring().unwrap().as_bytes_with_nul(),
            b"hello=world\0"
        );
    }

    #[test]
    fn test_insert_multi() {
        let mut cl = Cmdline::new(100).unwrap();
        assert!(cl.insert("hello", "world").is_ok());
        assert!(cl.insert("foo", "bar").is_ok());
        assert_eq!(
            cl.as_cstring().unwrap().as_bytes_with_nul(),
            b"hello=world foo=bar\0"
        );
    }

    #[test]
    fn test_insert_space() {
        let mut cl = Cmdline::new(100).unwrap();
        assert_eq!(cl.insert("a ", "b"), Err(Error::HasSpace));
        assert_eq!(cl.insert("a", "b "), Err(Error::HasSpace));
        assert_eq!(cl.insert("a ", "b "), Err(Error::HasSpace));
        assert_eq!(cl.insert(" a", "b"), Err(Error::HasSpace));
        assert_eq!(cl.as_cstring().unwrap().as_bytes_with_nul(), b"\0");
    }

    #[test]
    fn test_insert_equals() {
        let mut cl = Cmdline::new(100).unwrap();
        assert_eq!(cl.insert("a=", "b"), Err(Error::HasEquals));
        assert_eq!(cl.insert("a", "b="), Err(Error::HasEquals));
        assert_eq!(cl.insert("a=", "b "), Err(Error::HasEquals));
        assert_eq!(cl.insert("=a", "b"), Err(Error::HasEquals));
        assert_eq!(cl.insert("a", "=b"), Err(Error::HasEquals));
        assert_eq!(cl.as_cstring().unwrap().as_bytes_with_nul(), b"\0");
    }

    #[test]
    fn test_insert_emoji() {
        let mut cl = Cmdline::new(100).unwrap();
        assert_eq!(cl.insert("heart", "💖"), Err(Error::InvalidAscii));
        assert_eq!(cl.insert("💖", "love"), Err(Error::InvalidAscii));
        assert_eq!(cl.insert_str("heart=💖"), Err(Error::InvalidAscii));
        assert_eq!(
            cl.insert_multiple("💖", &["heart", "love"]),
            Err(Error::InvalidAscii)
        );
        assert_eq!(
            cl.insert_multiple("heart", &["💖", "love"]),
            Err(Error::InvalidAscii)
        );
        assert_eq!(cl.as_cstring().unwrap().as_bytes_with_nul(), b"\0");
    }

    #[test]
    fn test_insert_string() {
        let mut cl = Cmdline::new(13).unwrap();
        assert_eq!(cl.as_cstring().unwrap().as_bytes_with_nul(), b"\0");
        assert!(cl.insert_str("noapic").is_ok());
        assert_eq!(cl.as_cstring().unwrap().as_bytes_with_nul(), b"noapic\0");
        assert!(cl.insert_str("nopci").is_ok());
        assert_eq!(
            cl.as_cstring().unwrap().as_bytes_with_nul(),
            b"noapic nopci\0"
        );
    }

    #[test]
    fn test_insert_too_large() {
        let mut cl = Cmdline::new(4).unwrap();
        assert_eq!(cl.insert("hello", "world"), Err(Error::TooLarge));
        assert_eq!(cl.insert("a", "world"), Err(Error::TooLarge));
        assert_eq!(cl.insert("hello", "b"), Err(Error::TooLarge));
        assert!(cl.insert("a", "b").is_ok());
        assert_eq!(cl.insert("a", "b"), Err(Error::TooLarge));
        assert_eq!(cl.insert_str("a"), Err(Error::TooLarge));
        assert_eq!(cl.as_cstring().unwrap().as_bytes_with_nul(), b"a=b\0");

        let mut cl = Cmdline::new(10).unwrap();
        assert!(cl.insert("ab", "ba").is_ok()); // adds 5 length; 4 chars available
        assert_eq!(cl.insert("c", "da"), Err(Error::TooLarge)); // adds 5 (including space) length
        assert!(cl.insert("c", "d").is_ok()); // adds 4 (including space) length

        let mut cl = Cmdline::new(11).unwrap();
        assert!(cl.insert("ab", "ba").is_ok()); // adds 5 length; 5 chars available
        assert_eq!(cl.insert_init_args("da"), Err(Error::TooLarge)); // adds 6 (including INIT_ARGS_SEPARATOR) length
        assert!(cl.insert_init_args("d").is_ok()); // adds 6 (including INIT_ARGS_SEPARATOR)

        let mut cl = Cmdline::new(20).unwrap();
        assert!(cl.insert("ab", "ba").is_ok()); // adds 5 length; 14 chars available
        assert!(cl.insert_init_args("da").is_ok()); // 8 chars available
        assert_eq!(cl.insert_init_args("abcdabcd"), Err(Error::TooLarge)); // adds 9 (including space) length
        assert!(cl.insert_init_args("abcdabc").is_ok()); // adds 8 (including space) length
    }

    #[test]
    fn test_add_virtio_mmio_device() {
        let mut cl = Cmdline::new(5).unwrap();
        assert_eq!(
            cl.add_virtio_mmio_device(0, GuestAddress(0), 0, None),
            Err(Error::MmioSize)
        );
        assert_eq!(
            cl.add_virtio_mmio_device(1, GuestAddress(0), 0, None),
            Err(Error::TooLarge)
        );

        let mut cl = Cmdline::new(150).unwrap();
        assert!(cl
            .add_virtio_mmio_device(1, GuestAddress(0), 1, None)
            .is_ok());
        let mut expected_str = "virtio_mmio.device=1@0x0:1".to_string();
        assert_eq!(
            cl.as_cstring().unwrap(),
            CString::new(expected_str.as_bytes()).unwrap()
        );

        assert!(cl
            .add_virtio_mmio_device(2 << 10, GuestAddress(0x100), 2, None)
            .is_ok());
        expected_str.push_str(" virtio_mmio.device=2K@0x100:2");
        assert_eq!(
            cl.as_cstring().unwrap(),
            CString::new(expected_str.as_bytes()).unwrap()
        );

        assert!(cl
            .add_virtio_mmio_device(3 << 20, GuestAddress(0x1000), 3, None)
            .is_ok());
        expected_str.push_str(" virtio_mmio.device=3M@0x1000:3");
        assert_eq!(
            cl.as_cstring().unwrap(),
            CString::new(expected_str.as_bytes()).unwrap()
        );

        assert!(cl
            .add_virtio_mmio_device(4 << 30, GuestAddress(0x0001_0000), 4, Some(42))
            .is_ok());
        expected_str.push_str(" virtio_mmio.device=4G@0x10000:4:42");
        assert_eq!(
            cl.as_cstring().unwrap(),
            CString::new(expected_str.as_bytes()).unwrap()
        );
    }

    #[test]
    fn test_insert_kv() {
        let mut cl = Cmdline::new(10).unwrap();

        let no_vals: Vec<&str> = vec![];
        assert_eq!(cl.insert_multiple("foo=", &no_vals), Err(Error::HasEquals));
        assert_eq!(
            cl.insert_multiple("foo", &no_vals),
            Err(Error::MissingVal("foo".to_string()))
        );
        assert_eq!(cl.insert_multiple("foo", &["bar "]), Err(Error::HasSpace));
        assert_eq!(
            cl.insert_multiple("foo", &["bar", "baz"]),
            Err(Error::TooLarge)
        );

        let mut cl = Cmdline::new(100).unwrap();
        assert!(cl.insert_multiple("foo", &["bar"]).is_ok());
        assert_eq!(cl.as_cstring().unwrap().as_bytes_with_nul(), b"foo=bar\0");

        let mut cl = Cmdline::new(100).unwrap();
        assert!(cl.insert_multiple("foo", &["bar", "baz"]).is_ok());
        assert_eq!(
            cl.as_cstring().unwrap().as_bytes_with_nul(),
            b"foo=bar,baz\0"
        );
    }

    #[test]
    fn test_try_from_cmdline_for_vec() {
        let cl = Cmdline::new(CMDLINE_MAX_SIZE).unwrap();
        assert_eq!(Vec::try_from(cl).unwrap(), vec![b'\0']);

        let cl = Cmdline::try_from("foo", CMDLINE_MAX_SIZE).unwrap();
        assert_eq!(Vec::try_from(cl).unwrap(), vec![b'f', b'o', b'o', b'\0']);

        let mut cl = Cmdline::new(CMDLINE_MAX_SIZE).unwrap();
        cl.insert_init_args("foo--bar").unwrap();
        assert_eq!(Vec::try_from(cl), Err(Error::NoBootArgsInserted));
    }

    #[test]
    fn test_partial_eq() {
        let mut c1 = Cmdline::new(20).unwrap();
        let mut c2 = Cmdline::new(30).unwrap();

        c1.insert_str("hello world!").unwrap();
        c2.insert_str("hello").unwrap();
        assert_ne!(c1, c2);

        // `insert_str` also adds a whitespace before the string being inserted.
        c2.insert_str("world!").unwrap();
        assert_eq!(c1, c2);

        let mut cl1 = Cmdline::new(CMDLINE_MAX_SIZE).unwrap();
        let mut cl2 = Cmdline::new(CMDLINE_MAX_SIZE).unwrap();

        assert_eq!(cl1, cl2);
        assert!(cl1
            .add_virtio_mmio_device(1, GuestAddress(0), 1, None)
            .is_ok());
        assert_ne!(cl1, cl2);
        assert!(cl2
            .add_virtio_mmio_device(1, GuestAddress(0), 1, None)
            .is_ok());
        assert_eq!(cl1, cl2);
    }

    #[test]
    fn test_try_from() {
        assert_eq!(
            Cmdline::try_from("foo --  bar", 0),
            Err(Error::InvalidCapacity)
        );
        assert_eq!(
            Cmdline::try_from("foo --  bar", 10),
            Err(Error::InvalidCapacity)
        );
        assert!(Cmdline::try_from("foo --  bar", 11).is_ok());

        let cl = Cmdline::try_from("hello=world foo=bar", CMDLINE_MAX_SIZE).unwrap();

        assert_eq!(cl.boot_args, "hello=world foo=bar");
        assert_eq!(cl.init_args, "");

        let cl = Cmdline::try_from("hello=world -- foo=bar", CMDLINE_MAX_SIZE).unwrap();

        assert_eq!(cl.boot_args, "hello=world");
        assert_eq!(cl.init_args, "foo=bar");

        let cl =
            Cmdline::try_from("hello=world --foo=bar -- arg1 --arg2", CMDLINE_MAX_SIZE).unwrap();

        assert_eq!(cl.boot_args, "hello=world --foo=bar");
        assert_eq!(cl.init_args, "arg1 --arg2");

        let cl = Cmdline::try_from("arg1-- arg2 --arg3", CMDLINE_MAX_SIZE).unwrap();

        assert_eq!(cl.boot_args, "arg1-- arg2 --arg3");
        assert_eq!(cl.init_args, "");

        let cl = Cmdline::try_from("--arg1-- -- arg2 -- --arg3", CMDLINE_MAX_SIZE).unwrap();

        assert_eq!(cl.boot_args, "--arg1--");
        assert_eq!(cl.init_args, "arg2 -- --arg3");

        let cl = Cmdline::try_from("a=\"b -- c\" d -- e ", CMDLINE_MAX_SIZE).unwrap();

        assert_eq!(cl.boot_args, "a=\"b -- c\" d");
        assert_eq!(cl.init_args, "e");

        let cl = Cmdline::try_from("foo--bar=baz a=\"b -- c\"", CMDLINE_MAX_SIZE).unwrap();

        assert_eq!(cl.boot_args, "foo--bar=baz a=\"b -- c\"");
        assert_eq!(cl.init_args, "");

        let cl = Cmdline::try_from("--foo --bar", CMDLINE_MAX_SIZE).unwrap();

        assert_eq!(cl.boot_args, "--foo --bar");
        assert_eq!(cl.init_args, "");

        let cl = Cmdline::try_from("foo=\"bar--baz\" foo", CMDLINE_MAX_SIZE).unwrap();

        assert_eq!(cl.boot_args, "foo=\"bar--baz\" foo");
        assert_eq!(cl.init_args, "");
    }

    #[test]
    fn test_error_try_from() {
        assert_eq!(Cmdline::try_from("", 0), Err(Error::InvalidCapacity));

        assert_eq!(
            Cmdline::try_from(
                String::from_utf8(vec![b'X'; CMDLINE_MAX_SIZE])
                    .unwrap()
                    .as_str(),
                CMDLINE_MAX_SIZE - 1
            ),
            Err(Error::InvalidCapacity)
        );

        let cl = Cmdline::try_from(
            "console=ttyS0 nomodules -- /etc/password --param",
            CMDLINE_MAX_SIZE,
        )
        .unwrap();
        assert_eq!(
            cl.as_cstring().unwrap().as_bytes_with_nul(),
            b"console=ttyS0 nomodules -- /etc/password --param\0"
        );
    }

    #[test]
    fn test_as_cstring() {
        let mut cl = Cmdline::new(CMDLINE_MAX_SIZE).unwrap();

        assert_eq!(cl.as_cstring().unwrap().into_bytes_with_nul(), b"\0");
        assert!(cl.insert_init_args("/etc/password").is_ok());
        assert_eq!(cl.as_cstring(), Err(Error::NoBootArgsInserted));
        assert_eq!(cl.boot_args, "");
        assert_eq!(cl.init_args, "/etc/password");
        assert!(cl.insert("console", "ttyS0").is_ok());
        assert_eq!(
            cl.as_cstring().unwrap().into_bytes_with_nul(),
            b"console=ttyS0 -- /etc/password\0"
        );
        assert!(cl.insert_str("nomodules").is_ok());
        assert_eq!(
            cl.as_cstring().unwrap().into_bytes_with_nul(),
            b"console=ttyS0 nomodules -- /etc/password\0"
        );
        assert!(cl.insert_init_args("--param").is_ok());
        assert_eq!(
            cl.as_cstring().unwrap().into_bytes_with_nul(),
            b"console=ttyS0 nomodules -- /etc/password --param\0"
        );
    }
}
