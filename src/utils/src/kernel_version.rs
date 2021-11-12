// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io::Error as IoError;
use std::result::Result;

use libc::{uname, utsname};

#[derive(Debug)]
pub enum Error {
    Uname(IoError),
    InvalidUtf8(std::string::FromUtf8Error),
    InvalidFormat,
    InvalidInt(std::num::ParseIntError),
}

#[derive(PartialEq, PartialOrd)]
#[cfg_attr(test, derive(Debug))]
pub struct KernelVersion {
    major: u16,
    minor: u16,
    patch: u16,
}

impl KernelVersion {
    pub fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub fn get() -> Result<Self, Error> {
        let mut name: utsname = utsname {
            sysname: [0; 65],
            nodename: [0; 65],
            release: [0; 65],
            version: [0; 65],
            machine: [0; 65],
            domainname: [0; 65],
        };
        let res = unsafe { uname((&mut name) as *mut utsname) };

        if res < 0 {
            return Err(Error::Uname(IoError::last_os_error()));
        }

        Self::parse(
            String::from_utf8(name.release.iter().map(|c| *c as u8).collect())
                .map_err(Error::InvalidUtf8)?,
        )
    }

    fn parse(release: String) -> Result<Self, Error> {
        let mut tokens = release.split('.');

        let major = tokens.next().ok_or(Error::InvalidFormat)?;
        let minor = tokens.next().ok_or(Error::InvalidFormat)?;
        let mut patch = tokens.next().ok_or(Error::InvalidFormat)?;

        // Parse the `patch`, since it may contain other tokens as well.
        if let Some(index) = patch.find(|c: char| !c.is_digit(10)) {
            patch = &patch[..index];
        }

        Ok(Self {
            major: major.parse().map_err(Error::InvalidInt)?,
            minor: minor.parse().map_err(Error::InvalidInt)?,
            patch: patch.parse().map_err(Error::InvalidInt)?,
        })
    }
}

impl std::fmt::Display for KernelVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

pub fn min_kernel_version_for_io_uring() -> KernelVersion {
    KernelVersion::new(5, 10, 0)
}

#[macro_export]
macro_rules! skip_if_kernel_lt_5_10 {
    () => {
        if KernelVersion::get().unwrap() < KernelVersion::new(5, 10, 0) {
            return;
        }
    };
}

#[macro_export]
macro_rules! skip_if_kernel_ge_5_10 {
    () => {
        if KernelVersion::get().unwrap() >= KernelVersion::new(5, 10, 0) {
            return;
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_get() {
        assert!(KernelVersion::get().is_ok());
    }

    #[test]
    fn test_parse_valid() {
        assert_eq!(
            KernelVersion::parse("5.10.0".to_string()).unwrap(),
            KernelVersion::new(5, 10, 0),
        );
        assert_eq!(
            KernelVersion::parse("5.10.50".to_string()).unwrap(),
            KernelVersion::new(5, 10, 50)
        );
        assert_eq!(
            KernelVersion::parse("5.10.50-38.132.amzn2int.x86_64".to_string()).unwrap(),
            KernelVersion::new(5, 10, 50)
        );
    }

    #[test]
    fn test_parse_invalid() {
        assert!(KernelVersion::parse("".to_string()).is_err());
        assert!(KernelVersion::parse("ffff".to_string()).is_err());
        assert!(KernelVersion::parse("ffff.55.0".to_string()).is_err());
        assert!(KernelVersion::parse("5.10.".to_string()).is_err());
        assert!(KernelVersion::parse("5.0".to_string()).is_err());
        assert!(KernelVersion::parse("5.0fff".to_string()).is_err());
    }

    #[test]
    fn test_cmp() {
        // Comparing major.
        assert!(KernelVersion::new(4, 0, 0) < KernelVersion::new(5, 10, 15));
        assert!(KernelVersion::new(4, 0, 0) > KernelVersion::new(3, 10, 15));

        // Comparing minor.
        assert!(KernelVersion::new(5, 0, 20) < KernelVersion::new(5, 10, 15));
        assert!(KernelVersion::new(5, 20, 20) > KernelVersion::new(5, 10, 15));
        assert!(KernelVersion::new(5, 100, 20) > KernelVersion::new(5, 20, 0));

        // Comparing patch.
        assert!(KernelVersion::new(5, 0, 20) < KernelVersion::new(5, 10, 15));
        assert!(KernelVersion::new(5, 0, 20) > KernelVersion::new(4, 10, 15));

        // Equal.
        assert!(KernelVersion::new(5, 0, 20) == KernelVersion::new(5, 0, 20));
        assert!(KernelVersion::new(5, 0, 20) >= KernelVersion::new(5, 0, 20));
        assert!(KernelVersion::new(5, 0, 20) <= KernelVersion::new(5, 0, 20));
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", KernelVersion::new(5, 8, 80)), "5.8.80");
    }
}
