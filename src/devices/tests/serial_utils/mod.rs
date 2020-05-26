// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use devices::legacy::ReadableFd;
use std::io;
use std::os::raw::c_void;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;

pub struct MockSerialInput(pub RawFd);

impl io::Read for MockSerialInput {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = unsafe { libc::read(self.0, buf.as_mut_ptr() as *mut c_void, buf.len()) };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(count as usize)
    }
}

impl AsRawFd for MockSerialInput {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl ReadableFd for MockSerialInput {}
