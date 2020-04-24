// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};

use devices::legacy::ReadableFd;

pub struct MockSerialInput(pub File);

impl io::Read for MockSerialInput {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl AsRawFd for MockSerialInput {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl ReadableFd for MockSerialInput {}
