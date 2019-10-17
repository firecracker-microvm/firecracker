// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::fmt::Formatter;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

#[derive(Default, Clone, PartialEq, Debug)]
pub struct Pollable {
    // Event manager will use this in callbacks so the EventHandler implementation can
    // multiplex the handling for multiple registered fds.
    fd: RawFd,
}

/// Wrapper for file descriptorsl
impl Pollable {
    pub fn from<T: AsRawFd>(rawfd: &T) -> Pollable {
        Pollable {
            fd: rawfd.as_raw_fd(),
        }
    }
}

impl FromRawFd for Pollable {
    unsafe fn from_raw_fd(fd: RawFd) -> Pollable {
        Pollable { fd }
    }
}

impl AsRawFd for Pollable {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

pub type EventRegistrationData = (Pollable, EventSet);

#[derive(PartialEq)]
pub enum PollableOp {
    /// Register a new handler for a pollable and eventset.
    Register(EventRegistrationData),
    /// Unregister a handler for a pollable.
    Unregister(EventRegistrationData),
    /// Update eventset for a specified pollable.
    Update(EventRegistrationData),
}

impl std::fmt::Debug for PollableOp {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::PollableOp::*;

        match self {
            Register(data) => write!(f, "Register {:?}", data),
            Unregister(data) => write!(f, "Unregister {:?}", data),
            Update(data) => write!(f, "Update {:?}", data),
        }
    }
}

bitflags! {
    #[derive(Default)]
    pub struct EventSet: u8 {
        const NONE = 0b00000000;
        const READ = 0b00000001;
        const WRITE = 0b00000010;
        const CLOSE = 0b00000100;
    }
}

impl EventSet {
    /// Read event.
    pub fn readable(&self) -> bool {
        self.contains(EventSet::READ)
    }
    /// Write event.
    pub fn writeable(&self) -> bool {
        self.contains(EventSet::WRITE)
    }
    // Close event.
    pub fn closed(&self) -> bool {
        self.contains(EventSet::CLOSE)
    }
}

impl std::fmt::Display for Pollable {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", self.fd)
    }
}

pub struct PollableOpBuilder {
    fd: Pollable,
    event_mask: EventSet,
}

impl PollableOpBuilder {
    /// Constructs a new PollableOp builder for the specified Pollable.
    pub fn new(fd: Pollable) -> PollableOpBuilder {
        PollableOpBuilder {
            fd: fd,
            event_mask: EventSet::NONE,
        }
    }

    /// Caller is interested in Pollable read events.
    pub fn readable<'a>(&'a mut self) -> &'a mut PollableOpBuilder {
        self.event_mask |= EventSet::READ;
        self
    }

    /// Caller is interested in Pollable write events.
    pub fn writeable<'a>(&'a mut self) -> &'a mut PollableOpBuilder {
        self.event_mask |= EventSet::WRITE;
        self
    }

    /// Caller is interested in Pollable close events.
    pub fn closeable<'a>(&'a mut self) -> &'a mut PollableOpBuilder {
        self.event_mask |= EventSet::CLOSE;
        self
    }

    /// Create a Register PollableOp.
    pub fn register(&self) -> PollableOp {
        PollableOp::Register((self.fd.clone(), self.event_mask))
    }

    /// Create an Unregister PollableOp.
    pub fn unregister(&self) -> PollableOp {
        PollableOp::Unregister((self.fd.clone(), self.event_mask))
    }

    /// Create an Update PollableOp.
    pub fn update(&self) -> PollableOp {
        PollableOp::Update((self.fd.clone(), self.event_mask))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    #[test]
    fn test_pollable() {
        let mut pollable = Pollable::from(&io::stdin());
        assert_eq!(pollable.as_raw_fd(), io::stdin().as_raw_fd());
        pollable = unsafe { Pollable::from_raw_fd(io::stdin().as_raw_fd()) };
        assert_eq!(pollable.as_raw_fd(), io::stdin().as_raw_fd());
    }

    #[test]
    fn test_pollable_op_builder() {
        let pollable = Pollable::from(&io::stdin());
        let mut op_register = PollableOpBuilder::new(pollable.clone())
            .readable()
            .writeable()
            .closeable()
            .register();
        assert_eq!(
            format!("{:?}", op_register),
            "Register (Pollable { fd: 0 }, READ | WRITE | CLOSE)"
        );

        match op_register {
            PollableOp::Register(data) => {
                assert_eq!(data.0, pollable.clone());
                assert_eq!(data.1, EventSet::READ | EventSet::WRITE | EventSet::CLOSE);
            }
            _ => panic!("Expected Register op"),
        }

        op_register = PollableOpBuilder::new(pollable.clone())
            .closeable()
            .unregister();

        match op_register {
            PollableOp::Unregister(data) => {
                assert_eq!(data.0, pollable.clone());
                assert_eq!(data.1, EventSet::CLOSE);
            }
            _ => panic!("Expected Unregister op"),
        }

        op_register = PollableOpBuilder::new(pollable.clone()).readable().update();

        match op_register {
            PollableOp::Update(data) => {
                assert_eq!(data.0, pollable.clone());
                assert_eq!(data.1, EventSet::READ);
            }
            _ => panic!("Expected Update op"),
        }
    }
}
