// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::convert::From;
use std::fmt::Formatter;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

#[derive(Copy, Clone, PartialEq, Debug)]
pub struct Pollable {
    // Event manager will use this in callbacks so the EventHandler implementation can
    // multiplex the handling for multiple registered fds.
    fd: RawFd,
}

/// Wrapper for file descriptors.
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

pub enum PollableOp {
    /// Register a new handler for a pollable and eventset.
    Register(EventRegistrationData),
    /// Unregister a handler for a pollable.
    Unregister(Pollable),
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
    pub struct EventSet: u8 {
        const NONE = 0b0000_0000;
        const READ = 0b0000_0001;
        const WRITE = 0b0000_0010;
        const CLOSE = 0b0000_0100;
    }
}

/// Wraps the epoll specific event mask interface.
impl EventSet {
    /// Check if this is a read event.
    pub fn is_readable(self) -> bool {
        self.contains(EventSet::READ)
    }
    /// Check if this is a write event.
    pub fn is_writeable(self) -> bool {
        self.contains(EventSet::WRITE)
    }
    /// Check if this is a close event.
    pub fn is_closed(self) -> bool {
        self.contains(EventSet::CLOSE)
    }
}

impl From<EventSet> for epoll::Events {
    fn from(event: EventSet) -> epoll::Events {
        let mut epoll_event_mask = epoll::Events::empty();

        if event.is_readable() {
            epoll_event_mask |= epoll::Events::EPOLLIN;
        }

        if event.is_writeable() {
            epoll_event_mask |= epoll::Events::EPOLLOUT;
        }

        if event.is_closed() {
            epoll_event_mask |= epoll::Events::EPOLLRDHUP;
        }

        epoll_event_mask
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
            fd,
            event_mask: EventSet::NONE,
        }
    }

    /// Caller is interested in Pollable read events.
    pub fn readable(&mut self) -> &mut PollableOpBuilder {
        self.event_mask |= EventSet::READ;
        self
    }

    /// Caller is interested in Pollable write events.
    pub fn writeable(&mut self) -> &mut PollableOpBuilder {
        self.event_mask |= EventSet::WRITE;
        self
    }

    /// Caller is interested in Pollable close events.
    pub fn closeable(&mut self) -> &mut PollableOpBuilder {
        self.event_mask |= EventSet::CLOSE;
        self
    }

    /// Create a Register PollableOp.
    pub fn register(&self) -> PollableOp {
        PollableOp::Register((self.fd, self.event_mask))
    }

    /// Create an Unregister PollableOp.
    pub fn unregister(&self) -> PollableOp {
        PollableOp::Unregister(self.fd)
    }

    /// Create an Update PollableOp.
    pub fn update(&self) -> PollableOp {
        PollableOp::Update((self.fd, self.event_mask))
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
        let mut op_register = PollableOpBuilder::new(pollable)
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
                assert_eq!(data.0, pollable);
                assert_eq!(data.1, EventSet::READ | EventSet::WRITE | EventSet::CLOSE);
            }
            _ => panic!("Expected Register op"),
        }

        op_register = PollableOpBuilder::new(pollable).closeable().unregister();

        match op_register {
            PollableOp::Unregister(data) => {
                assert_eq!(data, pollable);
            }
            _ => panic!("Expected Unregister op"),
        }

        op_register = PollableOpBuilder::new(pollable).readable().update();

        match op_register {
            PollableOp::Update(data) => {
                assert_eq!(data.0, pollable);
                assert_eq!(data.1, EventSet::READ);
            }
            _ => panic!("Expected Update op"),
        }
    }
}
