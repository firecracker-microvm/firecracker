// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::convert::From;
use std::fmt::Formatter;
use std::os::unix::io::RawFd;

use epoll;

pub type Pollable = RawFd;
pub type EventRegistrationData = (Pollable, EventSet);

pub enum PollableOp {
    /// Register a new handler for a pollable fd and a set of events.
    Register(EventRegistrationData),
    /// Unregister a handler for a pollable fd.
    Unregister(Pollable),
    /// Update the event set for a specified pollable fd.
    Update(EventRegistrationData),
}

impl std::fmt::Debug for PollableOp {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::PollableOp::*;

        match self {
            Register(data) => write!(f, "Register (fd: {}, events: {:?})", data.0, data.1),
            Unregister(data) => write!(f, "Unregister fd: {}", data),
            Update(data) => write!(f, "Update (fd: {}, events: {:?})", data.0, data.1),
        }
    }
}

bitflags! {
    /// Contains the events we want to monitor a fd and it works as an interface between
    /// the platform specific events and some general events we are watching.
    pub struct EventSet: u8 {
        const NONE = 0b0000_0000;
        const READ = 0b0000_0001;
        const WRITE = 0b0000_0010;
        const CLOSE = 0b0000_0100;
        const EDGE_TRIGGERED = 0b0000_1000;
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
    // Check if this is an edge triggered event.
    pub fn is_edge_triggered(self) -> bool {
        self.contains(EventSet::EDGE_TRIGGERED)
    }
}

impl From<EventSet> for epoll::EventType {
    fn from(event: EventSet) -> epoll::EventType {
        let mut epoll_event_mask = epoll::EventType::empty();

        if event.is_readable() {
            epoll_event_mask |= epoll::EventType::IN;
        }

        if event.is_writeable() {
            epoll_event_mask |= epoll::EventType::OUT;
        }

        if event.is_closed() {
            epoll_event_mask |= epoll::EventType::READ_HANG_UP;
        }

        if event.is_edge_triggered() {
            epoll_event_mask |= epoll::EventType::EDGE_TRIGGERED;
        }

        epoll_event_mask
    }
}

/// Associates the file descriptor represented by `fd` with the events
/// that the user is interested for it.
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

    /// Caller is interested in Pollable edge triggered events.
    pub fn edge_trigered(&mut self) -> &mut PollableOpBuilder {
        self.event_mask |= EventSet::EDGE_TRIGGERED;
        self
    }

    /// Create a `Register` PollableOp.
    pub fn register(&self) -> PollableOp {
        PollableOp::Register((self.fd, self.event_mask))
    }

    /// Create an `Unregister` PollableOp.
    pub fn unregister(&self) -> PollableOp {
        PollableOp::Unregister(self.fd)
    }

    /// Create an `Update` PollableOp.
    pub fn update(&self) -> PollableOp {
        PollableOp::Update((self.fd, self.event_mask))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::os::unix::io::AsRawFd;

    #[test]
    fn test_pollable_op_builder() {
        let pollable = io::stdin().as_raw_fd();
        let mut op_register = PollableOpBuilder::new(pollable)
            .readable()
            .writeable()
            .closeable()
            .register();
        assert_eq!(
            format!("{:?}", op_register),
            "Register (fd: 0, events: READ | WRITE | CLOSE)"
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
