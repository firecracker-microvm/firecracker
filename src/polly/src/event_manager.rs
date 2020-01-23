// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fmt::Formatter;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};

use epoll::{self, Epoll, EpollEvent};

pub type Result<T> = std::result::Result<T, Error>;
pub type Pollable = RawFd;

/// Errors associated with epoll events handling.
pub enum Error {
    /// Cannot create epoll fd.
    EpollCreate(io::Error),
    /// Polling I/O error.
    Poll(io::Error),
    /// The specified pollable already registered.
    AlreadyExists(Pollable),
    /// The specified pollable is not registered.
    NotFound(Pollable),
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::Error::*;

        match self {
            EpollCreate(err) => write!(f, "Unable to create epoll fd: {}", err),
            Poll(err) => write!(f, "Error during epoll call: {}", err),
            AlreadyExists(pollable) => write!(
                f,
                "A handler for the specified pollable {} already exists.",
                pollable
            ),
            NotFound(pollable) => write!(
                f,
                "A handler for the specified pollable {} was not found.",
                pollable
            ),
        }
    }
}

/// A trait to express the ability to respond to I/O event readiness
/// using callbacks.
pub trait Subscriber {
    /// Callback called when an event is available.
    ///
    /// # Arguments
    /// * event - the available `EpollEvent` ready for processing
    /// * event_manager - Reference to the `EventManager` that gives the implementor
    ///                   the possibility to directly call the required update operations.
    fn process(&mut self, event: EpollEvent, event_manager: &mut EventManager);

    /// Returns a list of `EpollEvent` that this subscriber is interested in.
    fn interest_list(&self) -> Vec<EpollEvent>;
}

/// Manages I/O notifications using epoll mechanism.
pub struct EventManager {
    epoll: Epoll,
    subscribers: HashMap<RawFd, Arc<Mutex<dyn Subscriber>>>,
    ready_events: Vec<EpollEvent>,
}

impl AsRawFd for EventManager {
    fn as_raw_fd(&self) -> RawFd {
        self.epoll.as_raw_fd()
    }
}

impl EventManager {
    const EVENT_BUFFER_SIZE: usize = 128;

    /// Create a new EventManager.
    pub fn new() -> Result<EventManager> {
        let epoll_fd = epoll::Epoll::new().map_err(Error::EpollCreate)?;

        Ok(EventManager {
            epoll: epoll_fd,
            subscribers: HashMap::new(),
            // This buffer is used for storing the events returned by `epoll_wait()`.
            // We preallocate memory for this buffer in order to not repeat this
            // operation every time `run()` loop is executed.
            ready_events: vec![epoll::EpollEvent::default(); EventManager::EVENT_BUFFER_SIZE],
        })
    }

    pub fn subscriber(&self, fd: Pollable) -> Result<Arc<Mutex<dyn Subscriber>>> {
        self.subscribers
            .get(&fd)
            .ok_or(Error::NotFound(fd))
            .map(|subscriber| subscriber.clone())
    }

    pub fn add_subscriber(&mut self, subscriber: Arc<Mutex<dyn Subscriber>>) -> Result<()> {
        let interest_list = subscriber.lock().unwrap().interest_list();

        for event in interest_list {
            self.register(event.data() as i32, event, subscriber.clone())?
        }

        Ok(())
    }

    pub fn register(
        &mut self,
        pollable: Pollable,
        epoll_event: EpollEvent,
        subscriber: Arc<Mutex<dyn Subscriber>>,
    ) -> Result<()> {
        if self.subscribers.contains_key(&pollable) {
            return Err(Error::AlreadyExists(pollable));
        };

        self.epoll
            .ctl(epoll::ControlOperation::Add, pollable, epoll_event)
            .map_err(Error::Poll)?;

        self.subscribers.insert(pollable, subscriber);
        Ok(())
    }

    pub fn unregister(&mut self, pollable: Pollable) -> Result<()> {
        match self.subscribers.remove(&pollable) {
            Some(_) => {
                self.epoll
                    .ctl(
                        epoll::ControlOperation::Delete,
                        pollable,
                        epoll::EpollEvent::default(),
                    )
                    .map_err(Error::Poll)?;
            }
            None => {
                return Err(Error::NotFound(pollable));
            }
        }
        Ok(())
    }

    pub fn modify(&mut self, pollable: Pollable, epoll_event: EpollEvent) -> Result<()> {
        if self.subscribers.contains_key(&pollable) {
            self.epoll
                .ctl(epoll::ControlOperation::Modify, pollable, epoll_event)
                .map_err(Error::Poll)?;
        } else {
            return Err(Error::NotFound(pollable));
        }

        Ok(())
    }

    // Wait for events, then dispatch to registered event handlers.
    pub fn run(&mut self) -> Result<usize> {
        self.run_with_timeout(-1)
    }

    // Wait for events or a timeout, then dispatch to registered event handlers.
    pub fn run_with_timeout(&mut self, milliseconds: i32) -> Result<usize> {
        let event_count = self
            .epoll
            .wait(
                EventManager::EVENT_BUFFER_SIZE,
                milliseconds,
                &mut self.ready_events[..],
            )
            .map_err(Error::Poll)?;
        self.dispatch_events(event_count);

        Ok(event_count)
    }

    fn dispatch_events(&mut self, event_count: usize) {
        // Use the temporary, pre-allocated buffer to check ready events.
        for ev_index in 0..event_count {
            let event = self.ready_events[ev_index];
            let pollable = event.fd();

            if self.subscribers.contains_key(&pollable) {
                self.subscribers
                    .get_mut(&pollable)
                    .unwrap()
                    .clone()
                    .lock()
                    .unwrap()
                    .process(event, self);
            }
            // TODO: Should we log an error in case the subscriber does not exist?
        }
    }
}
