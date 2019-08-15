// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Emulates virtual and hardware devices.

use epoll;



#[macro_use]
extern crate logger;





#[cfg(feature = "vsock")]
extern crate vhost_backend;
#[cfg(feature = "vsock")]
extern crate vhost_gen;


use rate_limiter::Error as RateLimiterError;
use std::io;

mod bus;
pub mod legacy;
pub mod virtio;

pub use self::bus::{Bus, BusDevice, Error as BusError};
use crate::virtio::AsAny;

pub type DeviceEventT = u16;

type Result<T> = std::result::Result<T, Error>;

pub trait EpollHandler: AsAny + Send {
    fn handle_event(&mut self, device_event: DeviceEventT, evset: epoll::Events) -> Result<()>;
}

#[derive(Debug)]
pub enum Error {
    FailedReadingQueue {
        event_type: &'static str,
        underlying: io::Error,
    },
    FailedReadTap,
    FailedSignalingUsedQueue(io::Error),
    RateLimited(RateLimiterError),
    PayloadExpected,
    UnknownEvent {
        device: &'static str,
        event: DeviceEventT,
    },
    IoError(io::Error),
    NoAvailBuffers,
}
