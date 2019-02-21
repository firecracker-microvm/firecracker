// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Emulates virtual and hardware devices.
extern crate byteorder;
extern crate epoll;
extern crate libc;

extern crate dumbo;
#[macro_use]
extern crate logger;
extern crate memory_model;
extern crate net_gen;
extern crate net_util;
extern crate rate_limiter;
extern crate sys_util;
#[cfg(feature = "vsock")]
extern crate vhost_backend;
#[cfg(feature = "vsock")]
extern crate vhost_gen;
extern crate virtio_gen;

use rate_limiter::{Error as RateLimiterError, TokenBucket};
use std::fs::File;
use std::io;

mod bus;
pub mod legacy;
pub mod virtio;

pub use self::bus::{Bus, BusDevice, Error as BusError};

pub type DeviceEventT = u16;

/// The payload is used to handle events where the internal state of the VirtIO device
/// needs to be changed.
#[allow(clippy::large_enum_variant)]
pub enum EpollHandlerPayload {
    /// DrivePayload(disk_image)
    DrivePayload(File),
    /// Used to mutate current RateLimiter settings. The buckets are rx_bytes, rx_ops,
    /// tx_bytes, and tx_ops, respectively.
    NetRateLimiterPayload {
        rx_bytes: Option<TokenBucket>,
        rx_ops: Option<TokenBucket>,
        tx_bytes: Option<TokenBucket>,
        tx_ops: Option<TokenBucket>,
    },
    /// Events that do not need a payload.
    Empty,
}

type Result<T> = std::result::Result<T, Error>;

pub trait EpollHandler: Send {
    fn handle_event(
        &mut self,
        device_event: DeviceEventT,
        event_flags: u32,
        payload: EpollHandlerPayload,
    ) -> Result<()>;
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
}
