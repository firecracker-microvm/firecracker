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
extern crate net_sys;
extern crate net_util;
extern crate rate_limiter;
extern crate sys_util;
#[cfg(feature = "vsock")]
extern crate vhost_backend;
#[cfg(feature = "vsock")]
extern crate vhost_sys;
extern crate virtio_sys;

use std::fs::File;

mod bus;
pub mod legacy;
pub mod virtio;

pub use self::bus::{Bus, BusDevice, Error as BusError};

pub type DeviceEventT = u16;

/// The payload is used to handle events where the internal state of the VirtIO device
/// needs to be changed.
pub enum EpollHandlerPayload {
    /// DrivePayload(disk_image)
    DrivePayload(File),
    /// Events that do not need a payload.
    Empty,
}

pub trait EpollHandler: Send {
    fn handle_event(
        &mut self,
        device_event: DeviceEventT,
        event_flags: u32,
        payload: EpollHandlerPayload,
    );
}
