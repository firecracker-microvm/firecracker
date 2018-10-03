// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Emulates virtual and hardware devices.
extern crate byteorder;
extern crate epoll;
extern crate fc_util;
extern crate libc;
extern crate serde_json;

extern crate data_model;
extern crate dumbo;
#[macro_use]
extern crate logger;
extern crate memory_model;
extern crate net_sys;
extern crate net_util;
extern crate sys_util;
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
}

pub trait EpollHandler: Send {
    fn handle_event(&mut self, device_event: DeviceEventT, event_flags: u32);
    fn handle_event_with_payload(
        &mut self,
        device_event: DeviceEventT,
        event_flags: u32,
        payload: EpollHandlerPayload,
    );
}
