// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Emulates virtual and hardware devices.
extern crate byteorder;
extern crate epoll;
extern crate libc;
#[macro_use]
extern crate logger;
extern crate net_sys;
extern crate net_util;
extern crate sys_util;
extern crate virtio_sys;

mod bus;
pub mod legacy;
pub mod virtio;

pub use self::bus::{Bus, BusDevice};

pub type DeviceEventT = u16;

pub trait EpollHandler: Send {
    fn handle_event(&mut self, device_event: DeviceEventT, event_flags: u32);
}
