// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

mod i8042;
#[cfg(target_arch = "aarch64")]
mod rtc_pl031;
pub mod serial;

pub use self::i8042::Error as I8042DeviceError;
pub use self::i8042::I8042Device;
#[cfg(target_arch = "aarch64")]
pub use self::rtc_pl031::RTCDevice;
pub use self::serial::{SerialDevice, SerialEventsWrapper, SerialWrapper};

use std::io;
use std::ops::Deref;
use utils::eventfd::EventFd;
use vm_superio::Trigger;

/// Newtype for implementing the trigger functionality for `EventFd`.
///
/// The trigger is used for handling events in the legacy devices.
pub struct EventFdTrigger(EventFd);

impl Trigger for EventFdTrigger {
    type E = io::Error;

    fn trigger(&self) -> io::Result<()> {
        self.write(1)
    }
}
impl Deref for EventFdTrigger {
    type Target = EventFd;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl EventFdTrigger {
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(EventFdTrigger((**self).try_clone()?))
    }
    pub fn new(evt: EventFd) -> Self {
        Self(evt)
    }

    pub fn get_event(&self) -> EventFd {
        self.0.try_clone().unwrap()
    }
}
