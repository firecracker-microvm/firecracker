// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Implements legacy devices (UART, RTC etc).
mod i8042;
#[cfg(target_arch = "aarch64")]
mod rtc_pl031;
pub mod serial;

use std::io;
use std::ops::Deref;

use utils::eventfd::EventFd;
use vm_superio::Trigger;

pub use self::i8042::{I8042Device, I8042Error as I8042DeviceError};
#[cfg(target_arch = "aarch64")]
pub use self::rtc_pl031::RTCDevice;
pub use self::serial::{
    SerialDevice, SerialEventsWrapper, SerialWrapper, IER_RDA_BIT, IER_RDA_OFFSET,
};

/// Wrapper for implementing the trigger functionality for `EventFd`.
///
/// The trigger is used for handling events in the legacy devices.
#[derive(Debug)]
pub struct EventFdTrigger(EventFd);

impl Trigger for EventFdTrigger {
    type E = io::Error;

    #[tracing::instrument(level = "debug", ret(skip), skip(self))]
    fn trigger(&self) -> io::Result<()> {
        self.write(1)
    }
}

impl Deref for EventFdTrigger {
    type Target = EventFd;
    #[tracing::instrument(level = "debug", skip(self))]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl EventFdTrigger {
    /// Clone an `EventFdTrigger`.
    #[tracing::instrument(level = "debug", ret(skip), skip(self))]
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(EventFdTrigger((**self).try_clone()?))
    }

    /// Create an `EventFdTrigger`.
    #[tracing::instrument(level = "debug", ret(skip), skip(evt))]
    pub fn new(evt: EventFd) -> Self {
        Self(evt)
    }

    /// Get the associated event fd out of an `EventFdTrigger`.
    #[tracing::instrument(level = "debug", ret(skip), skip(self))]
    pub fn get_event(&self) -> EventFd {
        self.0.try_clone().unwrap()
    }
}
