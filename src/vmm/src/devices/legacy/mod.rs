// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Implements legacy devices (UART, RTC etc).
#[cfg(target_arch = "x86_64")]
mod i8042;
#[cfg(target_arch = "aarch64")]
pub mod rtc_pl031;
pub mod serial;

use std::io;
use std::ops::Deref;

use serde::ser::SerializeMap;
use serde::Serializer;
use utils::eventfd::EventFd;
use vm_superio::Trigger;

#[cfg(target_arch = "x86_64")]
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
    /// Clone an `EventFdTrigger`.
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(EventFdTrigger((**self).try_clone()?))
    }

    /// Create an `EventFdTrigger`.
    pub fn new(evt: EventFd) -> Self {
        Self(evt)
    }

    /// Get the associated event fd out of an `EventFdTrigger`.
    pub fn get_event(&self) -> EventFd {
        self.0.try_clone().unwrap()
    }
}

/// Called by METRICS.flush(), this function facilitates serialization of aggregated metrics.
pub fn flush_metrics<S: Serializer>(serializer: S) -> Result<S::Ok, S::Error> {
    let mut seq = serializer.serialize_map(Some(1))?;
    #[cfg(target_arch = "x86_64")]
    seq.serialize_entry("i8042", &i8042::METRICS)?;
    #[cfg(target_arch = "aarch64")]
    seq.serialize_entry("rtc", &rtc_pl031::METRICS)?;
    seq.serialize_entry("uart", &serial::METRICS)?;
    seq.end()
}
