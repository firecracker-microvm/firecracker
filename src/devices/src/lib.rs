// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Emulates virtual and hardware devices.

extern crate libc;

extern crate dumbo;
#[macro_use]
extern crate logger;
extern crate net_gen;
extern crate polly;
extern crate rate_limiter;
extern crate snapshot;
#[macro_use]
extern crate utils;
extern crate versionize;
extern crate versionize_derive;
extern crate vm_memory;

use std::io;

mod bus;
pub mod legacy;
pub mod pseudo;
pub mod virtio;

pub use self::bus::{Bus, BusDevice, Error as BusError};
use logger::{Metric, METRICS};

// Function used for reporting error in terms of logging
// but also in terms of METRICS net event fails.
pub(crate) fn report_net_event_fail(err: Error) {
    error!("{:?}", err);
    METRICS.net.event_fails.inc();
}

#[derive(Debug)]
pub enum Error {
    /// Failed to read from the TAP device.
    FailedReadTap,
    /// Failed to signal the virtio used queue.
    FailedSignalingUsedQueue(io::Error),
    /// IO error.
    IoError(io::Error),
    /// Device received malformed payload.
    MalformedPayload,
}
