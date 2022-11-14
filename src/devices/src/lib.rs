// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

#![deny(missing_docs)]

//! Emulates virtual and hardware devices.

mod bus;
pub mod legacy;
pub mod pseudo;
pub mod virtio;

use logger::{error, IncMetric, METRICS};

pub use self::bus::{Bus, BusDevice, Error as BusError};

// Function used for reporting error in terms of logging
// but also in terms of METRICS net event fails.
pub(crate) fn report_net_event_fail(err: virtio::net::Error) {
    error!("{:?}", err);
    METRICS.net.event_fails.inc();
}

pub(crate) fn report_balloon_event_fail(err: virtio::balloon::Error) {
    error!("{:?}", err);
    METRICS.balloon.event_fails.inc();
}
