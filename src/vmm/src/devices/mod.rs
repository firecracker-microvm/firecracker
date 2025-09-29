// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Emulates virtual and hardware devices.

#![allow(unused)]

use std::io;

pub mod acpi;
pub mod legacy;
pub mod pci;
pub mod pseudo;
pub mod virtio;

use log::error;

use crate::devices::virtio::net::metrics::NetDeviceMetrics;
use crate::devices::virtio::queue::{InvalidAvailIdx, QueueError};
use crate::devices::virtio::vsock::VsockError;
use crate::logger::IncMetric;
use crate::vstate::interrupts::InterruptError;

// Function used for reporting error in terms of logging
// but also in terms of metrics of net event fails.
// network metrics is reported per device so we need a handle to each net device's
// metrics `net_iface_metrics` to report metrics for that device.
pub(crate) fn report_net_event_fail(net_iface_metrics: &NetDeviceMetrics, err: DeviceError) {
    if let DeviceError::InvalidAvailIdx(err) = err {
        panic!("{}", err);
    }
    error!("{:?}", err);
    net_iface_metrics.event_fails.inc();
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum DeviceError {
    /// Failed to read from the TAP device.
    FailedReadTap,
    /// Failed to signal irq: {0}
    FailedSignalingIrq(#[from] InterruptError),
    /// IO error: {0}
    IoError(io::Error),
    /// Device received malformed payload.
    MalformedPayload,
    /// Device received malformed descriptor.
    MalformedDescriptor,
    /// Error during queue processing: {0}
    QueueError(#[from] QueueError),
    /// {0}
    InvalidAvailIdx(#[from] InvalidAvailIdx),
    /// Vsock device error: {0}
    VsockError(#[from] VsockError),
}
