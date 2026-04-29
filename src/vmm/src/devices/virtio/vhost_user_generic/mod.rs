// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod device;
pub mod event_handler;
pub mod persist;

use self::device::VhostUserGeneric;
use crate::devices::virtio::vhost_user::VhostUserError;
use crate::vstate::interrupts::InterruptError;

/// Default queue size for the generic vhost-user device.
pub const QUEUE_SIZE: u16 = 256;

/// Generic vhost-user device error.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VhostUserGenericError {
    /// Snapshotting of generic vhost-user devices is not supported
    SnapshottingNotSupported,
    /// Vhost-user error: {0}
    VhostUser(VhostUserError),
    /// Vhost error: {0}
    Vhost(vhost::Error),
    /// Error opening eventfd: {0}
    EventFd(std::io::Error),
    /// Error creating irqfd: {0}
    Interrupt(InterruptError),
    /// CONFIG protocol feature is required but was not negotiated with the backend
    ConfigFeatureNotNegotiated,
}
