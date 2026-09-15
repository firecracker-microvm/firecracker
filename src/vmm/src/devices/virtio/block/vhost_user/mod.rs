// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod device;
pub mod event_handler;
pub mod persist;

use self::device::VhostUserBlock;
use crate::devices::virtio::vhost_user::{VhostUserDeviceError, VhostUserError};
use crate::vstate::interrupts::InterruptError;

/// Number of queues for the vhost-user block device.
pub const NUM_QUEUES: u64 = 1;

/// Queue size for the vhost-user block device.
pub const QUEUE_SIZE: u16 = 256;

/// Vhost-user block device error.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VhostUserBlockError {
    /// Cannot create config
    Config,
    /// Snapshotting of vhost-user-blk devices is not supported
    SnapshottingNotSupported,
    /// Vhost-user error: {0}
    VhostUser(VhostUserError),
    /// Vhost error: {0}
    Vhost(vhost::Error),
    /// Error opening eventfd: {0}
    EventFd(std::io::Error),
    /// Error creating irqfd: {0}
    Interrupt(InterruptError),
    /// Vhost-user device error: {0}
    VhostUserDevice(VhostUserDeviceError),
}

impl From<VhostUserDeviceError> for VhostUserBlockError {
    fn from(err: VhostUserDeviceError) -> Self {
        match err {
            VhostUserDeviceError::VhostUser(err) => Self::VhostUser(err),
            VhostUserDeviceError::GetConfig(err) => Self::Vhost(err),
            VhostUserDeviceError::EventFd(err) => Self::EventFd(err),
            VhostUserDeviceError::Interrupt(err) => Self::Interrupt(err),
            // Block builds its spec from constants and treats CONFIG as
            // optional, so the only one of these it can actually hit is a
            // backend under-filling the config space. They are listed rather
            // than caught by a wildcard so that a new variant on the generic
            // error does not compile until it has been considered here.
            err @ (VhostUserDeviceError::InvalidNumQueues(_)
            | VhostUserDeviceError::InvalidConfigSpaceSize(_)
            | VhostUserDeviceError::InvalidQueueSize(_)
            | VhostUserDeviceError::TooManyQueues(..)
            | VhostUserDeviceError::ShortConfigSpace(..)
            | VhostUserDeviceError::ConfigFeatureNotNegotiated) => Self::VhostUserDevice(err),
        }
    }
}
