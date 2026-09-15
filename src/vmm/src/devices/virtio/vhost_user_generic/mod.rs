// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod device;
pub mod event_handler;

use self::device::VhostUserGeneric;
use crate::devices::virtio::vhost_user::{VhostUserDeviceError, VhostUserError};
use crate::vstate::interrupts::InterruptError;

/// Default queue size for the generic vhost-user device.
pub const QUEUE_SIZE: u16 = 256;

/// Generic vhost-user device error.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VhostUserGenericError {
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
    /// Invalid number of queues requested: {0}. At least one queue is required.
    InvalidNumQueues(u64),
    /// Config space size must be between 1 and 4096 bytes, got {0}
    InvalidConfigSpaceSize(u32),
    /// Device type {0} is not a valid virtio device type
    InvalidDeviceType(u8),
    /// A vhost-user device supports at most {1} queues, got {0}
    TooManyQueues(u64, u64),
    /// Queue size must be a power of two, got {0}
    InvalidQueueSize(u16),
    /// Backend returned {0} bytes of config space, expected {1}
    ShortConfigSpace(usize, u32),
}

impl From<VhostUserDeviceError> for VhostUserGenericError {
    fn from(err: VhostUserDeviceError) -> Self {
        match err {
            VhostUserDeviceError::InvalidNumQueues(n) => Self::InvalidNumQueues(n),
            VhostUserDeviceError::InvalidConfigSpaceSize(n) => Self::InvalidConfigSpaceSize(n),
            VhostUserDeviceError::ConfigFeatureNotNegotiated => Self::ConfigFeatureNotNegotiated,
            VhostUserDeviceError::VhostUser(err) => Self::VhostUser(err),
            VhostUserDeviceError::GetConfig(err) => Self::Vhost(err),
            VhostUserDeviceError::EventFd(err) => Self::EventFd(err),
            VhostUserDeviceError::TooManyQueues(n, max) => Self::TooManyQueues(n, max),
            VhostUserDeviceError::InvalidQueueSize(n) => Self::InvalidQueueSize(n),
            VhostUserDeviceError::ShortConfigSpace(got, want) => Self::ShortConfigSpace(got, want),
            VhostUserDeviceError::Interrupt(err) => Self::Interrupt(err),
        }
    }
}
