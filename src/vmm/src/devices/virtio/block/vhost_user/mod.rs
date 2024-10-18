// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod device;
pub mod event_handler;
pub mod persist;

use self::device::VhostUserBlock;
use crate::devices::virtio::vhost_user::VhostUserError;

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
    IrqTrigger(std::io::Error),
}
