// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Implements a virtio network device.

use std::io;

use crate::devices::virtio::queue::FIRECRACKER_MAX_QUEUE_SIZE;

/// Maximum size of the frame buffers handled by this device.
pub const MAX_BUFFER_SIZE: usize = 65562;
/// The number of queues of the network device.
pub const NET_NUM_QUEUES: usize = 2;
pub const NET_QUEUE_SIZES: [u16; NET_NUM_QUEUES] = [FIRECRACKER_MAX_QUEUE_SIZE; NET_NUM_QUEUES];
/// The index of the rx queue from Net device queues/queues_evts vector.
pub const RX_INDEX: usize = 0;
/// The index of the tx queue from Net device queues/queues_evts vector.
pub const TX_INDEX: usize = 1;

pub mod device;
mod event_handler;
pub mod metrics;
pub mod persist;
mod tap;
pub mod test_utils;

mod gen;

pub use tap::{Tap, TapError};

pub use self::device::Net;

/// Enum representing the Net device queue types
#[derive(Debug)]
pub enum NetQueue {
    /// The RX queue
    Rx,
    /// The TX queue
    Tx,
}

/// Errors the network device can trigger.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum NetError {
    /// Open tap device failed: {0}
    TapOpen(TapError),
    /// Setting vnet header size failed: {0}
    TapSetVnetHdrSize(TapError),
    /// EventFd error: {0}
    EventFd(io::Error),
    /// IO error: {0}
    IO(io::Error),
    /// The VNET header is missing from the frame
    VnetHeaderMissing,
}
