// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Implements a virtio block device.

pub mod device;
mod event_handler;
mod io;
pub mod metrics;
pub mod persist;
pub mod request;
pub mod test_utils;

use vm_memory::GuestMemoryError;

pub use self::device::VirtioBlock;
pub use self::request::*;
pub use crate::devices::virtio::block::CacheType;
use crate::devices::virtio::queue::FIRECRACKER_MAX_QUEUE_SIZE;

/// Sector shift for block device.
pub const SECTOR_SHIFT: u8 = 9;
/// Size of block sector.
pub const SECTOR_SIZE: u32 = (0x01_u32) << SECTOR_SHIFT;
/// The number of queues of block device.
pub const BLOCK_NUM_QUEUES: usize = 1;
pub const BLOCK_QUEUE_SIZES: [u16; BLOCK_NUM_QUEUES] = [FIRECRACKER_MAX_QUEUE_SIZE];
// The virtio queue can hold up to 256 descriptors, but 1 request spreads across 2-3 descriptors.
// So we can use 128 IO_URING entries without ever triggering a FullSq Error.
/// Maximum number of io uring entries we allow in the queue.
pub const IO_URING_NUM_ENTRIES: u16 = 128;

/// Errors the block device can trigger.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VirtioBlockError {
    /// Cannot create config
    Config,
    /// Guest gave us too few descriptors in a descriptor chain.
    DescriptorChainTooShort,
    /// Guest gave us a descriptor that was too short to use.
    DescriptorLengthTooSmall,
    /// Getting a block's metadata fails for any reason.
    GetFileMetadata(std::io::Error),
    /// Guest gave us bad memory addresses.
    GuestMemory(GuestMemoryError),
    /// The data length is invalid.
    InvalidDataLength,
    /// The requested operation would cause a seek beyond disk end.
    InvalidOffset,
    /// Guest gave us a read only descriptor that protocol says to write to.
    UnexpectedReadOnlyDescriptor,
    /// Guest gave us a write only descriptor that protocol says to read from.
    UnexpectedWriteOnlyDescriptor,
    /// Error coming from the IO engine: {0}
    FileEngine(io::BlockIoError),
    /// Error manipulating the backing file: {0} {1}
    BackingFile(std::io::Error, String),
    /// Error opening eventfd: {0}
    EventFd(std::io::Error),
    /// Error creating an irqfd: {0}
    IrqTrigger(std::io::Error),
    /// Error coming from the rate limiter: {0}
    RateLimiter(std::io::Error),
    /// Persistence error: {0}
    Persist(crate::devices::virtio::persist::PersistError),
}
