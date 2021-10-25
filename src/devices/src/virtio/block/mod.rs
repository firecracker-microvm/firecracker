// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod device;
pub mod event_handler;
mod io;
pub mod persist;
pub mod request;
pub mod test_utils;

pub use self::device::{Block, CacheType};
pub use self::event_handler::*;
pub use self::request::*;

use vm_memory::GuestMemoryError;

pub const CONFIG_SPACE_SIZE: usize = 8;
pub const SECTOR_SHIFT: u8 = 9;
pub const SECTOR_SIZE: u64 = (0x01_u64) << SECTOR_SHIFT;
pub const QUEUE_SIZE: u16 = 256;
pub const NUM_QUEUES: usize = 1;
pub const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];
// The virtio queue can hold up to 256 descriptors, but 1 request spreads across 2-3 descriptors.
// So we can use 128 IO_URING entries without ever triggering a FullSq Error.
pub const IO_URING_NUM_ENTRIES: u16 = 128;

#[derive(Debug)]
pub enum Error {
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
    // Error coming from the IO engine.
    FileEngine(io::Error),
    // Error manipulating the backing file.
    BackingFile(std::io::Error),
    // Error opening eventfd.
    EventFd(std::io::Error),
    // Error creating an irqfd.
    IrqTrigger(std::io::Error),
    // Error coming from the rate limiter.
    RateLimiter(std::io::Error),
    // Persistence error.
    Persist(crate::virtio::persist::Error),
}
