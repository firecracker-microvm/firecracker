// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod device;
pub mod event_handler;
pub mod persist;
pub mod request;

pub use self::device::Block;
pub use self::event_handler::*;
pub use self::request::*;

use vm_memory::GuestMemoryError;

pub const CONFIG_SPACE_SIZE: usize = 8;
pub const SECTOR_SHIFT: u8 = 9;
pub const SECTOR_SIZE: u64 = (0x01 as u64) << SECTOR_SHIFT;
pub const QUEUE_SIZE: u16 = 256;
pub const NUM_QUEUES: usize = 1;
pub const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];

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
    /// The requested operation would cause a seek beyond disk end.
    InvalidOffset,
    /// Guest gave us a read only descriptor that protocol says to write to.
    UnexpectedReadOnlyDescriptor,
    /// Guest gave us a write only descriptor that protocol says to read from.
    UnexpectedWriteOnlyDescriptor,
}
