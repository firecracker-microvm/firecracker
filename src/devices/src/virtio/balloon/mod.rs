// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod device;
pub mod event_handler;
mod utils;

use vm_memory::GuestMemoryError;

pub use self::device::Balloon;
pub use self::event_handler::*;

pub const CONFIG_SPACE_SIZE: usize = 8;
pub const QUEUE_SIZE: u16 = 256;
pub const NUM_QUEUES: usize = 2;
pub const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE, QUEUE_SIZE];
// The maximum number of pages that can be received in a single descriptor.
pub const MAX_PAGES_IN_DESC: usize = 256;
// The addresses given by the driver are divided by 4096.
pub const VIRTIO_BALLOON_PFN_SHIFT: u32 = 12;
// The index of the deflate queue from Balloon device queues/queues_evts vector.
pub const INFLATE_INDEX: usize = 0;
// The index of the deflate queue from Balloon device queues/queues_evts vector.
pub const DEFLATE_INDEX: usize = 1;

// The feature bitmap for virtio balloon.
const VIRTIO_BALLOON_F_MUST_TELL_HOST: u32 = 0; // Tell before reclaiming pages.
const VIRTIO_BALLOON_F_DEFLATE_ON_OOM: u32 = 2; // Deflate balloon on OOM.

#[derive(Debug)]
pub enum Error {
    /// Guest gave us too few descriptors in a descriptor chain.
    DescriptorChainTooShort,
    /// Guest gave us a descriptor that was too short to use.
    DescriptorLengthTooSmall,
    /// Guest gave us bad memory addresses.
    GuestMemory(GuestMemoryError),
    /// Guest gave us a malformed descriptor.
    MalformedDescriptor,
    /// Error removing a memory region at inflate time.
    RemoveMemoryRegion(RemoveRegionError),
    /// Guest gave us a read only descriptor that protocol says to write to.
    UnexpectedReadOnlyDescriptor,
    /// Guest gave us a write only descriptor that protocol says to read from.
    UnexpectedWriteOnlyDescriptor,
}

#[derive(Debug)]
pub enum RemoveRegionError {
    AddressTranslation,
    MalformedRange,
    MadviseFail(std::io::Error),
    MmapFail(std::io::Error),
    RegionNotFound,
}

pub type Result<T> = std::result::Result<T, Error>;
