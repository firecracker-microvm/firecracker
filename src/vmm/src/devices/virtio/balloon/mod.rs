// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Implements a virtio balloon device.

pub mod device;
mod event_handler;
pub mod persist;
pub mod test_utils;
mod util;

use utils::vm_memory::GuestMemoryError;

pub use self::device::{Balloon, BalloonConfig, BalloonStats};

/// Device ID used in MMIO device identification.
/// Because Balloon is unique per-vm, this ID can be hardcoded.
pub const BALLOON_DEV_ID: &str = "balloon";
/// The size of the config space.
pub const BALLOON_CONFIG_SPACE_SIZE: usize = 8;
/// Max size of virtio queues.
pub const BALLOON_QUEUE_SIZE: u16 = 256;
/// Number of virtio queues.
pub const BALLOON_NUM_QUEUES: usize = 3;
/// Virtio queue sizes, in number of descriptor chain heads.
//  There are 3 queues for a virtio device (in this order): RX, TX, Event
pub const BALLOON_QUEUE_SIZES: [u16; BALLOON_NUM_QUEUES] =
    [BALLOON_QUEUE_SIZE, BALLOON_QUEUE_SIZE, BALLOON_QUEUE_SIZE];
// Number of 4K pages in a MiB.
pub const MIB_TO_4K_PAGES: u32 = 256;
/// The maximum number of pages that can be received in a single descriptor.
pub const MAX_PAGES_IN_DESC: usize = 256;
/// The maximum number of pages that can be compacted into ranges during process_inflate().
/// Needs to be a multiple of MAX_PAGES_IN_DESC.
pub const MAX_PAGE_COMPACT_BUFFER: usize = 2048;
/// The addresses given by the driver are divided by 4096.
pub const VIRTIO_BALLOON_PFN_SHIFT: u32 = 12;
/// The index of the deflate queue from Balloon device queues/queues_evts vector.
pub const INFLATE_INDEX: usize = 0;
/// The index of the deflate queue from Balloon device queues/queues_evts vector.
pub const DEFLATE_INDEX: usize = 1;
/// The index of the deflate queue from Balloon device queues/queues_evts vector.
pub const STATS_INDEX: usize = 2;

// The feature bitmap for virtio balloon.
const VIRTIO_BALLOON_F_STATS_VQ: u32 = 1; // Enable statistics.
const VIRTIO_BALLOON_F_DEFLATE_ON_OOM: u32 = 2; // Deflate balloon on OOM.

// The statistics tags.
const VIRTIO_BALLOON_S_SWAP_IN: u16 = 0;
const VIRTIO_BALLOON_S_SWAP_OUT: u16 = 1;
const VIRTIO_BALLOON_S_MAJFLT: u16 = 2;
const VIRTIO_BALLOON_S_MINFLT: u16 = 3;
const VIRTIO_BALLOON_S_MEMFREE: u16 = 4;
const VIRTIO_BALLOON_S_MEMTOT: u16 = 5;
const VIRTIO_BALLOON_S_AVAIL: u16 = 6;
const VIRTIO_BALLOON_S_CACHES: u16 = 7;
const VIRTIO_BALLOON_S_HTLB_PGALLOC: u16 = 8;
const VIRTIO_BALLOON_S_HTLB_PGFAIL: u16 = 9;

/// Balloon device related errors.
#[derive(Debug, thiserror::Error)]
pub enum BalloonError {
    /// Activation error.
    #[error("Activation error: {0}")]
    Activate(super::ActivateError),
    /// No balloon device found.
    #[error("No balloon device found.")]
    DeviceNotFound,
    /// Device not activated yet.
    #[error("Device not activated yet.")]
    DeviceNotActive,
    /// EventFd error.
    #[error("EventFd error: {0}")]
    EventFd(std::io::Error),
    /// Guest gave us bad memory addresses.
    #[error("Guest gave us bad memory addresses: {0}")]
    GuestMemory(GuestMemoryError),
    /// Received error while sending an interrupt.
    #[error("Received error while sending an interrupt: {0}")]
    InterruptError(std::io::Error),
    /// Guest gave us a malformed descriptor.
    #[error("Guest gave us a malformed descriptor.")]
    MalformedDescriptor,
    /// Guest gave us a malformed payload.
    #[error("Guest gave us a malformed payload.")]
    MalformedPayload,
    /// Error restoring the balloon device queues.
    #[error("Error restoring the balloon device queues.")]
    QueueRestoreError,
    /// Received stats querry when stats are disabled.
    #[error("Received stats querry when stats are disabled.")]
    StatisticsDisabled,
    /// Statistics cannot be enabled/disabled after activation.
    #[error("Statistics cannot be enabled/disabled after activation.")]
    StatisticsStateChange,
    /// Amount of pages requested cannot fit in `u32`.
    #[error("Amount of pages requested cannot fit in `u32`.")]
    TooManyPagesRequested,
    /// Error while processing the virt queues.
    #[error("Error while processing the virt queues: {0}")]
    Queue(super::QueueError),
    /// Error removing a memory region at inflate time.
    #[error("Error removing a memory region at inflate time: {0}")]
    RemoveMemoryRegion(RemoveRegionError),
    /// Error creating the statistics timer.
    #[error("Error creating the statistics timer: {0}")]
    Timer(std::io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum RemoveRegionError {
    #[error("Address translation.")]
    AddressTranslation,
    #[error("Malformed range.")]
    MalformedRange,
    #[error("madvise fail: {0}")]
    MadviseFail(std::io::Error),
    #[error("mmap fail: {0}")]
    MmapFail(std::io::Error),
    #[error("Region not found.")]
    RegionNotFound,
}
