// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod device;
pub mod event_handler;
pub mod persist;
pub mod test_utils;
mod utils;

use vm_memory::GuestMemoryError;

pub use self::device::Balloon;
pub use self::device::BalloonConfig;
pub use self::device::BalloonStats;
pub use self::event_handler::*;

/// Device ID used in MMIO device identification.
/// Because Balloon is unique per-vm, this ID can be hardcoded.
pub const BALLOON_DEV_ID: &str = "balloon";
pub const CONFIG_SPACE_SIZE: usize = 8;
pub const QUEUE_SIZE: u16 = 256;
pub const NUM_QUEUES: usize = 3;
pub const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE, QUEUE_SIZE, QUEUE_SIZE];
// Number of 4K pages in a MB.
pub const MB_TO_4K_PAGES: u32 = 256;
// The maximum number of pages that can be received in a single descriptor.
pub const MAX_PAGES_IN_DESC: usize = 256;
// The addresses given by the driver are divided by 4096.
pub const VIRTIO_BALLOON_PFN_SHIFT: u32 = 12;
// The index of the deflate queue from Balloon device queues/queues_evts vector.
pub const INFLATE_INDEX: usize = 0;
// The index of the deflate queue from Balloon device queues/queues_evts vector.
pub const DEFLATE_INDEX: usize = 1;
// The index of the deflate queue from Balloon device queues/queues_evts vector.
pub const STATS_INDEX: usize = 2;

// The feature bitmap for virtio balloon.
const VIRTIO_BALLOON_F_MUST_TELL_HOST: u32 = 0; // Tell before reclaiming pages.
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

#[derive(Debug)]
pub enum Error {
    /// Activation error.
    Activate(super::ActivateError),
    /// No balloon device found.
    DeviceNotFound,
    /// Device not activated yet.
    DeviceNotActive,
    /// EventFd error.
    EventFd(std::io::Error),
    /// Failed to signal the virtio used queue.
    FailedSignalingUsedQueue(std::io::Error),
    /// Guest gave us bad memory addresses.
    GuestMemory(GuestMemoryError),
    /// Received error while sending an interrupt.
    InterruptError(std::io::Error),
    /// Guest gave us a malformed descriptor.
    MalformedDescriptor,
    /// Guest gave us a malformed payload.
    MalformedPayload,
    /// Error restoring the balloon device queues.
    QueueRestoreError,
    /// Received stats querry when stats are disabled.
    StatisticsDisabled,
    /// Statistics cannot be enabled/disabled after activation.
    StatisticsStateChange,
    /// Amount of pages requested cannot fit in `u32`.
    TooManyPagesRequested,
    /// Error while processing the virt queues.
    Queue(super::QueueError),
    /// Error removing a memory region at inflate time.
    RemoveMemoryRegion(RemoveRegionError),
    /// Error creating the statistics timer.
    Timer(std::io::Error),
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
