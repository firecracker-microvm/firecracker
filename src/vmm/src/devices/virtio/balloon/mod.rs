// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Implements a virtio balloon device.

pub mod device;
mod event_handler;
pub mod metrics;
pub mod persist;
pub mod test_utils;
mod util;

use log::error;

pub use self::device::{Balloon, BalloonConfig, BalloonStats};
use super::queue::{InvalidAvailIdx, QueueError};
use crate::devices::virtio::balloon::metrics::METRICS;
use crate::devices::virtio::queue::FIRECRACKER_MAX_QUEUE_SIZE;
use crate::logger::IncMetric;
use crate::vstate::interrupts::InterruptError;

/// Device ID used in MMIO device identification.
/// Because Balloon is unique per-vm, this ID can be hardcoded.
pub const BALLOON_DEV_ID: &str = "balloon";
/// The size of the config space.
pub const BALLOON_CONFIG_SPACE_SIZE: usize = 12;
/// Min number of virtio queues.
pub const BALLOON_MIN_NUM_QUEUES: usize = 2;
/// Virtio queue size, in number of descriptor chain heads.
pub const BALLOON_QUEUE_SIZE: u16 = FIRECRACKER_MAX_QUEUE_SIZE;
// Number of 4K pages in a MiB.
pub const MIB_TO_4K_PAGES: u32 = 256;
/// The maximum number of pages that can be received in a single descriptor.
pub const MAX_PAGES_IN_DESC: usize = 256;
/// The maximum number of pages that can be compacted into ranges during process_inflate().
/// Needs to be a multiple of MAX_PAGES_IN_DESC.
pub const MAX_PAGE_COMPACT_BUFFER: usize = 2048;
/// The addresses given by the driver are divided by 4096.
pub const VIRTIO_BALLOON_PFN_SHIFT: u32 = 12;
/// The index of the inflate queue from Balloon device queues/queues_evts vector.
pub const INFLATE_INDEX: usize = 0;
/// The index of the deflate queue from Balloon device queues/queues_evts vector.
pub const DEFLATE_INDEX: usize = 1;
/// The index of the stats queue from Balloon device queues/queues_evts vector.
pub const STATS_INDEX: usize = 2;

/// Command used in free page hinting to indicate the guest has finished
pub const FREE_PAGE_HINT_STOP: u32 = 0;
/// Command used in free page hinting to indicate to the guest to release pages
pub const FREE_PAGE_HINT_DONE: u32 = 1;

// The feature bitmap for virtio balloon.
const VIRTIO_BALLOON_F_STATS_VQ: u32 = 1; // Enable statistics.
const VIRTIO_BALLOON_F_DEFLATE_ON_OOM: u32 = 2; // Deflate balloon on OOM.
const VIRTIO_BALLOON_F_FREE_PAGE_HINTING: u32 = 3; // Enable free page hinting
const VIRTIO_BALLOON_F_FREE_PAGE_REPORTING: u32 = 5; // Enable free page reporting

// The statistics tags. defined in linux "include/uapi/linux/virtio_balloon.h".
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
const VIRTIO_BALLOON_S_OOM_KILL: u16 = 10;
const VIRTIO_BALLOON_S_ALLOC_STALL: u16 = 11;
const VIRTIO_BALLOON_S_ASYNC_SCAN: u16 = 12;
const VIRTIO_BALLOON_S_DIRECT_SCAN: u16 = 13;
const VIRTIO_BALLOON_S_ASYNC_RECLAIM: u16 = 14;
const VIRTIO_BALLOON_S_DIRECT_RECLAIM: u16 = 15;

/// Balloon device related errors.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum BalloonError {
    /// Device not activated yet.
    DeviceNotActive,
    /// Attempting to use hinting when not enabled
    HintingNotEnabled,
    /// EventFd error: {0}
    EventFd(std::io::Error),
    /// Received error while sending an interrupt: {0}
    InterruptError(InterruptError),
    /// Guest gave us a malformed descriptor.
    MalformedDescriptor,
    /// Guest gave us a malformed payload.
    MalformedPayload,
    /// Error restoring the balloon device queues.
    QueueRestoreError,
    /// Received stats query when stats are disabled.
    StatisticsDisabled,
    /// Statistics cannot be enabled/disabled after activation.
    StatisticsStateChange,
    /// Requested memory should be less than {0}MiB
    TooMuchMemoryRequested(u32),
    /// Error while processing the virt queues: {0}
    Queue(#[from] QueueError),
    /// {0}
    InvalidAvailIdx(#[from] InvalidAvailIdx),
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum RemoveRegionError {
    /// Address translation error.
    AddressTranslation,
    /// Malformed guest address range.
    MalformedRange,
    /// Error calling madvise: {0}
    MadviseFail(std::io::Error),
    /// Error calling mmap: {0}
    MmapFail(std::io::Error),
    /// Region not found.
    RegionNotFound,
}

pub(super) fn report_balloon_event_fail(err: BalloonError) {
    if let BalloonError::InvalidAvailIdx(err) = err {
        panic!("{}", err);
    }
    error!("{:?}", err);
    METRICS.event_fails.inc();
}
