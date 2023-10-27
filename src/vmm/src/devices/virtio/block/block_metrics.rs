// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the metrics system for block devices.
//!
//! # Metrics format
//! The metrics are flushed in JSON when requested by vmm::logger::metrics::METRICS.write().
//!
//! ## JSON example with metrics:
//! ```json
//! {
//!  "block_drv0": {
//!     "activate_fails": "SharedIncMetric",
//!     "cfg_fails": "SharedIncMetric",
//!     "no_avail_buffer": "SharedIncMetric",
//!     "event_fails": "SharedIncMetric",
//!     "execute_fails": "SharedIncMetric",
//!     ...
//!  }
//!  "block_drv1": {
//!     "activate_fails": "SharedIncMetric",
//!     "cfg_fails": "SharedIncMetric",
//!     "no_avail_buffer": "SharedIncMetric",
//!     "event_fails": "SharedIncMetric",
//!     "execute_fails": "SharedIncMetric",
//!     ...
//!  }
//!  ...
//!  "block_drive_id": {
//!     "activate_fails": "SharedIncMetric",
//!     "cfg_fails": "SharedIncMetric",
//!     "no_avail_buffer": "SharedIncMetric",
//!     "event_fails": "SharedIncMetric",
//!     "execute_fails": "SharedIncMetric",
//!     ...
//!  }
//!  "block": {
//!     "activate_fails": "SharedIncMetric",
//!     "cfg_fails": "SharedIncMetric",
//!     "no_avail_buffer": "SharedIncMetric",
//!     "event_fails": "SharedIncMetric",
//!     "execute_fails": "SharedIncMetric",
//!     ...
//!  }
//! }
//! ```
//! Each `block` field in the example above is a serializable `BlockDeviceMetrics` structure
//! collecting metrics such as `activate_fails`, `cfg_fails`, etc. for the block device.
//! `block_drv0` represent metrics for the endpoint "/drives/drv0",
//! `block_drv1` represent metrics for the endpoint "/drives/drv1", and
//! `block_drive_id` represent metrics for the endpoint "/drives/{drive_id}"
//! block device respectively and `block` is the aggregate of all the per device metrics.
//!
//! # Limitations
//! block device currently do not have `vmm::logger::metrics::StoreMetrics` so aggregate
//! doesn't consider them.
//!
//! # Design
//! The main design goals of this system are:
//! * To improve block device metrics by logging them at per device granularity.
//! * Continue to provide aggregate block metrics to maintain backward compatibility.
//! * Move BlockDeviceMetrics out of from logger and decouple it.
//! * Rely on `serde` to provide the actual serialization for writing the metrics.
//! * Since all metrics start at 0, we implement the `Default` trait via derive for all of them, to
//!   avoid having to initialize everything by hand.
//!
//! * Devices could be created in any order i.e. the first device created could either be drv0 or
//!   drv1 so if we use a vector for BlockDeviceMetrics and call 1st device as block0, then block0
//!   could sometimes point to drv0 and sometimes to drv1 which doesn't help with analysing the
//!   metrics. So, use Map instead of Vec to help understand which drive the metrics actually
//!   belongs to.
//!
//! The system implements 1 type of metrics:
//! * Shared Incremental Metrics (SharedIncMetrics) - dedicated for the metrics which need a counter
//! (i.e the number of times an API request failed). These metrics are reset upon flush.
//! We use BLOCK_METRICS instead of adding an entry of BlockDeviceMetrics
//! in block so that metrics are accessible to be flushed even from signal handlers.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use crate::logger::{IncMetric, SharedIncMetric};

/// map of block drive id and metrics
/// this should be protected by a lock before accessing.
#[derive(Debug)]
pub struct BlockMetricsPerDevice {
    /// used to access per block device metrics
    pub metrics: BTreeMap<String, Arc<BlockDeviceMetrics>>,
}

impl BlockMetricsPerDevice {
    /// Allocate `BlockDeviceMetrics` for block device having
    /// id `drive_id`. Also, allocate only if it doesn't
    /// exist to avoid overwriting previously allocated data.
    /// lock is always initialized so it is safe the unwrap
    /// the lock without a check.
    pub fn alloc(drive_id: String) -> Arc<BlockDeviceMetrics> {
        if BLOCK_METRICS
            .read()
            .unwrap()
            .metrics
            .get(&drive_id)
            .is_none()
        {
            BLOCK_METRICS
                .write()
                .unwrap()
                .metrics
                .insert(drive_id.clone(), Arc::new(BlockDeviceMetrics::default()));
        }
        BLOCK_METRICS
            .read()
            .unwrap()
            .metrics
            .get(&drive_id)
            .unwrap()
            .clone()
    }
}

/// Pool of block-related metrics per device behind a lock to
/// keep things thread safe. Since the lock is initialized here
/// it is safe to unwrap it without any check.
static BLOCK_METRICS: RwLock<BlockMetricsPerDevice> = RwLock::new(BlockMetricsPerDevice {
    metrics: BTreeMap::new(),
});

/// This function facilitates aggregation and serialization of
/// per block device metrics.
pub fn flush_metrics<S: Serializer>(serializer: S) -> Result<S::Ok, S::Error> {
    let block_metrics = BLOCK_METRICS.read().unwrap();
    let metrics_len = block_metrics.metrics.len();
    // +1 to accomodate aggregate block metrics
    let mut seq = serializer.serialize_map(Some(1 + metrics_len))?;

    let mut block_aggregated: BlockDeviceMetrics = BlockDeviceMetrics::default();

    for (name, metrics) in block_metrics.metrics.iter() {
        let devn = format!("block_{}", name);
        // serialization will flush the metrics so aggregate before it.
        let m: &BlockDeviceMetrics = metrics;
        block_aggregated.aggregate(m);
        seq.serialize_entry(&devn, m)?;
    }
    seq.serialize_entry("block", &block_aggregated)?;
    seq.end()
}

/// Block Device associated metrics.
#[derive(Debug, Default, Serialize)]
pub struct BlockDeviceMetrics {
    /// Number of times when activate failed on a block device.
    pub activate_fails: SharedIncMetric,
    /// Number of times when interacting with the space config of a block device failed.
    pub cfg_fails: SharedIncMetric,
    /// No available buffer for the block queue.
    pub no_avail_buffer: SharedIncMetric,
    /// Number of times when handling events on a block device failed.
    pub event_fails: SharedIncMetric,
    /// Number of failures in executing a request on a block device.
    pub execute_fails: SharedIncMetric,
    /// Number of invalid requests received for this block device.
    pub invalid_reqs_count: SharedIncMetric,
    /// Number of flushes operation triggered on this block device.
    pub flush_count: SharedIncMetric,
    /// Number of events triggerd on the queue of this block device.
    pub queue_event_count: SharedIncMetric,
    /// Number of events ratelimiter-related.
    pub rate_limiter_event_count: SharedIncMetric,
    /// Number of update operation triggered on this block device.
    pub update_count: SharedIncMetric,
    /// Number of failures while doing update on this block device.
    pub update_fails: SharedIncMetric,
    /// Number of bytes read by this block device.
    pub read_bytes: SharedIncMetric,
    /// Number of bytes written by this block device.
    pub write_bytes: SharedIncMetric,
    /// Number of successful read operations.
    pub read_count: SharedIncMetric,
    /// Number of successful write operations.
    pub write_count: SharedIncMetric,
    /// Number of rate limiter throttling events.
    pub rate_limiter_throttled_events: SharedIncMetric,
    /// Number of virtio events throttled because of the IO engine.
    /// This happens when the io_uring submission queue is full.
    pub io_engine_throttled_events: SharedIncMetric,
}

impl BlockDeviceMetrics {
    /// block metrics are SharedIncMetric where the diff of current vs
    /// old is serialized i.e. serialize_u64(current-old).
    /// So to have the aggregate serialized in same way we need to
    /// fetch the diff of current vs old metrics and add it to the
    /// aggregate.
    pub fn aggregate(&mut self, other: &Self) {
        self.activate_fails.add(other.activate_fails.fetch_diff());
        self.cfg_fails.add(other.cfg_fails.fetch_diff());
        self.no_avail_buffer.add(other.no_avail_buffer.fetch_diff());
        self.event_fails.add(other.event_fails.fetch_diff());
        self.execute_fails.add(other.execute_fails.fetch_diff());
        self.invalid_reqs_count
            .add(other.invalid_reqs_count.fetch_diff());
        self.flush_count.add(other.flush_count.fetch_diff());
        self.queue_event_count
            .add(other.queue_event_count.fetch_diff());
        self.rate_limiter_event_count
            .add(other.rate_limiter_event_count.fetch_diff());
        self.update_count.add(other.update_count.fetch_diff());
        self.update_fails.add(other.update_fails.fetch_diff());
        self.read_bytes.add(other.read_bytes.fetch_diff());
        self.write_bytes.add(other.write_bytes.fetch_diff());
        self.read_count.add(other.read_count.fetch_diff());
        self.write_count.add(other.write_count.fetch_diff());
        self.rate_limiter_throttled_events
            .add(other.rate_limiter_throttled_events.fetch_diff());
        self.io_engine_throttled_events
            .add(other.io_engine_throttled_events.fetch_diff());
    }
    pub const fn new() -> Self {
        Self {
            activate_fails: SharedIncMetric::new(),
            cfg_fails: SharedIncMetric::new(),
            no_avail_buffer: SharedIncMetric::new(),
            event_fails: SharedIncMetric::new(),
            execute_fails: SharedIncMetric::new(),
            invalid_reqs_count:SharedIncMetric::new(),
            flush_count: SharedIncMetric::new(),
            queue_event_count:SharedIncMetric::new(),
            rate_limiter_event_count:SharedIncMetric::new(),
            update_count: SharedIncMetric::new(),
            update_fails: SharedIncMetric::new(),
            read_bytes: SharedIncMetric::new(),
            write_bytes: SharedIncMetric::new(),
            read_count: SharedIncMetric::new(),
            write_count: SharedIncMetric::new(),
            rate_limiter_throttled_events:SharedIncMetric::new(),
            io_engine_throttled_events:SharedIncMetric::new(),
        }
    }
}
