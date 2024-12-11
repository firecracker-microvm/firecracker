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
//!   (i.e the number of times an API request failed). These metrics are reset upon flush.
//!
//! We add BlockDeviceMetrics entries from block::metrics::METRICS into Block device instead of
//! Block device having individual separate BlockDeviceMetrics entries because Block device is not
//! accessible from signal handlers to flush metrics and block::metrics::METRICS is.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use crate::logger::{IncMetric, LatencyAggregateMetrics, SharedIncMetric};

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
        Arc::clone(
            METRICS
                .write()
                .unwrap()
                .metrics
                .entry(drive_id)
                .or_insert_with(|| Arc::new(BlockDeviceMetrics::default())),
        )
    }
}

/// Pool of block-related metrics per device behind a lock to
/// keep things thread safe. Since the lock is initialized here
/// it is safe to unwrap it without any check.
static METRICS: RwLock<BlockMetricsPerDevice> = RwLock::new(BlockMetricsPerDevice {
    metrics: BTreeMap::new(),
});

/// This function facilitates aggregation and serialization of
/// per block device metrics.
pub fn flush_metrics<S: Serializer>(serializer: S) -> Result<S::Ok, S::Error> {
    let block_metrics = METRICS.read().unwrap();
    let metrics_len = block_metrics.metrics.len();
    // +1 to accommodate aggregate block metrics
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
    /// Number of events triggered on the queue of this block device.
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
    /// Duration of all read operations.
    pub read_agg: LatencyAggregateMetrics,
    /// Duration of all write operations.
    pub write_agg: LatencyAggregateMetrics,
    /// Number of rate limiter throttling events.
    pub rate_limiter_throttled_events: SharedIncMetric,
    /// Number of virtio events throttled because of the IO engine.
    /// This happens when the io_uring submission queue is full.
    pub io_engine_throttled_events: SharedIncMetric,
    /// Number of remaining requests in the queue.
    pub remaining_reqs_count: SharedIncMetric,
}

impl BlockDeviceMetrics {
    /// Const default construction.
    pub fn new() -> Self {
        Self {
            read_agg: LatencyAggregateMetrics::new(),
            write_agg: LatencyAggregateMetrics::new(),
            ..Default::default()
        }
    }

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
        self.read_agg.sum_us.add(other.read_agg.sum_us.fetch_diff());
        self.write_agg
            .sum_us
            .add(other.write_agg.sum_us.fetch_diff());
        self.rate_limiter_throttled_events
            .add(other.rate_limiter_throttled_events.fetch_diff());
        self.io_engine_throttled_events
            .add(other.io_engine_throttled_events.fetch_diff());
        self.remaining_reqs_count
            .add(other.remaining_reqs_count.fetch_diff());
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_max_block_dev_metrics() {
        // Note: this test has nothing to do with
        // block structure or IRQs, this is just to allocate
        // metrics for max number of devices that system can have.
        // We have 5-23 IRQ for block devices on x86_64 so, there
        // are 19 block devices at max. And, even though we have more
        // devices on aarch64 but we stick to 19 to keep test common.
        const MAX_BLOCK_DEVICES: usize = 19;

        // This is to make sure that RwLock for block::metrics::METRICS is good.
        drop(METRICS.read().unwrap());
        drop(METRICS.write().unwrap());

        // block::metrics::METRICS is in short RwLock on Vec of BlockDeviceMetrics.
        // Normally, pointer to unique entries of block::metrics::METRICS are stored
        // in Block device so that Block device can do self.metrics.* to
        // update a metric. We try to do something similar here without
        // using Block device by allocating max number of
        // BlockDeviceMetrics in block::metrics::METRICS and store pointer to
        // each entry in the local `metrics` vec.
        // We then update 1 IncMetric and 2 SharedMetric for each metrics
        // and validate if the metrics for per device was updated as
        // expected.
        let mut metrics: Vec<Arc<BlockDeviceMetrics>> = Vec::new();
        for i in 0..MAX_BLOCK_DEVICES {
            let devn: String = format!("drv{}", i);
            metrics.push(BlockMetricsPerDevice::alloc(devn.clone()));
            // update IncMetric
            metrics[i].activate_fails.inc();
            // update SharedMetric
            metrics[i].read_bytes.add(10);
            metrics[i].write_bytes.add(5);

            if i == 0 {
                // Unit tests run in parallel and we have
                // `test_single_block_dev_metrics` that also increases
                // the IncMetric count of drv0 by 1 (intentional to check
                // thread safety) so we check if the count is >=1.
                assert!(metrics[i].activate_fails.count() >= 1);

                // For the same reason as above since we have
                // another unit test running in parallel which updates
                // drv0 metrics we check if count is >=10.
                assert!(metrics[i].read_bytes.count() >= 10);
            } else {
                assert!(metrics[i].activate_fails.count() == 1);
                assert!(metrics[i].read_bytes.count() == 10);
            }
            assert_eq!(metrics[i].write_bytes.count(), 5);
        }
    }

    #[test]
    fn test_single_block_dev_metrics() {
        // Use drv0 so that we can check thread safety with the
        // `test_max_block_dev_metrics` which also uses the same name.
        let devn = "drv0";

        // This is to make sure that RwLock for block::metrics::METRICS is good.
        drop(METRICS.read().unwrap());
        drop(METRICS.write().unwrap());

        let test_metrics = BlockMetricsPerDevice::alloc(String::from(devn));
        // Test to update IncMetrics
        test_metrics.activate_fails.inc();
        assert!(
            test_metrics.activate_fails.count() > 0,
            "{}",
            test_metrics.activate_fails.count()
        );

        // We expect only 2 tests (this and test_max_block_dev_metrics)
        // to update activate_fails count for drv0.
        assert!(
            test_metrics.activate_fails.count() <= 2,
            "{}",
            test_metrics.activate_fails.count()
        );

        // Test to update SharedMetrics
        test_metrics.read_bytes.add(5);
        // We expect only 2 tests (this and test_max_block_dev_metrics)
        // to update read_bytes count for drv0 by 5.
        assert!(test_metrics.read_bytes.count() >= 5);
        assert!(test_metrics.read_bytes.count() <= 15);
    }
}
