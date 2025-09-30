// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the metrics system for pmem devices.
//!
//! # Metrics format
//! The metrics are flushed in JSON when requested by vmm::logger::metrics::METRICS.write().
//!
//! ## JSON example with metrics:
//! ```json
//! {
//!  "pmem_drv0": {
//!     "activate_fails": "SharedIncMetric",
//!     "cfg_fails": "SharedIncMetric",
//!     "no_avail_buffer": "SharedIncMetric",
//!     "event_fails": "SharedIncMetric",
//!     "execute_fails": "SharedIncMetric",
//!     ...
//!  }
//!  "pmem_drv1": {
//!     "activate_fails": "SharedIncMetric",
//!     "cfg_fails": "SharedIncMetric",
//!     "no_avail_buffer": "SharedIncMetric",
//!     "event_fails": "SharedIncMetric",
//!     "execute_fails": "SharedIncMetric",
//!     ...
//!  }
//!  ...
//!  "pmem_drive_id": {
//!     "activate_fails": "SharedIncMetric",
//!     "cfg_fails": "SharedIncMetric",
//!     "no_avail_buffer": "SharedIncMetric",
//!     "event_fails": "SharedIncMetric",
//!     "execute_fails": "SharedIncMetric",
//!     ...
//!  }
//!  "pmem": {
//!     "activate_fails": "SharedIncMetric",
//!     "cfg_fails": "SharedIncMetric",
//!     "no_avail_buffer": "SharedIncMetric",
//!     "event_fails": "SharedIncMetric",
//!     "execute_fails": "SharedIncMetric",
//!     ...
//!  }
//! }
//! ```
//! Each `pmem` field in the example above is a serializable `PmemDeviceMetrics` structure
//! collecting metrics such as `activate_fails`, `cfg_fails`, etc. for the pmem device.
//! `pmem_drv0` represent metrics for the endpoint "/pmem/drv0",
//! `pmem_drv1` represent metrics for the endpoint "/pmem/drv1", and
//! `pmem_drive_id` represent metrics for the endpoint "/pmem/{drive_id}"
//! pmem device respectively and `pmem` is the aggregate of all the per device metrics.
//!
//! # Limitations
//! pmem device currently do not have `vmm::logger::metrics::StoreMetrics` so aggregate
//! doesn't consider them.
//!
//! # Design
//! The main design goals of this system are:
//! * To improve pmem device metrics by logging them at per device granularity.
//! * Continue to provide aggregate pmem metrics to maintain backward compatibility.
//! * Move PmemDeviceMetrics out of from logger and decouple it.
//! * Rely on `serde` to provide the actual serialization for writing the metrics.
//! * Since all metrics start at 0, we implement the `Default` trait via derive for all of them, to
//!   avoid having to initialize everything by hand.
//!
//! * Devices could be created in any order i.e. the first device created could either be drv0 or
//!   drv1 so if we use a vector for PmemDeviceMetrics and call 1st device as pmem0, then pmem0
//!   could sometimes point to drv0 and sometimes to drv1 which doesn't help with analysing the
//!   metrics. So, use Map instead of Vec to help understand which drive the metrics actually
//!   belongs to.
//!
//! The system implements 1 type of metrics:
//! * Shared Incremental Metrics (SharedIncMetrics) - dedicated for the metrics which need a counter
//!   (i.e the number of times an API request failed). These metrics are reset upon flush.
//!
//! We add PmemDeviceMetrics entries from pmem::metrics::METRICS into Pmem device instead of
//! Pmem device having individual separate PmemDeviceMetrics entries because Pmem device is not
//! accessible from signal handlers to flush metrics and pmem::metrics::METRICS is.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use crate::logger::{IncMetric, LatencyAggregateMetrics, SharedIncMetric};

/// map of pmem drive id and metrics
/// this should be protected by a lock before accessing.
#[derive(Debug)]
pub struct PmemMetricsPerDevice {
    /// used to access per pmem device metrics
    pub metrics: BTreeMap<String, Arc<PmemMetrics>>,
}

impl PmemMetricsPerDevice {
    /// Allocate `PmemDeviceMetrics` for pmem device having
    /// id `drive_id`. Also, allocate only if it doesn't
    /// exist to avoid overwriting previously allocated data.
    /// lock is always initialized so it is safe the unwrap
    /// the lock without a check.
    pub fn alloc(drive_id: String) -> Arc<PmemMetrics> {
        Arc::clone(
            METRICS
                .write()
                .unwrap()
                .metrics
                .entry(drive_id)
                .or_insert_with(|| Arc::new(PmemMetrics::default())),
        )
    }
}

/// Pool of pmem-related metrics per device behind a lock to
/// keep things thread safe. Since the lock is initialized here
/// it is safe to unwrap it without any check.
static METRICS: RwLock<PmemMetricsPerDevice> = RwLock::new(PmemMetricsPerDevice {
    metrics: BTreeMap::new(),
});

/// This function facilitates aggregation and serialization of
/// per pmem device metrics.
pub fn flush_metrics<S: Serializer>(serializer: S) -> Result<S::Ok, S::Error> {
    let pmem_metrics = METRICS.read().unwrap();
    let metrics_len = pmem_metrics.metrics.len();
    // +1 to accommodate aggregate pmem metrics
    let mut seq = serializer.serialize_map(Some(1 + metrics_len))?;

    let mut pmem_aggregated: PmemMetrics = PmemMetrics::default();

    for (name, metrics) in pmem_metrics.metrics.iter() {
        let devn = format!("pmem_{}", name);
        // serialization will flush the metrics so aggregate before it.
        let m: &PmemMetrics = metrics;
        pmem_aggregated.aggregate(m);
        seq.serialize_entry(&devn, m)?;
    }
    seq.serialize_entry("pmem", &pmem_aggregated)?;
    seq.end()
}

/// Pmem Device associated metrics.
#[derive(Debug, Default, Serialize)]
pub struct PmemMetrics {
    /// Number of times when activate failed on a pmem device.
    pub activate_fails: SharedIncMetric,
    /// Number of times when interacting with the space config of a pmem device failed.
    pub cfg_fails: SharedIncMetric,
    /// Number of times when handling events on a pmem device failed.
    pub event_fails: SharedIncMetric,
    /// Number of events triggered on the queue of this pmem device.
    pub queue_event_count: SharedIncMetric,
}

impl PmemMetrics {
    /// Const default construction.
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    /// pmem metrics are SharedIncMetric where the diff of current vs
    /// old is serialized i.e. serialize_u64(current-old).
    /// So to have the aggregate serialized in same way we need to
    /// fetch the diff of current vs old metrics and add it to the
    /// aggregate.
    pub fn aggregate(&mut self, other: &Self) {
        self.activate_fails.add(other.activate_fails.fetch_diff());
        self.cfg_fails.add(other.cfg_fails.fetch_diff());
        self.event_fails.add(other.event_fails.fetch_diff());
        self.queue_event_count
            .add(other.queue_event_count.fetch_diff());
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_max_pmem_dev_metrics() {
        // Note: this test has nothing to do with
        // pmem structure or IRQs, this is just to allocate
        // metrics for max number of devices that system can have.
        // We have 5-23 IRQ for pmem devices on x86_64 so, there
        // are 19 pmem devices at max. And, even though we have more
        // devices on aarch64 but we stick to 19 to keep test common.
        const MAX_PMEM_DEVICES: usize = 19;

        // This is to make sure that RwLock for pmem::metrics::METRICS is good.
        drop(METRICS.read().unwrap());
        drop(METRICS.write().unwrap());

        // pmem::metrics::METRICS is in short RwLock on Vec of PmemDeviceMetrics.
        // Normally, pointer to unique entries of pmem::metrics::METRICS are stored
        // in Pmem device so that Pmem device can do self.metrics.* to
        // update a metric. We try to do something similar here without
        // using Pmem device by allocating max number of
        // PmemDeviceMetrics in pmem::metrics::METRICS and store pointer to
        // each entry in the local `metrics` vec.
        // We then update 1 IncMetric and 2 SharedMetric for each metrics
        // and validate if the metrics for per device was updated as
        // expected.
        let mut metrics: Vec<Arc<PmemMetrics>> = Vec::new();
        for i in 0..MAX_PMEM_DEVICES {
            let pmem_name: String = format!("pmem{}", i);
            metrics.push(PmemMetricsPerDevice::alloc(pmem_name.clone()));
            // update IncMetric
            metrics[i].activate_fails.inc();

            if i == 0 {
                // Unit tests run in parallel and we have
                // `test_single_pmem_dev_metrics` that also increases
                // the IncMetric count of drv0 by 1 (intentional to check
                // thread safety) so we check if the count is >=1.
                assert!(metrics[i].activate_fails.count() >= 1);
            } else {
                assert!(metrics[i].activate_fails.count() == 1);
            }
        }
    }

    #[test]
    fn test_single_pmem_dev_metrics() {
        let test_metrics = PmemMetricsPerDevice::alloc(String::from("pmem0"));
        // Test to update IncMetrics
        test_metrics.activate_fails.inc();
        assert!(
            test_metrics.activate_fails.count() > 0,
            "{}",
            test_metrics.activate_fails.count()
        );

        // We expect only 2 tests (this and test_max_pmem_dev_metrics)
        // to update activate_fails count for pmem0.
        assert!(
            test_metrics.activate_fails.count() <= 2,
            "{}",
            test_metrics.activate_fails.count()
        );
    }
}
