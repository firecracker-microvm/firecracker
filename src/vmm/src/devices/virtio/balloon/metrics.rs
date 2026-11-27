// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the metrics system for balloon devices.
//!
//! # Metrics format
//! The metrics are flushed in JSON when requested by vmm::logger::metrics::METRICS.write().
//!
//! ## JSON example with metrics:
//! ```json
//!  "balloon": {
//!     "activate_fails": "SharedIncMetric",
//!     "inflate_count": "SharedIncMetric",
//!     "stats_updates_count": "SharedIncMetric",
//!     ...
//!  }
//! }
//! ```
//! Each `balloon` field in the example above is a serializable `BalloonDeviceMetrics` structure
//! collecting metrics such as `activate_fails`, `inflate_count` etc. for the balloon device.
//! Since balloon doesn't support multiple devices, there is no per device metrics and
//! `balloon` represents the aggregate balloon metrics.
//!
//! # Design
//! The main design goals of this system are:
//! * Have a consistent approach of keeping device related metrics in the individual devices
//!   modules.
//! * To decouple balloon device metrics from logger module by moving BalloonDeviceMetrics out of
//!   FirecrackerDeviceMetrics.
//! * Rely on `serde` to provide the actual serialization for writing the metrics.
//!
//! The system implements 1 type of metrics:
//! * Shared Incremental Metrics (SharedIncMetrics) - dedicated for the metrics which need a counter
//!   (i.e the number of times an API request failed). These metrics are reset upon flush.

use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use crate::logger::SharedIncMetric;

/// Key of the VM's balloon device in `METRICS`. Only this entry is flushed.
const METRICS_KEY: u64 = 0;

/// Metrics instances of every balloon device created in this process.
static METRICS: RwLock<BTreeMap<u64, Arc<BalloonDeviceMetrics>>> = RwLock::new(BTreeMap::new());

// Tests get a unique key above METRICS_KEY so their devices are never flushed.
#[cfg(test)]
static NEXT_TEST_KEY: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(METRICS_KEY + 1);

fn metrics_key() -> u64 {
    #[cfg(not(test))]
    return METRICS_KEY;
    #[cfg(test)]
    return NEXT_TEST_KEY.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Return the balloon device's metrics instance, inserting a fresh one into `METRICS` if absent.
pub(super) fn register() -> Arc<BalloonDeviceMetrics> {
    Arc::clone(
        METRICS
            .write()
            .unwrap()
            .entry(metrics_key())
            .or_insert_with(|| Arc::new(BalloonDeviceMetrics::default())),
    )
}

/// Called by METRICS.flush(), this function facilitates serialization of balloon device metrics.
pub fn flush_metrics<S: Serializer>(serializer: S) -> Result<S::Ok, S::Error> {
    let mut seq = serializer.serialize_map(Some(1))?;
    let dev_name = "balloon";

    match METRICS.read().unwrap().get(&METRICS_KEY) {
        Some(metrics) => seq.serialize_entry(dev_name, metrics.as_ref())?,
        None => seq.serialize_entry(dev_name, &BalloonDeviceMetrics::default())?,
    }

    seq.end()
}

/// Balloon Device associated metrics.
#[derive(Default, Debug, Serialize)]
pub struct BalloonDeviceMetrics {
    /// Number of times when activate failed on a balloon device.
    pub activate_fails: SharedIncMetric,
    /// Number of balloon device inflations.
    pub inflate_count: SharedIncMetric,
    // Number of balloon statistics updates from the driver.
    pub stats_updates_count: SharedIncMetric,
    // Number of balloon statistics update failures.
    pub stats_update_fails: SharedIncMetric,
    /// Number of balloon device deflations.
    pub deflate_count: SharedIncMetric,
    /// Number of times when handling events on a balloon device failed.
    pub event_fails: SharedIncMetric,
    /// Number of times when free page repoting was triggered
    pub free_page_report_count: SharedIncMetric,
    /// Total memory freed by the reporting driver
    pub free_page_report_freed: SharedIncMetric,
    /// Number of errors occurred while reporting
    pub free_page_report_fails: SharedIncMetric,
    /// Number of times when free page hinting was triggered
    pub free_page_hint_count: SharedIncMetric,
    /// Total memory freed by the hinting driver
    pub free_page_hint_freed: SharedIncMetric,
    /// Number of errors occurred while hinting
    pub free_page_hint_fails: SharedIncMetric,
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::logger::IncMetric;

    #[test]
    fn test_balloon_dev_metrics() {
        let balloon_metrics = BalloonDeviceMetrics::default();
        balloon_metrics.inflate_count.inc();

        let serialized = serde_json::to_string(&balloon_metrics).unwrap();
        let json_val: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        let obj = json_val.as_object().unwrap();

        assert_eq!(obj.get("inflate_count").and_then(|v| v.as_u64()), Some(1));
    }
}
