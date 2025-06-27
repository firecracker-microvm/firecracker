// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the metrics system for virtio-mem devices.
//!
//! # Metrics format
//! The metrics are flushed in JSON when requested by vmm::logger::metrics::METRICS.write().
//!
//! ## JSON example with metrics:
//! ```json
//!  "virtio_mem": {
//!     "activate_fails": "SharedIncMetric",
//!     "mem_event_fails": "SharedIncMetric",
//!     "mem_event_count": "SharedIncMetric",
//!     ...
//!  }
//! }
//! ```
//! Each `virtio_mem` field in the example above is a serializable `VirtioMemDeviceMetrics`
//! structure collecting metrics such as `activate_fails`, `mem_event_fails` etc. for the virtio-mem
//! device. Since virtio-mem doesn't support multiple devices, there is no per device metrics and
//! `virtio_mem` represents the aggregate virtio-mem metrics.
//!
//! # Design
//! The main design goals of this system are:
//! * Have a consistent approach of keeping device related metrics in the individual devices
//!   modules.
//! * To decouple entropy device metrics from logger module by moving EntropyDeviceMetrics out of
//!   FirecrackerDeviceMetrics.
//! * Rely on `serde` to provide the actual serialization for writing the metrics.
//!
//! The system implements 1 type of metrics:
//! * Shared Incremental Metrics (SharedIncMetrics) - dedicated for the metrics which need a counter
//!   (i.e the number of times an API request failed). These metrics are reset upon flush.

use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use crate::logger::SharedIncMetric;

/// Stores aggregated virtio-mem metrics
pub(super) static METRICS: VirtioMemDeviceMetrics = VirtioMemDeviceMetrics::new();

/// Called by METRICS.flush(), this function facilitates serialization of virtio-mem device metrics.
pub fn flush_metrics<S: Serializer>(serializer: S) -> Result<S::Ok, S::Error> {
    let mut seq = serializer.serialize_map(Some(1))?;
    seq.serialize_entry("virtio_mem", &METRICS)?;
    seq.end()
}

#[derive(Debug, Serialize)]
pub(super) struct VirtioMemDeviceMetrics {
    /// Number of device activation failures
    pub activate_fails: SharedIncMetric,
    /// Number of mem queue event handling failures
    pub mem_event_fails: SharedIncMetric,
    /// Number of mem requests handled
    pub mem_event_count: SharedIncMetric,
}
impl VirtioMemDeviceMetrics {
    /// Const default construction.
    const fn new() -> Self {
        Self {
            activate_fails: SharedIncMetric::new(),
            mem_event_fails: SharedIncMetric::new(),
            mem_event_count: SharedIncMetric::new(),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::logger::IncMetric;

    #[test]
    fn test_virtio_mem_dev_metrics() {
        let mem_metrics: VirtioMemDeviceMetrics = VirtioMemDeviceMetrics::new();
        let mem_metrics_local: String = serde_json::to_string(&mem_metrics).unwrap();
        // the 1st serialize flushes the metrics and resets values to 0 so that
        // we can compare the values with local metrics.
        serde_json::to_string(&METRICS).unwrap();
        let mem_metrics_global: String = serde_json::to_string(&METRICS).unwrap();
        assert_eq!(mem_metrics_local, mem_metrics_global);
        mem_metrics.mem_event_count.inc();
        assert_eq!(mem_metrics.mem_event_count.count(), 1);
    }
}
