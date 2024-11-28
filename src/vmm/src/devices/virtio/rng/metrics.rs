// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the metrics system for entropy devices.
//!
//! # Metrics format
//! The metrics are flushed in JSON when requested by vmm::logger::metrics::METRICS.write().
//!
//! ## JSON example with metrics:
//! ```json
//!  "entropy": {
//!     "activate_fails": "SharedIncMetric",
//!     "entropy_event_fails": "SharedIncMetric",
//!     "entropy_event_count": "SharedIncMetric",
//!     ...
//!  }
//! }
//! ```
//! Each `entropy` field in the example above is a serializable `EntropyDeviceMetrics` structure
//! collecting metrics such as `activate_fails`, `entropy_event_fails` etc. for the entropy device.
//! Since entropy doesn't support multiple devices, there is no per device metrics and
//! `entropy` represents the aggregate entropy metrics.
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

/// Stores aggregated entropy metrics
pub(super) static METRICS: EntropyDeviceMetrics = EntropyDeviceMetrics::new();

/// Called by METRICS.flush(), this function facilitates serialization of entropy device metrics.
pub fn flush_metrics<S: Serializer>(serializer: S) -> Result<S::Ok, S::Error> {
    let mut seq = serializer.serialize_map(Some(1))?;
    seq.serialize_entry("entropy", &METRICS)?;
    seq.end()
}

#[derive(Debug, Serialize)]
pub(super) struct EntropyDeviceMetrics {
    /// Number of device activation failures
    pub activate_fails: SharedIncMetric,
    /// Number of entropy queue event handling failures
    pub entropy_event_fails: SharedIncMetric,
    /// Number of entropy requests handled
    pub entropy_event_count: SharedIncMetric,
    /// Number of entropy bytes provided to guest
    pub entropy_bytes: SharedIncMetric,
    /// Number of errors while getting random bytes on host
    pub host_rng_fails: SharedIncMetric,
    /// Number of times an entropy request was rate limited
    pub entropy_rate_limiter_throttled: SharedIncMetric,
    /// Number of events associated with the rate limiter
    pub rate_limiter_event_count: SharedIncMetric,
}
impl EntropyDeviceMetrics {
    /// Const default construction.
    const fn new() -> Self {
        Self {
            activate_fails: SharedIncMetric::new(),
            entropy_event_fails: SharedIncMetric::new(),
            entropy_event_count: SharedIncMetric::new(),
            entropy_bytes: SharedIncMetric::new(),
            host_rng_fails: SharedIncMetric::new(),
            entropy_rate_limiter_throttled: SharedIncMetric::new(),
            rate_limiter_event_count: SharedIncMetric::new(),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::logger::IncMetric;

    #[test]
    fn test_entropy_dev_metrics() {
        let entropy_metrics: EntropyDeviceMetrics = EntropyDeviceMetrics::new();
        let entropy_metrics_local: String = serde_json::to_string(&entropy_metrics).unwrap();
        // the 1st serialize flushes the metrics and resets values to 0 so that
        // we can compare the values with local metrics.
        serde_json::to_string(&METRICS).unwrap();
        let entropy_metrics_global: String = serde_json::to_string(&METRICS).unwrap();
        assert_eq!(entropy_metrics_local, entropy_metrics_global);
        entropy_metrics.entropy_event_count.inc();
        assert_eq!(entropy_metrics.entropy_event_count.count(), 1);
    }
}
