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

use serde::{Serialize, Serializer};

use crate::logger::{IncMetric, SharedIncMetric};

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

/// This function facilitates aggregation and serialization of rng metrics.
pub fn flush_metrics<S: Serializer>(serializer: S) -> Result<S::Ok, S::Error> {
    METRICS
        .get()
        .expect("rng: metrics instance not intialized")
        .serialize(serializer)
}

pub static METRICS: OnceLock<Arc<EntropyDeviceMetrics>> = OnceLock::new();
#[derive(Debug, Serialize, Default)]
pub struct EntropyDeviceMetrics {
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
    use std::sync::Arc;

    #[test]
    fn test_rng_dev_metrics() {
        let metrics_instance = Arc::new(EntropyDeviceMetrics::new());
        METRICS.set(metrics_instance);
        METRICS.get().unwrap().activate_fails.inc();
        METRICS.get().unwrap().entropy_bytes.add(10);
        METRICS.get().unwrap().host_rng_fails.add(5);

        assert!(METRICS.get().unwrap().activate_fails.count() >= 1);
        assert!(METRICS.get().unwrap().entropy_bytes.count() >= 10);
        assert_eq!(METRICS.get().unwrap().host_rng_fails.count(), 5);
    }
}
