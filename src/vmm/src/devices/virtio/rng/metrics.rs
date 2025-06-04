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

use std::sync::{Arc, RwLock};
use std::collections::BTreeMap;

/// This function facilitates aggregation and serialization of
/// per device vsock metrics. (Can also handle singular)
pub fn flush_metrics<S: Serializer>(serializer: S) -> Result<S::Ok, S::Error> {
    let entropy_metrics = METRICS.read().unwrap();
    let metrics_len = entropy_metrics.metrics.len();
    // +1 to accomodate aggregate net metrics
    let mut seq = serializer.serialize_map(Some(1 + metrics_len))?;

    let mut entropy_aggregated: EntropyDeviceMetrics = EntropyDeviceMetrics::default();

    for (name, metrics) in entropy_metrics.metrics.iter() {
        let devn = format!("entropy_{}", name);
        // serialization will flush the metrics so aggregate before it.
        let m: &EntropyDeviceMetrics = metrics;
        entropy_aggregated.aggregate(m);
        seq.serialize_entry(&devn, m)?;
    }
    seq.serialize_entry("entropy", &entropy_aggregated)?;
    seq.end()
}

pub struct EntropyMetricsPerDevice {
    pub metrics: BTreeMap<String, Arc<EntropyDeviceMetrics>>
}

impl EntropyMetricsPerDevice {
    /// Allocate `NetDeviceMetrics` for net device having
    /// id `iface_id`. Also, allocate only if it doesn't
    /// exist to avoid overwriting previously allocated data.
    /// lock is always initialized so it is safe the unwrap
    /// the lock without a check.
    pub fn alloc(iface_id: String) -> Arc<EntropyDeviceMetrics> {
        Arc::clone(
            METRICS
                .write()
                .unwrap()
                .metrics
                .entry(iface_id)
                .or_insert_with(|| Arc::new(EntropyDeviceMetrics::default())),
        )
    }
}

static METRICS: RwLock<EntropyMetricsPerDevice> = RwLock::new(EntropyMetricsPerDevice {
    metrics: {
        let tree = BTreeMap::new();
        tree.insert(
            "global".to_string(),
            Arc::new(EntropyDeviceMetrics::default()),
        );
        tree
    },
});

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
    fn test_rng_dev_metrics() {
        drop(METRICS.read().unwrap());
        drop(METRICS.write().unwrap());

        for i in 0..5 {
            let devn: String = format!("entropy{}", i);
            NetMetricsPerDevice::alloc(devn.clone());
            METRICS
                .read()
                .unwrap()
                .metrics
                .get(&devn)
                .unwrap()
                .activate_fails
                .inc();
            METRICS
                .read()
                .unwrap()
                .metrics
                .get(&devn)
                .unwrap()
                .entropy_bytes
                .add(10);
            METRICS
                .read()
                .unwrap()
                .metrics
                .get(&devn)
                .unwrap()
                .host_rng_fails
                .add(5);
        }

        for i in 0..5 {
            let devn: String = format!("entropy{}", i);
            assert!(
                METRICS
                    .read()
                    .unwrap()
                    .metrics
                    .get(&devn)
                    .unwrap()
                    .activate_fails
                    .count()
                    >= 1
            );
            assert!(
                METRICS
                    .read()
                    .unwrap()
                    .metrics
                    .get(&devn)
                    .unwrap()
                    .entropy_bytes
                    .count()
                    >= 10
            );
            assert_eq!(
                METRICS
                    .read()
                    .unwrap()
                    .metrics
                    .get(&devn)
                    .unwrap()
                    .host_rng_fails
                    .count(),
                5
            );
        }
    }

    #[test]
    fn test_single_rng_metrics() {
        // Use eth0 so that we can check thread safety with the
        // `test_net_dev_metrics` which also uses the same name.
        let devn = "entropy0";

        drop(METRICS.read().unwrap());
        drop(METRICS.write().unwrap());

        NetMetricsPerDevice::alloc(String::from(devn));
        METRICS.read().unwrap().metrics.get(devn).unwrap();

        METRICS
            .read()
            .unwrap()
            .metrics
            .get(devn)
            .unwrap()
            .activate_fails
            .inc();
        assert!(
            METRICS
                .read()
                .unwrap()
                .metrics
                .get(devn)
                .unwrap()
                .activate_fails
                .count()
                > 0,
            "{}",
            METRICS
                .read()
                .unwrap()
                .metrics
                .get(devn)
                .unwrap()
                .activate_fails
                .count()
        );
        // we expect only 2 tests (this and test_max_net_dev_metrics)
        // to update activate_fails count for eth0.
        assert!(
            METRICS
                .read()
                .unwrap()
                .metrics
                .get(devn)
                .unwrap()
                .activate_fails
                .count()
                <= 2,
            "{}",
            METRICS
                .read()
                .unwrap()
                .metrics
                .get(devn)
                .unwrap()
                .activate_fails
                .count()
        );

        METRICS
            .read()
            .unwrap()
            .metrics
            .get(devn)
            .unwrap()
            .activate_fails
            .inc();
        METRICS
            .read()
            .unwrap()
            .metrics
            .get(devn)
            .unwrap()
            .entropy_bytes
            .add(5);
        assert!(
            METRICS
                .read()
                .unwrap()
                .metrics
                .get(devn)
                .unwrap()
                .entropy_bytes
                .count()
                >= 5
        );
    }
}
