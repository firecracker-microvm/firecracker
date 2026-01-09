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

/// This function facilitates aggregation and serialization of
/// per device rng metrics. (Can also handle singular)
pub fn flush_metrics<S: Serializer>(serializer: S) -> Result<S::Ok, S::Error> {
    let entropy_metrics = METRICS.read().unwrap();
    let metrics_len = entropy_metrics.metrics.len();
    // +1 to accomodate aggregate rng metrics
    let mut seq = serializer.serialize_map(Some(1 + metrics_len))?;

    let mut entropy_aggregated: EntropyDeviceMetrics = EntropyDeviceMetrics::default();

    for (name, metrics) in entropy_metrics.metrics.iter() {
        let dev_id = format!("entropy_{}", name);
        // serialization will flush the metrics so aggregate before it.
        let m: &EntropyDeviceMetrics = metrics;
        entropy_aggregated.aggregate(m);
        seq.serialize_entry(&dev_id, m)?;
    }
    seq.serialize_entry("entropy", &entropy_aggregated)?;
    seq.end()
}

#[derive(Debug)]
pub struct EntropyMetricsPerDevice {
    pub metrics: BTreeMap<String, Arc<EntropyDeviceMetrics>>,
}

impl EntropyMetricsPerDevice {
    pub fn alloc(device_id: String) -> Arc<EntropyDeviceMetrics> {
        Arc::clone(
            METRICS
                .write()
                .unwrap()
                .metrics
                .entry(device_id)
                .or_insert_with(|| Arc::new(EntropyDeviceMetrics::default())),
        )
    }
}

static METRICS: RwLock<EntropyMetricsPerDevice> = RwLock::new(EntropyMetricsPerDevice {
    metrics: BTreeMap::new(),
});

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

    pub fn aggregate(&mut self, other: &Self) {
        self.activate_fails.add(other.activate_fails.fetch_diff());
        self.entropy_event_fails
            .add(other.entropy_event_fails.fetch_diff());
        self.entropy_event_count
            .add(other.entropy_event_count.fetch_diff());
        self.entropy_bytes.add(other.entropy_bytes.fetch_diff());
        self.host_rng_fails.add(other.host_rng_fails.fetch_diff());
        self.entropy_rate_limiter_throttled
            .add(other.entropy_rate_limiter_throttled.fetch_diff());
        self.rate_limiter_event_count
            .add(other.rate_limiter_event_count.fetch_diff());
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::logger::IncMetric;

    #[test]
    fn test_rng_dev_metrics() {
        for i in 0..5 {
            let dev_id: String = format!("entropy{}", i);
            EntropyMetricsPerDevice::alloc(dev_id.clone());
            METRICS
                .read()
                .unwrap()
                .metrics
                .get(&dev_id)
                .unwrap()
                .activate_fails
                .inc();
            METRICS
                .read()
                .unwrap()
                .metrics
                .get(&dev_id)
                .unwrap()
                .entropy_bytes
                .add(10);
            METRICS
                .read()
                .unwrap()
                .metrics
                .get(&dev_id)
                .unwrap()
                .host_rng_fails
                .add(5);
        }

        for i in 0..5 {
            let dev_id: String = format!("entropy{}", i);
            assert!(
                METRICS
                    .read()
                    .unwrap()
                    .metrics
                    .get(&dev_id)
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
                    .get(&dev_id)
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
                    .get(&dev_id)
                    .unwrap()
                    .host_rng_fails
                    .count(),
                5
            );
        }
    }
}
