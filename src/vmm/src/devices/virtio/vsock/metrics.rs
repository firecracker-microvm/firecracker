// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the metrics system for vsock devices.
//!
//! # Metrics format
//! The metrics are flushed in JSON when requested by vmm::logger::metrics::METRICS.write().
//!
//! ## JSON example with metrics:
//! ```json
//!  "vsock": {
//!     "activate_fails": "SharedIncMetric",
//!     "cfg_fails": "SharedIncMetric",
//!     "rx_queue_event_fails": "SharedIncMetric",
//!     "tx_queue_event_fails": "SharedIncMetric",
//!     "ev_queue_event_fails": "SharedIncMetric",
//!     "muxer_event_fails": "SharedIncMetric",
//!     ...
//!  }
//! }
//! ```
//! Each `vsock` field in the example above is a serializable `VsockDeviceMetrics` structure
//! collecting metrics such as `activate_fails`, `cfg_fails`, etc. for the Vsock device.
//! Since vsock doesn't support multiple devices, there is no per device metrics and
//! `vsock` represents the aggregate metrics for all vsock connections.
//!
//! # Design
//! The main design goals of this system are:
//! * Have a consistent approach of keeping device related metrics in the individual devices
//!   modules.
//! * To decouple vsock device metrics from logger module by moving VsockDeviceMetrics out of
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

/// Stores aggregate metrics of all Vsock connections/actions
// pub(super) static METRICS: VsockDeviceMetrics = VsockDeviceMetrics::new();

/// This function facilitates aggregation and serialization of
/// per device vsock metrics. (Can also handle singular)
pub fn flush_metrics<S: Serializer>(serializer: S) -> Result<S::Ok, S::Error> {
    let vsock_metrics = METRICS.read().unwrap();
    let metrics_len = vsock_metrics.metrics.len();
    // +1 to accomodate aggregate net metrics
    let mut seq = serializer.serialize_map(Some(1 + metrics_len))?;

    let mut vsock_aggregated: VsockDeviceMetrics = VsockDeviceMetrics::default();

    for (name, metrics) in vsock_metrics.metrics.iter() {
        let devn = format!("vsock_{}", name);
        // serialization will flush the metrics so aggregate before it.
        let m: &VsockDeviceMetrics = metrics;
        vsock_aggregated.aggregate(m);
        seq.serialize_entry(&devn, m)?;
    }
    seq.serialize_entry("vsock", &vsock_aggregated)?;
    seq.end()
}

pub struct VsockMetricsPerDevice {
    pub metrics: BTreeMap<String, Arc<VsockDeviceMetrics>>
}

impl VsockMetricsPerDevice {
    /// Allocate `NetDeviceMetrics` for net device having
    /// id `iface_id`. Also, allocate only if it doesn't
    /// exist to avoid overwriting previously allocated data.
    /// lock is always initialized so it is safe the unwrap
    /// the lock without a check.
    pub fn alloc(iface_id: String) -> Arc<VsockDeviceMetrics> {
        Arc::clone(
            METRICS
                .write()
                .unwrap()
                .metrics
                .entry(iface_id)
                .or_insert_with(|| Arc::new(VsockDeviceMetrics::default())),
        )
    }
}

static METRICS: RwLock<VsockMetricsPerDevice> = RwLock::new(VsockMetricsPerDevice {
    metrics: {
        let tree = BTreeMap::new();
        tree.insert(
            "global".to_string(),
            Arc::new(VsockDeviceMetrics::default()),
        );
        tree
    },
});

/// Vsock-related metrics.
#[derive(Debug, Serialize)]
pub(super) struct VsockDeviceMetrics {
    /// Number of times when activate failed on a vsock device.
    pub activate_fails: SharedIncMetric,
    /// Number of times when interacting with the space config of a vsock device failed.
    pub cfg_fails: SharedIncMetric,
    /// Number of times when handling RX queue events on a vsock device failed.
    pub rx_queue_event_fails: SharedIncMetric,
    /// Number of times when handling TX queue events on a vsock device failed.
    pub tx_queue_event_fails: SharedIncMetric,
    /// Number of times when handling event queue events on a vsock device failed.
    pub ev_queue_event_fails: SharedIncMetric,
    /// Number of times when handling muxer events on a vsock device failed.
    pub muxer_event_fails: SharedIncMetric,
    /// Number of times when handling connection events on a vsock device failed.
    pub conn_event_fails: SharedIncMetric,
    /// Number of events associated with the receiving queue.
    pub rx_queue_event_count: SharedIncMetric,
    /// Number of events associated with the transmitting queue.
    pub tx_queue_event_count: SharedIncMetric,
    /// Number of bytes received.
    pub rx_bytes_count: SharedIncMetric,
    /// Number of transmitted bytes.
    pub tx_bytes_count: SharedIncMetric,
    /// Number of packets received.
    pub rx_packets_count: SharedIncMetric,
    /// Number of transmitted packets.
    pub tx_packets_count: SharedIncMetric,
    /// Number of added connections.
    pub conns_added: SharedIncMetric,
    /// Number of killed connections.
    pub conns_killed: SharedIncMetric,
    /// Number of removed connections.
    pub conns_removed: SharedIncMetric,
    /// How many times the killq has been resynced.
    pub killq_resync: SharedIncMetric,
    /// How many flush fails have been seen.
    pub tx_flush_fails: SharedIncMetric,
    /// How many write fails have been seen.
    pub tx_write_fails: SharedIncMetric,
    /// Number of times read() has failed.
    pub rx_read_fails: SharedIncMetric,
}

impl VsockDeviceMetrics {
    // We need this because vsock::metrics::METRICS does not accept
    // VsockDeviceMetrics::default()
    const fn new() -> Self {
        Self {
            activate_fails: SharedIncMetric::new(),
            cfg_fails: SharedIncMetric::new(),
            rx_queue_event_fails: SharedIncMetric::new(),
            tx_queue_event_fails: SharedIncMetric::new(),
            ev_queue_event_fails: SharedIncMetric::new(),
            muxer_event_fails: SharedIncMetric::new(),
            conn_event_fails: SharedIncMetric::new(),
            rx_queue_event_count: SharedIncMetric::new(),
            tx_queue_event_count: SharedIncMetric::new(),
            rx_bytes_count: SharedIncMetric::new(),
            tx_bytes_count: SharedIncMetric::new(),
            rx_packets_count: SharedIncMetric::new(),
            tx_packets_count: SharedIncMetric::new(),
            conns_added: SharedIncMetric::new(),
            conns_killed: SharedIncMetric::new(),
            conns_removed: SharedIncMetric::new(),
            killq_resync: SharedIncMetric::new(),
            tx_flush_fails: SharedIncMetric::new(),
            tx_write_fails: SharedIncMetric::new(),
            rx_read_fails: SharedIncMetric::new(),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::logger::IncMetric;

    // Simple test to test ability to handle different devices based on some id
    // Mimics the behavior and test of per-device structure in network devices.
    #[test]
    fn test_vsock_dev_metrics() {
        drop(METRICS.read().unwrap());
        drop(METRICS.write().unwrap());

        for i in 0..3 {
            let devn: String = format!("vsock{}", i);
            VsockMetricsPerDevice::alloc(devn.clone());
            METRICS
                .read()
                .unwrap()
                .metrics
                .get(&devn)
                .unwrap()
                .conns_added
                .inc();
        }
        METRICS
                .read()
                .unwrap()
                .metrics
                .get("vsock1")
                .unwrap()
                .conns_added
                .add(5);
        METRICS
            .read()
            .unwrap()
            .metrics
            .get("vsock2")
            .unwrap()
            .activate_fails
            .inc();

        let json_output = serde_json::to_string(&*METRICS.read().unwrap()).unwrap();

        // Optional: print JSON to visually verify structure
        println!("{}", json_output);

        let parsed: serde_json::Value = serde_json::from_str(&json_output).unwrap();
        let a_count = parsed["vsock_vsock0"]["conns_added"]["count"].as_u64().unwrap();
        let b_count = parsed["vsock_vsock1"]["conns_added"]["count"].as_u64().unwrap();
        let c_count = parsed["vsock_vsock2"]["conns_added"]["count"].as_u64().unwrap();
        let a_count_2 = parsed["vsock_vsock0"]["activate_fails"]["count"].as_u64().unwrap();
        let c_count_2 = parsed["vsock_vsock2"]["activate_fails"]["count"].as_u64().unwrap();
        let aggregated = parsed["vsock"]["conns_added"]["count"].as_u64().unwrap();

        assert_eq!(a_count, 1);
        assert_eq!(b_count, 6);
        assert_eq!(c_count, 1);
        assert_eq!(a_count_2, 0);
        assert_eq!(c_count_2, 1);
        assert_eq!(aggregated, 8);

        drop(METRICS.read().unwrap());
        assert_eq!(METRICS
            .read()
            .unwrap()
            .metrics
            .get("vsock0")
            .unwrap()
            .conns_added
            .count(), 0);
        assert_eq!(METRICS
            .read()
            .unwrap()
            .metrics
            .get("vsock1")
            .unwrap()
            .conns_added
            .count(), 0);

        METRICS
            .read()
            .unwrap()
            .metrics
            .get("vsock0")
            .unwrap()
            .activate_fails
            .inc();
    
        METRICS
            .read()
            .unwrap()
            .metrics
            .get("vsock0")
            .unwrap()
            .rx_bytes_count
            .inc();
        
    }

    // Device meant to test capability of retrieving and maintaining
    // a default vsock for the tree, the default represents the global value.
    // Also copies thread safety test from net devices.
    #[test]
    fn test_vsock_default() {
        // Use vsock0 so that we can check thread safety with other tests.
        let devn = "vsock0";

        // Drop any existing read/write lock to avoid deadlocks or stale locks.
        drop(METRICS.read().unwrap());
        drop(METRICS.write().unwrap());

        // Allocate metrics for the device.
        VsockMetricsPerDevice::alloc(String::from(devn));
        assert!(METRICS.read().unwrap().metrics.get(devn).is_some());

        // Increment a field (e.g. activate_fails) to ensure it's being tracked.
        METRICS
            .read()
            .unwrap()
            .metrics
            .get(devn)
            .unwrap()
            .activate_fails
            .inc();

        let count = METRICS
            .read()
            .unwrap()
            .metrics
            .get(devn)
            .unwrap()
            .activate_fails
            .count();
        assert!(
            count > 0,
            "Expected activate_fails count > 0 but got {}",
            count
        );

        // Ensure only up to 2 tests increment this (if sharing across tests).
        assert!(
            count <= 2,
            "Expected activate_fails count <= 2 but got {}",
            count
        );

        // Add more metric changes and assert correctness.
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
            .rx_bytes_count
            .add(5);

        let rx_count = METRICS
            .read()
            .unwrap()
            .metrics
            .get(devn)
            .unwrap()
            .rx_bytes_count
            .count();
        assert!(
            rx_count >= 5,
            "Expected rx_bytes_count >= 5 but got {}",
            rx_count
        );
    }
}
