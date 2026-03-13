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

use crate::logger::{IncMetric, SharedIncMetric};

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

/// This function facilitates aggregation and serialization of
/// per device vsock metrics. (Can also handle singular)
pub fn flush_metrics<S: Serializer>(serializer: S) -> Result<S::Ok, S::Error> {
    let vsock_metrics = METRICS.read().unwrap();
    let metrics_len = vsock_metrics.len();
    // +1 to accomodate aggregate vsock metrics
    let mut seq = serializer.serialize_map(Some(1 + metrics_len))?;

    let mut vsock_aggregated: VsockDeviceMetrics = VsockDeviceMetrics::default();

    for (cid, metrics) in vsock_metrics.iter() {
        // serialization will flush the metrics so aggregate before it.
        let m: &VsockDeviceMetrics = metrics;
        vsock_aggregated.aggregate(m);
        seq.serialize_entry(&cid, m)?;
    }
    seq.serialize_entry("vsock", &vsock_aggregated)?;
    seq.end()
}

pub static METRICS: RwLock<BTreeMap<u64, Arc<VsockDeviceMetrics>>> = RwLock::new(BTreeMap::new());

/// Vsock-related metrics.
#[derive(Debug, Serialize, Default)]
pub struct VsockDeviceMetrics {
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

    pub fn aggregate(&mut self, other: &Self) {
        self.activate_fails.add(other.activate_fails.fetch_diff());
        self.cfg_fails.add(other.cfg_fails.fetch_diff());
        self.rx_queue_event_fails
            .add(other.rx_queue_event_fails.fetch_diff());
        self.tx_queue_event_fails
            .add(other.tx_queue_event_fails.fetch_diff());
        self.ev_queue_event_fails
            .add(other.ev_queue_event_fails.fetch_diff());
        self.muxer_event_fails
            .add(other.muxer_event_fails.fetch_diff());
        self.conn_event_fails
            .add(other.conn_event_fails.fetch_diff());
        self.rx_queue_event_count
            .add(other.rx_queue_event_count.fetch_diff());
        self.tx_queue_event_count
            .add(other.tx_queue_event_count.fetch_diff());
        self.rx_bytes_count.add(other.rx_bytes_count.fetch_diff());
        self.tx_bytes_count.add(other.tx_bytes_count.fetch_diff());
        self.rx_packets_count
            .add(other.rx_packets_count.fetch_diff());
        self.tx_packets_count
            .add(other.tx_packets_count.fetch_diff());
        self.conns_added.add(other.conns_added.fetch_diff());
        self.conns_killed.add(other.conns_killed.fetch_diff());
        self.conns_removed.add(other.conns_removed.fetch_diff());
        self.killq_resync.add(other.killq_resync.fetch_diff());
        self.tx_flush_fails.add(other.tx_flush_fails.fetch_diff());
        self.tx_write_fails.add(other.tx_write_fails.fetch_diff());
        self.rx_read_fails.add(other.rx_read_fails.fetch_diff());
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::logger::IncMetric;

    // Device meant to test capability of retrieving and maintaining
    // a default vsock for the tree, the default represents the global value.
    // Also copies thread safety test from net devices.
    #[test]
    fn test_vsock_default() {
        let guest_cid: u64 = 10;

        // Drop any existing read/write lock to avoid deadlocks or stale locks.
        drop(METRICS.read().unwrap());
        drop(METRICS.write().unwrap());

        METRICS
            .write()
            .unwrap()
            .insert(guest_cid, Arc::new(VsockDeviceMetrics::default()));

        // Increment a field (e.g. activate_fails) to ensure it's being tracked.
        METRICS
            .read()
            .unwrap()
            .get(&guest_cid)
            .unwrap()
            .activate_fails
            .inc();

        let count = METRICS
            .read()
            .unwrap()
            .get(&guest_cid)
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
            .get(&guest_cid)
            .unwrap()
            .activate_fails
            .inc();

        METRICS
            .read()
            .unwrap()
            .get(&guest_cid)
            .unwrap()
            .rx_bytes_count
            .add(5);

        let rx_count = METRICS
            .read()
            .unwrap()
            .get(&guest_cid)
            .unwrap()
            .rx_bytes_count
            .count();
        assert!(
            rx_count >= 5,
            "Expected rx_bytes_count >= 5 but got {}",
            rx_count
        );
    }

    #[test]
    fn test_vsock_metrics_serialization() {
        // Create a fresh metrics instance
        let mut metrics = VsockDeviceMetrics::default();

        // Set specific values for each metric
        metrics.activate_fails.add(1);
        metrics.cfg_fails.add(2);
        metrics.rx_queue_event_fails.add(3);
        metrics.tx_queue_event_fails.add(4);
        metrics.ev_queue_event_fails.add(5);
        metrics.muxer_event_fails.add(6);
        metrics.conn_event_fails.add(7);
        metrics.rx_queue_event_count.add(100);
        metrics.tx_queue_event_count.add(200);
        metrics.rx_bytes_count.add(1024);
        metrics.tx_bytes_count.add(2048);
        metrics.rx_packets_count.add(10);
        metrics.tx_packets_count.add(20);
        metrics.conns_added.add(5);
        metrics.conns_killed.add(2);
        metrics.conns_removed.add(3);
        metrics.killq_resync.add(1);
        metrics.tx_flush_fails.add(8);
        metrics.tx_write_fails.add(9);
        metrics.rx_read_fails.add(10);

        let serialized = serde_json::to_string(&metrics).expect("Failed to serialize metrics");

        let json_value: serde_json::Value =
            serde_json::from_str(&serialized).expect("Failed to parse JSON");

        assert!(
            json_value.is_object(),
            "Serialized metrics should be a JSON object"
        );

        let obj = json_value.as_object().unwrap();

        assert_eq!(obj.get("activate_fails").and_then(|v| v.as_u64()), Some(1));
        assert_eq!(obj.get("cfg_fails").and_then(|v| v.as_u64()), Some(2));
        assert_eq!(
            obj.get("rx_queue_event_fails").and_then(|v| v.as_u64()),
            Some(3)
        );
        assert_eq!(
            obj.get("tx_queue_event_fails").and_then(|v| v.as_u64()),
            Some(4)
        );
        assert_eq!(
            obj.get("ev_queue_event_fails").and_then(|v| v.as_u64()),
            Some(5)
        );
        assert_eq!(
            obj.get("muxer_event_fails").and_then(|v| v.as_u64()),
            Some(6)
        );
        assert_eq!(
            obj.get("conn_event_fails").and_then(|v| v.as_u64()),
            Some(7)
        );
        assert_eq!(
            obj.get("rx_queue_event_count").and_then(|v| v.as_u64()),
            Some(100)
        );
        assert_eq!(
            obj.get("tx_queue_event_count").and_then(|v| v.as_u64()),
            Some(200)
        );
        assert_eq!(
            obj.get("rx_bytes_count").and_then(|v| v.as_u64()),
            Some(1024)
        );
        assert_eq!(
            obj.get("tx_bytes_count").and_then(|v| v.as_u64()),
            Some(2048)
        );
        assert_eq!(
            obj.get("rx_packets_count").and_then(|v| v.as_u64()),
            Some(10)
        );
        assert_eq!(
            obj.get("tx_packets_count").and_then(|v| v.as_u64()),
            Some(20)
        );
        assert_eq!(obj.get("conns_added").and_then(|v| v.as_u64()), Some(5));
        assert_eq!(obj.get("conns_killed").and_then(|v| v.as_u64()), Some(2));
        assert_eq!(obj.get("conns_removed").and_then(|v| v.as_u64()), Some(3));
        assert_eq!(obj.get("killq_resync").and_then(|v| v.as_u64()), Some(1));
        assert_eq!(obj.get("tx_flush_fails").and_then(|v| v.as_u64()), Some(8));
        assert_eq!(obj.get("tx_write_fails").and_then(|v| v.as_u64()), Some(9));
        assert_eq!(obj.get("rx_read_fails").and_then(|v| v.as_u64()), Some(10));

        assert_eq!(obj.len(), 20, "Expected exactly 20 metric fields");
    }

    #[test]
    fn test_vsock_metrics_aggregation() {
        let mut metrics1 = VsockDeviceMetrics::default();
        metrics1.activate_fails.add(5);
        metrics1.rx_bytes_count.add(1000);
        metrics1.tx_packets_count.add(10);

        let mut metrics2 = VsockDeviceMetrics::default();
        metrics2.activate_fails.add(3);
        metrics2.rx_bytes_count.add(500);
        metrics2.tx_packets_count.add(7);

        // Create an aggregated metrics instance
        let mut aggregated = VsockDeviceMetrics::default();
        aggregated.aggregate(&metrics1);
        aggregated.aggregate(&metrics2);

        // Verify aggregated values
        assert_eq!(aggregated.activate_fails.count(), 8);
        assert_eq!(aggregated.rx_bytes_count.count(), 1500);
        assert_eq!(aggregated.tx_packets_count.count(), 17);

        // Verify serialization of aggregated metrics
        let serialized = serde_json::to_string(&aggregated).expect("Failed to serialize");
        let json_value: serde_json::Value =
            serde_json::from_str(&serialized).expect("Failed to parse");
        let obj = json_value.as_object().unwrap();

        assert_eq!(obj.get("activate_fails").and_then(|v| v.as_u64()), Some(8));
        assert_eq!(
            obj.get("rx_bytes_count").and_then(|v| v.as_u64()),
            Some(1500)
        );
        assert_eq!(
            obj.get("tx_packets_count").and_then(|v| v.as_u64()),
            Some(17)
        );
    }

    #[test]
    fn test_flush_metrics_format() {
        METRICS.write().unwrap().clear();

        let cid1: u64 = 100;
        let cid2: u64 = 200;

        let mut metrics1 = VsockDeviceMetrics::default();
        metrics1.activate_fails.add(1);
        metrics1.rx_bytes_count.add(1024);

        let mut metrics2 = VsockDeviceMetrics::default();
        metrics2.activate_fails.add(2);
        metrics2.rx_bytes_count.add(2048);

        METRICS.write().unwrap().insert(cid1, Arc::new(metrics1));
        METRICS.write().unwrap().insert(cid2, Arc::new(metrics2));

        let mut buffer = Vec::new();
        let mut serializer = serde_json::Serializer::new(&mut buffer);
        flush_metrics(&mut serializer).expect("Failed to flush metrics");

        let json_str = String::from_utf8(buffer).expect("Invalid UTF-8");
        let json_value: serde_json::Value = serde_json::from_str(&json_str).expect("Invalid JSON");

        assert!(json_value.is_object());
        let obj = json_value.as_object().unwrap();

        assert_eq!(obj.len(), 3, "Expected 3 entries: 2 CIDs + 1 aggregate");

        assert!(obj.contains_key("100"));
        assert!(obj.contains_key("200"));
        assert!(obj.contains_key("vsock"));

        let vsock_aggregate = obj.get("vsock").unwrap().as_object().unwrap();
        assert_eq!(
            vsock_aggregate
                .get("activate_fails")
                .and_then(|v| v.as_u64()),
            Some(3)
        );
        assert_eq!(
            vsock_aggregate
                .get("rx_bytes_count")
                .and_then(|v| v.as_u64()),
            Some(3072)
        );
    }
}
