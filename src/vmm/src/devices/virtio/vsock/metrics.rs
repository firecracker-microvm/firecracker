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

use std::sync::{Arc, RwLock};

use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use crate::logger::SharedIncMetric;

/// Called by METRICS.flush(), this function facilitates serialization of vsock device metrics.
pub fn flush_metrics<S: Serializer>(serializer: S) -> Result<S::Ok, S::Error> {
    let mut seq = serializer.serialize_map(Some(1))?;
    match METRICS.read().unwrap().as_ref() {
        Some(metrics) => seq.serialize_entry("vsock", metrics.as_ref())?,
        None => seq.serialize_entry("vsock", &VsockDeviceMetrics::default())?,
    }
    seq.end()
}

/// Metrics of the (single) vsock device, shared by the device, its muxer and all connections.
pub(super) static METRICS: RwLock<Option<Arc<VsockDeviceMetrics>>> = RwLock::new(None);

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

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::logger::IncMetric;

    #[test]
    fn test_vsock_default() {
        let metrics = VsockDeviceMetrics::default();

        // Increment a field (e.g. activate_fails) to ensure it's being tracked.
        metrics.activate_fails.inc();

        let count = metrics.activate_fails.count();
        assert!(
            count > 0,
            "Expected activate_fails count > 0 but got {}",
            count
        );

        // Add more metric changes and assert correctness.
        metrics.activate_fails.inc();
        metrics.rx_bytes_count.add(5);

        let rx_count = metrics.rx_bytes_count.count();
        assert!(
            rx_count >= 5,
            "Expected rx_bytes_count >= 5 but got {}",
            rx_count
        );
    }

    #[test]
    fn test_vsock_metrics_serialization() {
        // Create a fresh metrics instance
        let metrics = VsockDeviceMetrics::default();

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
}
