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

/// Stores aggregate metrics of all Vsock connections/actions
pub(super) static METRICS: VsockDeviceMetrics = VsockDeviceMetrics::new();

/// Called by METRICS.flush(), this function facilitates serialization of vsock device metrics.
pub fn flush_metrics<S: Serializer>(serializer: S) -> Result<S::Ok, S::Error> {
    let mut seq = serializer.serialize_map(Some(1))?;
    seq.serialize_entry("vsock", &METRICS)?;
    seq.end()
}

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

    #[test]
    fn test_vsock_dev_metrics() {
        let vsock_metrics: VsockDeviceMetrics = VsockDeviceMetrics::new();
        let vsock_metrics_local: String = serde_json::to_string(&vsock_metrics).unwrap();
        // the 1st serialize flushes the metrics and resets values to 0 so that
        // we can compare the values with local metrics.
        serde_json::to_string(&METRICS).unwrap();
        let vsock_metrics_global: String = serde_json::to_string(&METRICS).unwrap();
        assert_eq!(vsock_metrics_local, vsock_metrics_global);
        vsock_metrics.conns_added.inc();
        assert_eq!(vsock_metrics.conns_added.count(), 1);
    }
}
