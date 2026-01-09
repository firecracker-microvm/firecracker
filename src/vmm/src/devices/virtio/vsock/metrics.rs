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

/// This function facilitates aggregation and serialization of
/// per device vsock metrics. (Can also handle singular)
pub fn flush_metrics<S: Serializer>(serializer: S) -> Result<S::Ok, S::Error> {
    let vsock_metrics = METRICS.read().unwrap();
    let metrics_len = vsock_metrics.metrics.len();
    // +1 to accomodate aggregate vsock metrics
    let mut seq = serializer.serialize_map(Some(1 + metrics_len))?;

    let mut vsock_aggregated: VsockDeviceMetrics = VsockDeviceMetrics::default();

    for (cid, metrics) in vsock_metrics.metrics.iter() {
        // serialization will flush the metrics so aggregate before it.
        let m: &VsockDeviceMetrics = metrics;
        vsock_aggregated.aggregate(m);
        seq.serialize_entry(&cid, m)?;
    }
    seq.serialize_entry("vsock", &vsock_aggregated)?;
    seq.end()
}

#[derive(Debug)]
pub struct VsockMetricsPerDevice {
    pub metrics: BTreeMap<u64, Arc<VsockDeviceMetrics>>,
}

impl VsockMetricsPerDevice {
    pub fn alloc(cid: u64) -> Arc<VsockDeviceMetrics> {
        Arc::clone(
            METRICS
                .write()
                .unwrap()
                .metrics
                .entry(cid)
                .or_insert_with(|| Arc::new(VsockDeviceMetrics::default())),
        )
    }
}

pub static METRICS: RwLock<VsockMetricsPerDevice> = RwLock::new(VsockMetricsPerDevice {
    metrics: BTreeMap::new(),
});

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

        // Allocate metrics for the device.
        VsockMetricsPerDevice::alloc(guest_cid);
        assert!(METRICS.read().unwrap().metrics.contains_key(&guest_cid));

        // Increment a field (e.g. activate_fails) to ensure it's being tracked.
        METRICS
            .read()
            .unwrap()
            .metrics
            .get(&guest_cid)
            .unwrap()
            .activate_fails
            .inc();

        let count = METRICS
            .read()
            .unwrap()
            .metrics
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
            .metrics
            .get(&guest_cid)
            .unwrap()
            .activate_fails
            .inc();

        METRICS
            .read()
            .unwrap()
            .metrics
            .get(&guest_cid)
            .unwrap()
            .rx_bytes_count
            .add(5);

        let rx_count = METRICS
            .read()
            .unwrap()
            .metrics
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
}
