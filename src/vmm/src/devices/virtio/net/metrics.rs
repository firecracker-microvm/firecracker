// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the metrics system for Network devices.
//!
//! # Metrics format
//! The metrics are flushed in JSON when requested by vmm::logger::metrics::METRICS.write().
//!
//! ## JSON example with metrics:
//! ```json
//! {
//!  "net": {
//!     "activate_fails": "SharedIncMetric",
//!     "cfg_fails": "SharedIncMetric",
//!     "mac_address_updates": "SharedIncMetric",
//!     "no_rx_avail_buffer": "SharedIncMetric",
//!     "no_tx_avail_buffer": "SharedIncMetric",
//!     ...
//!  }
//!  "net0": {
//!     "activate_fails": "SharedIncMetric",
//!     "cfg_fails": "SharedIncMetric",
//!     "mac_address_updates": "SharedIncMetric",
//!     "no_rx_avail_buffer": "SharedIncMetric",
//!     "no_tx_avail_buffer": "SharedIncMetric",
//!     ...
//!  }
//!  "net1": {
//!     "activate_fails": "SharedIncMetric",
//!     "cfg_fails": "SharedIncMetric",
//!     "mac_address_updates": "SharedIncMetric",
//!     "no_rx_avail_buffer": "SharedIncMetric",
//!     "no_tx_avail_buffer": "SharedIncMetric",
//!     ...
//!  }
//!  ...
//!  "netN": {
//!     "activate_fails": "SharedIncMetric",
//!     "cfg_fails": "SharedIncMetric",
//!     "mac_address_updates": "SharedIncMetric",
//!     "no_rx_avail_buffer": "SharedIncMetric",
//!     "no_tx_avail_buffer": "SharedIncMetric",
//!     ...
//!  }
//! }
//! ```
//! Each `net` field in the example above is a serializable `NetDeviceMetrics` structure
//! collecting metrics such as `activate_fails`, `cfg_fails`, etc. for the network device.
//! `net0`, `net1` and `netN` in the above example represent metrics 0th, 1st and 'N'th
//! network device respectively and `net` is the aggregate of all the per device metrics.
//!
//! # Limitations
//! Network device currently do not have `vmm::logger::metrics::StoreMetrics` so aggregate
//! doesn't consider them.
//!
//! # Design
//! The main design goals of this system are:
//! * To improve network device metrics by logging them at per device granularity.
//! * Continue to provide aggregate net metrics to maintain backward compatibility.
//! * Move NetDeviceMetrics out of from logger and decouple it.
//! * Use lockless operations, preferably ones that don't require anything other than simple
//!   reads/writes being atomic.
//! * Rely on `serde` to provide the actual serialization for writing the metrics.
//! * Since all metrics start at 0, we implement the `Default` trait via derive for all of them, to
//!   avoid having to initialize everything by hand.
//!
//! The system implements 1 types of metrics:
//! * Shared Incremental Metrics (SharedIncMetrics) - dedicated for the metrics which need a counter
//! (i.e the number of times an API request failed). These metrics are reset upon flush.
//! We use NET_DEV_METRICS_PVT instead of adding an entry of NetDeviceMetrics
//! in Net so that metrics are accessible to be flushed even from signal handlers.

use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use crate::logger::{IncMetric, SharedIncMetric};

#[derive(Debug, Default)]
pub struct NetDeviceMetricsIndex(usize);

impl NetDeviceMetricsIndex {
    pub fn get(&self) -> &NetDeviceMetrics {
        // SAFETY: This is called by individual Net devices
        // on self (i.e. self.metrics.get()) so no race condition
        // and it is safe.
        unsafe { &NET_DEV_METRICS_PVT.metrics[self.0] }
    }
}

/// provides instance for net metrics
#[derive(Debug, Default)]
pub struct NetDeviceMetricsPool {
    /// used to access per net device metrics
    metrics: Vec<NetDeviceMetrics>,
}

impl NetDeviceMetricsPool {
    /// default construction
    pub fn get() -> NetDeviceMetricsIndex {
        // SAFETY: This is only called during creation of a Net device
        // and since each device is created sequentially so there is no
        // case of race condition.
        unsafe {
            NET_DEV_METRICS_PVT.metrics.push(NetDeviceMetrics::new());
            NetDeviceMetricsIndex(NET_DEV_METRICS_PVT.metrics.len() - 1)
        }
    }
}

/// Contains Network-related metrics per device.
static mut NET_DEV_METRICS_PVT: NetDeviceMetricsPool = NetDeviceMetricsPool {
    metrics: Vec::new(),
};

pub fn flush_metrics<S: Serializer>(serializer: S) -> Result<S::Ok, S::Error> {
    // SAFETY: This is called from vmm::logger::metrics::METRICS.write which
    // has a lock and takes care of race condition.
    unsafe {
        // +1 to accomodate aggregate net metrics
        let mut seq = serializer.serialize_map(Some(1 + NET_DEV_METRICS_PVT.metrics.len()))?;

        let net_aggregated: NetDeviceMetrics = NET_DEV_METRICS_PVT.metrics.iter().fold(
            NetDeviceMetrics::default(),
            |mut net_agg, net| {
                net_agg.aggregate(net);
                net_agg
            },
        );

        seq.serialize_entry("net", &net_aggregated)?;

        for (i, metrics) in NET_DEV_METRICS_PVT.metrics.iter().enumerate() {
            let devn = format!("net{}", i);
            // let ser_metrics = NetDeviceMetrics::default().aggregate(&metrics);
            seq.serialize_entry(&devn, &metrics)?;
        }
        seq.end()
    }
}

/// Network-related metrics.
// #[derive(Debug, Default)]
#[derive(Debug, Default, Serialize)]
pub struct NetDeviceMetrics {
    /// Number of times when activate failed on a network device.
    pub activate_fails: SharedIncMetric,
    /// Number of times when interacting with the space config of a network device failed.
    pub cfg_fails: SharedIncMetric,
    /// Number of times the mac address was updated through the config space.
    pub mac_address_updates: SharedIncMetric,
    /// No available buffer for the net device rx queue.
    pub no_rx_avail_buffer: SharedIncMetric,
    /// No available buffer for the net device tx queue.
    pub no_tx_avail_buffer: SharedIncMetric,
    /// Number of times when handling events on a network device failed.
    pub event_fails: SharedIncMetric,
    /// Number of events associated with the receiving queue.
    pub rx_queue_event_count: SharedIncMetric,
    /// Number of events associated with the rate limiter installed on the receiving path.
    pub rx_event_rate_limiter_count: SharedIncMetric,
    /// Number of RX partial writes to guest.
    pub rx_partial_writes: SharedIncMetric,
    /// Number of RX rate limiter throttling events.
    pub rx_rate_limiter_throttled: SharedIncMetric,
    /// Number of events received on the associated tap.
    pub rx_tap_event_count: SharedIncMetric,
    /// Number of bytes received.
    pub rx_bytes_count: SharedIncMetric,
    /// Number of packets received.
    pub rx_packets_count: SharedIncMetric,
    /// Number of errors while receiving data.
    pub rx_fails: SharedIncMetric,
    /// Number of successful read operations while receiving data.
    pub rx_count: SharedIncMetric,
    /// Number of times reading from TAP failed.
    pub tap_read_fails: SharedIncMetric,
    /// Number of times writing to TAP failed.
    pub tap_write_fails: SharedIncMetric,
    /// Number of transmitted bytes.
    pub tx_bytes_count: SharedIncMetric,
    /// Number of malformed TX frames.
    pub tx_malformed_frames: SharedIncMetric,
    /// Number of errors while transmitting data.
    pub tx_fails: SharedIncMetric,
    /// Number of successful write operations while transmitting data.
    pub tx_count: SharedIncMetric,
    /// Number of transmitted packets.
    pub tx_packets_count: SharedIncMetric,
    /// Number of TX partial reads from guest.
    pub tx_partial_reads: SharedIncMetric,
    /// Number of events associated with the transmitting queue.
    pub tx_queue_event_count: SharedIncMetric,
    /// Number of events associated with the rate limiter installed on the transmitting path.
    pub tx_rate_limiter_event_count: SharedIncMetric,
    /// Number of RX rate limiter throttling events.
    pub tx_rate_limiter_throttled: SharedIncMetric,
    /// Number of packets with a spoofed mac, sent by the guest.
    pub tx_spoofed_mac_count: SharedIncMetric,
}

impl NetDeviceMetrics {
    /// Const default construction.
    pub const fn new() -> Self {
        Self {
            activate_fails: SharedIncMetric::new(),
            cfg_fails: SharedIncMetric::new(),
            mac_address_updates: SharedIncMetric::new(),
            no_rx_avail_buffer: SharedIncMetric::new(),
            no_tx_avail_buffer: SharedIncMetric::new(),
            event_fails: SharedIncMetric::new(),
            rx_queue_event_count: SharedIncMetric::new(),
            rx_event_rate_limiter_count: SharedIncMetric::new(),
            rx_partial_writes: SharedIncMetric::new(),
            rx_rate_limiter_throttled: SharedIncMetric::new(),
            rx_tap_event_count: SharedIncMetric::new(),
            rx_bytes_count: SharedIncMetric::new(),
            rx_packets_count: SharedIncMetric::new(),
            rx_fails: SharedIncMetric::new(),
            rx_count: SharedIncMetric::new(),
            tap_read_fails: SharedIncMetric::new(),
            tap_write_fails: SharedIncMetric::new(),
            tx_bytes_count: SharedIncMetric::new(),
            tx_malformed_frames: SharedIncMetric::new(),
            tx_fails: SharedIncMetric::new(),
            tx_count: SharedIncMetric::new(),
            tx_packets_count: SharedIncMetric::new(),
            tx_partial_reads: SharedIncMetric::new(),
            tx_queue_event_count: SharedIncMetric::new(),
            tx_rate_limiter_event_count: SharedIncMetric::new(),
            tx_rate_limiter_throttled: SharedIncMetric::new(),
            tx_spoofed_mac_count: SharedIncMetric::new(),
        }
    }

    /// Net metrics are SharedIncMetric where the diff of current vs
    /// old is serialized i.e. serialize_u64(current-old).
    /// So to have the aggregate serialized in same way we need to
    /// fetch the diff of current vs old metrics and add it to the
    /// aggregate.
    pub fn aggregate(&mut self, other: &Self) {
        self.activate_fails.add(other.activate_fails.fetch_diff());
        self.cfg_fails.add(other.cfg_fails.fetch_diff());
        self.mac_address_updates
            .add(other.mac_address_updates.fetch_diff());
        self.no_rx_avail_buffer
            .add(other.no_rx_avail_buffer.fetch_diff());
        self.no_tx_avail_buffer
            .add(other.no_tx_avail_buffer.fetch_diff());
        self.event_fails.add(other.event_fails.fetch_diff());
        self.rx_queue_event_count
            .add(other.rx_queue_event_count.fetch_diff());
        self.rx_event_rate_limiter_count
            .add(other.rx_event_rate_limiter_count.fetch_diff());
        self.rx_partial_writes
            .add(other.rx_partial_writes.fetch_diff());
        self.rx_rate_limiter_throttled
            .add(other.rx_rate_limiter_throttled.fetch_diff());
        self.rx_tap_event_count
            .add(other.rx_tap_event_count.fetch_diff());
        self.rx_bytes_count.add(other.rx_bytes_count.fetch_diff());
        self.rx_packets_count
            .add(other.rx_packets_count.fetch_diff());
        self.rx_fails.add(other.rx_fails.fetch_diff());
        self.rx_count.add(other.rx_count.fetch_diff());
        self.tap_read_fails.add(other.tap_read_fails.fetch_diff());
        self.tap_write_fails.add(other.tap_write_fails.fetch_diff());
        self.tx_bytes_count.add(other.tx_bytes_count.fetch_diff());
        self.tx_malformed_frames
            .add(other.tx_malformed_frames.fetch_diff());
        self.tx_fails.add(other.tx_fails.fetch_diff());
        self.tx_count.add(other.tx_count.fetch_diff());
        self.tx_packets_count
            .add(other.tx_packets_count.fetch_diff());
        self.tx_partial_reads
            .add(other.tx_partial_reads.fetch_diff());
        self.tx_queue_event_count
            .add(other.tx_queue_event_count.fetch_diff());
        self.tx_rate_limiter_event_count
            .add(other.tx_rate_limiter_event_count.fetch_diff());
        self.tx_rate_limiter_throttled
            .add(other.tx_rate_limiter_throttled.fetch_diff());
        self.tx_spoofed_mac_count
            .add(other.tx_spoofed_mac_count.fetch_diff());
    }
}
