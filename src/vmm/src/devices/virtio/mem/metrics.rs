// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the metrics system for memory devices.
//!
//! # Metrics format
//! The metrics are flushed in JSON when requested by vmm::logger::metrics::METRICS.write().
//!
//! ## JSON example with metrics:
//! ```json
//!  "memory_hotplug": {
//!     "activate_fails": "SharedIncMetric",
//!     "queue_event_fails": "SharedIncMetric",
//!     "queue_event_count": "SharedIncMetric",
//!     ...
//!  }
//! }
//! ```
//! Each `memory` field in the example above is a serializable `VirtioMemDeviceMetrics` structure
//! collecting metrics such as `activate_fails`, `queue_event_fails` etc. for the memoty hotplug
//! device.
//! Since Firecrakcer only supports one virtio-mem device, there is no per device metrics and
//! `memory_hotplug` represents the aggregate entropy metrics.

use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};
use std::sync::{Arc, RwLock};

use crate::logger::{LatencyAggregateMetrics, SharedIncMetric};

/// Stores aggregated virtio-mem metrics
pub(super) static METRICS: RwLock<Option<Arc<VirtioMemDeviceMetrics>>> = RwLock::new(None);

/// Called by METRICS.flush(), this function facilitates serialization of virtio-mem device metrics.
pub fn flush_metrics<S: Serializer>(serializer: S) -> Result<S::Ok, S::Error> {
    let mut seq = serializer.serialize_map(Some(1))?;
    let dev_name = "memory_hotplug";
    match METRICS.read().unwrap().as_ref() {
        Some(metrics) => seq.serialize_entry(dev_name, &metrics)?,
        None => seq.serialize_entry(dev_name, &VirtioMemDeviceMetrics::default())?,
    }
    seq.end()
}

#[derive(Default, Debug, Serialize)]
pub(super) struct VirtioMemDeviceMetrics {
    /// Number of device activation failures
    pub activate_fails: SharedIncMetric,
    /// Number of queue event handling failures
    pub queue_event_fails: SharedIncMetric,
    /// Number of queue events handled
    pub queue_event_count: SharedIncMetric,
    /// Latency of Plug operations
    pub plug_agg: LatencyAggregateMetrics,
    /// Number of Plug operations
    pub plug_count: SharedIncMetric,
    /// Number of plugged bytes
    pub plug_bytes: SharedIncMetric,
    /// Number of Plug operations failed
    pub plug_fails: SharedIncMetric,
    /// Latency of Unplug operations
    pub unplug_agg: LatencyAggregateMetrics,
    /// Number of Unplug operations
    pub unplug_count: SharedIncMetric,
    /// Number of unplugged bytes
    pub unplug_bytes: SharedIncMetric,
    /// Number of Unplug operations failed
    pub unplug_fails: SharedIncMetric,
    /// Number of discards failed for an Unplug or UnplugAll operation
    pub unplug_discard_fails: SharedIncMetric,
    /// Latency of UnplugAll operations
    pub unplug_all_agg: LatencyAggregateMetrics,
    /// Number of UnplugAll operations
    pub unplug_all_count: SharedIncMetric,
    /// Number of UnplugAll operations failed
    pub unplug_all_fails: SharedIncMetric,
    /// Latency of State operations
    pub state_agg: LatencyAggregateMetrics,
    /// Number of State operations
    pub state_count: SharedIncMetric,
    /// Number of State operations failed
    pub state_fails: SharedIncMetric,
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::logger::IncMetric;

    #[test]
    fn test_memory_hotplug_metrics() {
        let mem_metrics = VirtioMemDeviceMetrics::default();
        mem_metrics.queue_event_count.inc();
        assert_eq!(mem_metrics.queue_event_count.count(), 1);

        let serialized = serde_json::to_string(&mem_metrics).unwrap();
        let json_val: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        let obj = json_val.as_object().unwrap();

        assert_eq!(
            obj.get("queue_event_count").and_then(|v| v.as_u64()),
            Some(1)
        );
    }
}
