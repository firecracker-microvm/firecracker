// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Component-defined metrics traits and implementations.
//!
//! This module provides reusable metric traits and implementations that can be used
//! by any component without depending on Firecracker-specific logger implementation.
//!
//! # Design
//! The main design goals of this system are:
//! * Use lockless operations, preferably ones that don't require anything other than simple
//!   reads/writes being atomic.
//! * Exploit interior mutability and atomics being Sync to allow all methods (including the ones
//!   which are effectively mutable) to be callable on a global non-mut static.
//! * Rely on `serde` to provide the actual serialization for writing the metrics.
//! * Since all metrics start at 0, we implement the `Default` trait via derive for all of them, to
//!   avoid having to initialize everything by hand.
//!
//! The system implements 2 types of metrics:
//! * Shared Incremental Metrics (SharedIncMetrics) - dedicated for the metrics which need a counter
//!   (i.e the number of times an API request failed). These metrics are reset upon flush.
//! * Shared Store Metrics (SharedStoreMetrics) - are targeted at keeping a persistent value, it is
//!   not intended to act as a counter (i.e for measure the process start up time for example).

use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Serialize, Serializer};
use utils::time::{ClockType, get_time_us};

/// Used for defining new types of metrics that act as a counter (i.e they are continuously updated
/// by incrementing their value).
pub trait IncMetric {
    /// Adds `value` to the current counter.
    fn add(&self, value: u64);
    /// Increments by 1 unit the current counter.
    fn inc(&self) {
        self.add(1);
    }
    /// Returns current value of the counter.
    fn count(&self) -> u64;

    /// Returns diff of current and old value of the counter.
    /// Mostly used in process of aggregating per device metrics.
    fn fetch_diff(&self) -> u64;
}

/// Used for defining new types of metrics that do not need a counter and act as a persistent
/// indicator.
pub trait StoreMetric {
    /// Returns current value of the counter.
    fn fetch(&self) -> u64;
    /// Stores `value` to the current counter.
    fn store(&self, value: u64);
}

/// Representation of a metric that is expected to be incremented from more than one thread, so more
/// synchronization is necessary.
// It's currently used for vCPU metrics. An alternative here would be
// to have one instance of every metric for each thread, and to
// aggregate them when writing. However this probably overkill unless we have a lot of vCPUs
// incrementing metrics very often. Still, it's there if we ever need it :-s
// We will be keeping two values for each metric for being able to reset
// counters on each metric.
// 1st member - current value being updated
// 2nd member - old value that gets the current value whenever metrics is flushed to disk
#[derive(Debug, Default)]
pub struct SharedIncMetric(AtomicU64, AtomicU64);

impl SharedIncMetric {
    /// Const default construction.
    pub const fn new() -> Self {
        Self(AtomicU64::new(0), AtomicU64::new(0))
    }
}

/// Representation of a metric that is expected to hold a value that can be accessed
/// from more than one thread, so more synchronization is necessary.
#[derive(Debug, Default)]
pub struct SharedStoreMetric(AtomicU64);

impl SharedStoreMetric {
    /// Const default construction.
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }
}

impl IncMetric for SharedIncMetric {
    // While the order specified for this operation is still Relaxed, the actual instruction will
    // be an asm "LOCK; something" and thus atomic across multiple threads, simply because of the
    // fetch_and_add (as opposed to "store(load() + 1)") implementation for atomics.
    // TODO: would a stronger ordering make a difference here?
    fn add(&self, value: u64) {
        self.0.fetch_add(value, Ordering::Relaxed);
    }

    fn count(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    fn fetch_diff(&self) -> u64 {
        self.0.load(Ordering::Relaxed) - self.1.load(Ordering::Relaxed)
    }
}

impl StoreMetric for SharedStoreMetric {
    fn fetch(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    fn store(&self, value: u64) {
        self.0.store(value, Ordering::Relaxed);
    }
}

impl Serialize for SharedIncMetric {
    /// Reset counters of each metrics. Here we suppose that Serialize's goal is to help with the
    /// flushing of metrics.
    /// !!! Any print of the metrics will also reset them. Use with caution !!!
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let snapshot = self.0.load(Ordering::Relaxed);
        let res = serializer.serialize_u64(snapshot - self.1.load(Ordering::Relaxed));

        if res.is_ok() {
            self.1.store(snapshot, Ordering::Relaxed);
        }
        res
    }
}

impl Serialize for SharedStoreMetric {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.0.load(Ordering::Relaxed))
    }
}

/// Used to record Aggregate (min/max/sum) of latency metrics
#[derive(Debug, Default, Serialize)]
pub struct LatencyAggregateMetrics {
    /// represents minimum value of the metrics in microseconds
    pub min_us: SharedStoreMetric,
    /// represents maximum value of the metrics in microseconds
    pub max_us: SharedStoreMetric,
    /// represents sum of the metrics in microseconds
    pub sum_us: SharedIncMetric,
}

impl LatencyAggregateMetrics {
    /// Const default construction.
    pub const fn new() -> Self {
        Self {
            min_us: SharedStoreMetric::new(),
            max_us: SharedStoreMetric::new(),
            sum_us: SharedIncMetric::new(),
        }
    }

    /// returns a latency recorder which captures stores start_time
    /// and updates the actual metrics at the end of recorders lifetime.
    /// in short instead of below 2 lines :
    /// 1st for start_time_us = get_time_us()
    /// 2nd for delta_time_us = get_time_us() - start_time; and metrics.store(delta_time_us)
    /// we have just `_m = metrics.record_latency_metrics()`
    pub fn record_latency_metrics(&self) -> LatencyMetricsRecorder<'_> {
        LatencyMetricsRecorder::new(self)
    }
}

/// Provides efficient way to record LatencyAggregateMetrics
#[derive(Debug)]
pub struct LatencyMetricsRecorder<'a> {
    start_time: u64,
    metric: &'a LatencyAggregateMetrics,
}

impl<'a> LatencyMetricsRecorder<'a> {
    /// Const default construction.
    fn new(metric: &'a LatencyAggregateMetrics) -> Self {
        Self {
            start_time: get_time_us(ClockType::Monotonic),
            metric,
        }
    }
}

impl Drop for LatencyMetricsRecorder<'_> {
    /// records aggregate (min/max/sum) for the given metric
    /// This captures delta between self.start_time and current time
    /// and updates min/max/sum metrics.
    ///  self.start_time is recorded in new() and metrics are updated in drop
    fn drop(&mut self) {
        let delta_us = get_time_us(ClockType::Monotonic) - self.start_time;
        self.metric.sum_us.add(delta_us);
        let min_us = self.metric.min_us.fetch();
        let max_us = self.metric.max_us.fetch();
        if (0 == min_us) || (min_us > delta_us) {
            self.metric.min_us.store(delta_us);
        }
        if (0 == max_us) || (max_us < delta_us) {
            self.metric.max_us.store(delta_us);
        }
    }
}
