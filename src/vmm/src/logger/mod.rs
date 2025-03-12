// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Crate that implements Firecracker specific functionality as far as logging and metrics
//! collecting.

mod logging;
mod metrics;

pub use log::{Level, debug, error, info, log_enabled, trace, warn};
pub use logging::{
    DEFAULT_INSTANCE_ID, DEFAULT_LEVEL, INSTANCE_ID, LOGGER, LevelFilter, LevelFilterFromStrError,
    LoggerConfig, LoggerInitError, LoggerUpdateError,
};
pub use metrics::{
    IncMetric, LatencyAggregateMetrics, METRICS, MetricsError, ProcessTimeReporter,
    SharedIncMetric, SharedStoreMetric, StoreMetric,
};
use utils::time::{ClockType, get_time_us};

/// Alias for `std::io::LineWriter<std::fs::File>`.
pub type FcLineWriter = std::io::LineWriter<std::fs::File>;

/// Prefix to be used in log lines for functions/modules in Firecracker
/// that are not generally available.
const DEV_PREVIEW_LOG_PREFIX: &str = "[DevPreview]";

/// Log a standard warning message indicating a given feature name
/// is in development preview.
pub fn log_dev_preview_warning(feature_name: &str, msg_opt: Option<String>) {
    match msg_opt {
        None => warn!("{DEV_PREVIEW_LOG_PREFIX} {feature_name} is in development preview."),
        Some(msg) => {
            warn!("{DEV_PREVIEW_LOG_PREFIX} {feature_name} is in development preview - {msg}")
        }
    }
}

/// Helper function for updating the value of a store metric with elapsed time since some time in a
/// past.
pub fn update_metric_with_elapsed_time(metric: &SharedStoreMetric, start_time_us: u64) -> u64 {
    let delta_us = get_time_us(ClockType::Monotonic) - start_time_us;
    metric.store(delta_us);
    delta_us
}
