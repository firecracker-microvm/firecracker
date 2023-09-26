// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![deny(missing_docs)]

//! Crate that implements Firecracker specific functionality as far as logging and metrics
//! collecting.

mod init;
mod logging;
mod metrics;

use std::sync::LockResult;

pub use log::Level::*;
pub use log::{warn, *};

pub use crate::logger::logging::{LoggerError, LOGGER};
#[cfg(target_arch = "aarch64")]
pub use crate::logger::metrics::RTCDeviceMetrics;
pub use crate::logger::metrics::{
    IncMetric, MetricsError, ProcessTimeReporter, SerialDeviceMetrics, SharedIncMetric,
    SharedStoreMetric, StoreMetric, METRICS,
};

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

fn extract_guard<G>(lock_result: LockResult<G>) -> G {
    match lock_result {
        Ok(guard) => guard,
        // If a thread panics while holding this lock, the writer within should still be usable.
        // (we might get an incomplete log line or something like that).
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Helper function for updating the value of a store metric with elapsed time since some time in a
/// past.
pub fn update_metric_with_elapsed_time(metric: &SharedStoreMetric, start_time_us: u64) -> u64 {
    let delta_us = utils::time::get_time_us(utils::time::ClockType::Monotonic) - start_time_us;
    metric.store(delta_us as usize);
    delta_us
}
