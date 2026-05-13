// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Crate that implements Firecracker specific functionality as far as logging and metrics
//! collecting.

mod logging;
mod metrics;
pub mod rate_limited;

pub use log::{Level, log_enabled, trace};

// Re-export log macros under hidden names for use by wrapper macros.
#[doc(hidden)]
pub use log::{debug as __log_debug, error as __log_error, info as __log_info, warn as __log_warn};
// Re-export the rate-limited macros so callers can use
// `crate::logger::{error, warn, info}` as before.
pub use crate::{
    debug, error, error_unrestricted, info, info_unrestricted, warn, warn_unrestricted,
};
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
#[allow(clippy::disallowed_macros)]
pub fn log_dev_preview_warning(feature_name: &str, msg_opt: Option<String>) {
    match msg_opt {
        None => {
            warn_unrestricted!("{DEV_PREVIEW_LOG_PREFIX} {feature_name} is in development preview.")
        }
        Some(msg) => {
            warn_unrestricted!(
                "{DEV_PREVIEW_LOG_PREFIX} {feature_name} is in development preview - {msg}"
            )
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

/// Debug log — passthrough to `log::debug!`.
#[macro_export]
macro_rules! debug {
    ($($arg:tt)+) => {{
        #[allow(clippy::disallowed_macros)]
        { $crate::logger::__log_debug!($($arg)+) }
    }};
}

/// Unrestricted error log — bypasses rate limiting.
/// Use for non-guest-triggerable paths only.
#[macro_export]
macro_rules! error_unrestricted {
    ($($arg:tt)+) => {{
        #[allow(clippy::disallowed_macros)]
        { $crate::logger::__log_error!($($arg)+) }
    }};
}

/// Unrestricted warning log — bypasses rate limiting.
#[macro_export]
macro_rules! warn_unrestricted {
    ($($arg:tt)+) => {{
        #[allow(clippy::disallowed_macros)]
        { $crate::logger::__log_warn!($($arg)+) }
    }};
}

/// Unrestricted info log — bypasses rate limiting.
#[macro_export]
macro_rules! info_unrestricted {
    ($($arg:tt)+) => {{
        #[allow(clippy::disallowed_macros)]
        { $crate::logger::__log_info!($($arg)+) }
    }};
}

/// Internal helper macro implementing the rate-limiting logic.
#[doc(hidden)]
#[macro_export]
macro_rules! __log_rate_limited_impl {
    ($level:expr, $level_macro:path, $($arg:tt)+) => {{
        #[allow(clippy::disallowed_macros)]
        if $crate::logger::log_enabled!($level) {
            static LIMITER: $crate::logger::rate_limited::DefaultLogRateLimiter =
                $crate::logger::rate_limited::DefaultLogRateLimiter::new();
            if LIMITER.check_maybe_suppressed() {
                $level_macro!($($arg)+);
            }
        }
    }};
}

/// Rate-limited error log. Default: 10 messages per 5-second refill period.
/// Suppressed messages are tracked via the `rate_limited_log_count` metric.
/// When logging resumes after suppression, a warn-level summary reports
/// the number of suppressed messages.
#[macro_export]
macro_rules! error {
    ($($arg:tt)+) => {
        $crate::__log_rate_limited_impl!(
            $crate::logger::Level::Error,
            $crate::logger::error_unrestricted,
            $($arg)+
        )
    };
}

/// Rate-limited warning log. Same semantics as [`error!`].
#[macro_export]
macro_rules! warn {
    ($($arg:tt)+) => {
        $crate::__log_rate_limited_impl!(
            $crate::logger::Level::Warn,
            $crate::logger::warn_unrestricted,
            $($arg)+
        )
    };
}

/// Rate-limited info log. Same semantics as [`error!`].
#[macro_export]
macro_rules! info {
    ($($arg:tt)+) => {
        $crate::__log_rate_limited_impl!(
            $crate::logger::Level::Info,
            $crate::logger::info_unrestricted,
            $($arg)+
        )
    };
}
