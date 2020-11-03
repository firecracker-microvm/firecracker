// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
mod init;
mod logger;
mod metrics;

use std::sync::LockResult;

pub use crate::logger::{LoggerError, LOGGER};
pub use crate::metrics::{
    IncMetric, MetricsError, SharedIncMetric, SharedStoreMetric, StoreMetric, METRICS,
};
pub use log::Level::*;
pub use log::*;

fn extract_guard<G>(lock_result: LockResult<G>) -> G {
    match lock_result {
        Ok(guard) => guard,
        // If a thread panics while holding this lock, the writer within should still be usable.
        // (we might get an incomplete log line or something like that).
        Err(poisoned) => poisoned.into_inner(),
    }
}

pub fn update_metric_with_elapsed_time(metric: &SharedStoreMetric, start_time_us: u64) -> u64 {
    let delta_us = utils::time::get_time_us(utils::time::ClockType::Monotonic) - start_time_us;
    metric.store(delta_us as usize);
    delta_us
}
