// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Workaround to `macro_reexport`.
#[macro_use]
extern crate lazy_static;
extern crate libc;
#[cfg_attr(test, macro_use)]
extern crate log;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate utils;

mod init;
mod logger;
mod metrics;

pub use log::Level::*;
pub use log::*;
pub use logger::{LoggerError, LOGGER};
pub use metrics::{Metric, MetricsError, SharedMetric, METRICS};

use std::sync::LockResult;

fn extract_guard<G>(lock_result: LockResult<G>) -> G {
    match lock_result {
        Ok(guard) => guard,
        // If a thread panics while holding this lock, the writer within should still be usable.
        // (we might get an incomplete log line or something like that).
        Err(poisoned) => poisoned.into_inner(),
    }
}

pub fn update_metric_with_elapsed_time(metric: &SharedMetric, start_time_us: u64) -> u64 {
    let delta_us = utils::time::get_time_us(utils::time::ClockType::Monotonic) - start_time_us;
    metric.store(delta_us as usize);
    delta_us
}
