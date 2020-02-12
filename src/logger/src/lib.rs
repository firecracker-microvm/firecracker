// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Workaround to `macro_reexport`.
#[macro_use]
extern crate lazy_static;
extern crate libc;
#[cfg(test)]
#[macro_use]
extern crate log;
#[cfg(not(test))]
extern crate log;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate utils;

mod logger;
mod metrics;

pub use log::*;
pub use logger::{AppInfo, LoggerError, LOGGER};
pub use metrics::{Metric, MetricsError, METRICS};

use std::io::Write;
use std::sync::{Mutex, MutexGuard};

fn buf_guard(
    buf: &Mutex<Option<Box<dyn Write + Send>>>,
) -> MutexGuard<Option<Box<dyn Write + Send>>> {
    match buf.lock() {
        Ok(guard) => guard,
        // If a thread panics while holding this lock, the writer within should still be usable.
        // (we might get an incomplete log line or something like that).
        Err(poisoned) => poisoned.into_inner(),
    }
}
