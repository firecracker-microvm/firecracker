// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::io::Write;
use std::sync::Mutex;
use std::thread;

use log::{LevelFilter, Log, Metadata, Record};
use utils::time::LocalTime;

use crate::metrics::{IncMetric, METRICS};

/// The logger.
/// 
/// Default values matching the swagger specification (`src/api_server/swagger/firecracker.yaml`).
pub static LOGGER: Logger = Logger(Mutex::new(LoggerConfiguration {
    target: None,
    filter: LogFiler {
        level: LevelFilter::Warn,
        file: None,
        module: None,
    },
    format: LogFormat {
        
        show_level: false,
        show_log_origin: false,
    },
}));

#[derive(Debug)]
pub struct LogFiler {
    pub level: LevelFilter,
    pub file: Option<String>,
    pub module: Option<String>,
}
#[derive(Debug)]
pub struct LogFormat {
    pub show_level: bool,
    pub show_log_origin: bool,
}
#[derive(Debug)]
pub struct LoggerConfiguration {
    pub target: Option<std::fs::File>,
    pub filter: LogFiler,
    pub format: LogFormat,
}
#[derive(Debug)]
pub struct Logger(pub Mutex<LoggerConfiguration>);

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.0.lock().unwrap().filter.level
    }

    fn log(&self, record: &Record) {
        // Lock the logger.
        let mut guard = self.0.lock().unwrap();

        // Check if the log message is enabled
        {
            let enabled_level = record.level() <= guard.filter.level;
            let enabled_file = match (record.file(), &guard.filter.file) {
                (Some(file), Some(filter)) => file.starts_with(filter),
                (Some(_), None) => true,
                (None, _) => false,
            };
            let enabled_module = match (record.module_path(), &guard.filter.module) {
                (Some(module), Some(filter)) => module.starts_with(filter),
                (Some(_), None) => true,
                (None, _) => false,
            };
            let enabled = enabled_level && enabled_file && enabled_module;
            if !enabled {
                return;
            }
        }

        // Prints log message
        {
            let thread = thread::current().name().unwrap_or("-").to_string();
            let level = match guard.format.show_level {
                true => format!(":{}", record.level()),
                false => String::new(),
            };

            let origin = match guard.format.show_log_origin {
                true => {
                    let file = record.file().unwrap_or("?");
                    let line = match record.line() {
                        Some(x) => x.to_string(),
                        None => String::from("?"),
                    };
                    format!(":{file}:{line}")
                }
                false => String::new(),
            };

            let message = format!(
                "{} [{thread}{level}{origin}] {}\n",
                LocalTime::now(),
                record.args()
            );

            let result = if let Some(file) = &mut guard.target {
                file.write_all(message.as_bytes())
            } else {
                std::io::stdout().write_all(message.as_bytes())
            };

            // If the write returns an error, increment missed log count.
            // No reason to log the error to stderr here, just increment the metric.
            if result.is_err() {
                METRICS.logger.missed_log_count.inc();
            }
        }
    }

    // This is currently not used.
    fn flush(&self) {
        unreachable!()
    }
}
