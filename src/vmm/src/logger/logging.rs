// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};
use std::thread;

use log::{Log, Metadata, Record};
use serde::{Deserialize, Deserializer, Serialize};
use utils::time::LocalTime;

use super::metrics::{IncMetric, METRICS};

/// Default level filter for logger matching the swagger specification
/// (`src/firecracker/swagger/firecracker.yaml`).
pub const DEFAULT_LEVEL: log::LevelFilter = log::LevelFilter::Info;
/// Default instance id.
pub const DEFAULT_INSTANCE_ID: &str = "anonymous-instance";
/// Instance id.
pub static INSTANCE_ID: OnceLock<String> = OnceLock::new();

/// The logger.
///
/// Default values matching the swagger specification (`src/firecracker/swagger/firecracker.yaml`).
pub static LOGGER: Logger = Logger(Mutex::new(LoggerConfiguration {
    target: None,
    filter: LogFilter { module: None },
    format: LogFormat {
        show_level: false,
        show_log_origin: false,
    },
}));

/// Error type for [`Logger::init`].
pub type LoggerInitError = log::SetLoggerError;

/// Error type for [`Logger::update`].
#[derive(Debug, thiserror::Error)]
#[error("Failed to open target file: {0}")]
pub struct LoggerUpdateError(pub std::io::Error);

impl Logger {
    /// Initialize the logger.
    pub fn init(&'static self) -> Result<(), LoggerInitError> {
        log::set_logger(self)?;
        log::set_max_level(DEFAULT_LEVEL);
        Ok(())
    }

    /// Applies the given logger configuration the logger.
    pub fn update(&self, config: LoggerConfig) -> Result<(), LoggerUpdateError> {
        let mut guard = self.0.lock().unwrap();
        log::set_max_level(
            config
                .level
                .map(log::LevelFilter::from)
                .unwrap_or(DEFAULT_LEVEL),
        );

        if let Some(log_path) = config.log_path {
            let file = std::fs::OpenOptions::new()
                .custom_flags(libc::O_NONBLOCK)
                .read(true)
                .write(true)
                .open(log_path)
                .map_err(LoggerUpdateError)?;

            guard.target = Some(file);
        };

        if let Some(show_level) = config.show_level {
            guard.format.show_level = show_level;
        }

        if let Some(show_log_origin) = config.show_log_origin {
            guard.format.show_log_origin = show_log_origin;
        }

        if let Some(module) = config.module {
            guard.filter.module = Some(module);
        }

        // Ensure we drop the guard before attempting to log, otherwise this
        // would deadlock.
        drop(guard);

        Ok(())
    }
}

#[derive(Debug)]
pub struct LogFilter {
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
    pub filter: LogFilter,
    pub format: LogFormat,
}
#[derive(Debug)]
pub struct Logger(pub Mutex<LoggerConfiguration>);

impl Log for Logger {
    // No additional filters to <https://docs.rs/log/latest/log/fn.max_level.html>.
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        // Lock the logger.
        let mut guard = self.0.lock().unwrap();

        // Check if the log message is enabled
        {
            let enabled_module = match (&guard.filter.module, record.module_path()) {
                (Some(filter), Some(source)) => source.starts_with(filter),
                (Some(_), None) => false,
                (None, _) => true,
            };
            let enabled = enabled_module;
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
                "{} [{}:{thread}{level}{origin}] {}\n",
                LocalTime::now(),
                INSTANCE_ID
                    .get()
                    .map(|s| s.as_str())
                    .unwrap_or(DEFAULT_INSTANCE_ID),
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

    fn flush(&self) {}
}

/// Strongly typed structure used to describe the logger.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoggerConfig {
    /// Named pipe or file used as output for logs.
    pub log_path: Option<PathBuf>,
    /// The level of the Logger.
    pub level: Option<LevelFilter>,
    /// Whether to show the log level in the log.
    pub show_level: Option<bool>,
    /// Whether to show the log origin in the log.
    pub show_log_origin: Option<bool>,
    /// The module to filter logs by.
    pub module: Option<String>,
}

/// This is required since we originally supported `Warning` and uppercase variants being used as
/// the log level filter. It would be a breaking change to no longer support this. In the next
/// breaking release this should be removed (replaced with `log::LevelFilter` and only supporting
/// its default deserialization).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum LevelFilter {
    /// [`log::LevelFilter::Off`]
    Off,
    /// [`log::LevelFilter::Trace`]
    Trace,
    /// [`log::LevelFilter::Debug`]
    Debug,
    /// [`log::LevelFilter::Info`]
    Info,
    /// [`log::LevelFilter::Warn`]
    Warn,
    /// [`log::LevelFilter::Error`]
    Error,
}
impl From<LevelFilter> for log::LevelFilter {
    fn from(filter: LevelFilter) -> log::LevelFilter {
        match filter {
            LevelFilter::Off => log::LevelFilter::Off,
            LevelFilter::Trace => log::LevelFilter::Trace,
            LevelFilter::Debug => log::LevelFilter::Debug,
            LevelFilter::Info => log::LevelFilter::Info,
            LevelFilter::Warn => log::LevelFilter::Warn,
            LevelFilter::Error => log::LevelFilter::Error,
        }
    }
}
impl<'de> Deserialize<'de> for LevelFilter {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let key = String::deserialize(deserializer)?;
        let level = match key.to_lowercase().as_str() {
            "off" => Ok(LevelFilter::Off),
            "trace" => Ok(LevelFilter::Trace),
            "debug" => Ok(LevelFilter::Debug),
            "info" => Ok(LevelFilter::Info),
            "warn" | "warning" => Ok(LevelFilter::Warn),
            "error" => Ok(LevelFilter::Error),
            _ => Err(D::Error::custom("Invalid LevelFilter")),
        };
        level
    }
}

/// Error type for [`<LevelFilter as FromStr>::from_str`].
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("Failed to parse string to level filter: {0}")]
pub struct LevelFilterFromStrError(String);

impl FromStr for LevelFilter {
    type Err = LevelFilterFromStrError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "trace" => Ok(Self::Trace),
            "debug" => Ok(Self::Debug),
            "info" => Ok(Self::Info),
            "warn" | "warning" => Ok(Self::Warn),
            "error" => Ok(Self::Error),
            _ => Err(LevelFilterFromStrError(String::from(s))),
        }
    }
}

#[cfg(test)]
mod tests {
    use log::Level;

    use super::*;

    #[test]
    fn levelfilter_from_levelfilter() {
        assert_eq!(
            log::LevelFilter::from(LevelFilter::Off),
            log::LevelFilter::Off
        );
        assert_eq!(
            log::LevelFilter::from(LevelFilter::Trace),
            log::LevelFilter::Trace
        );
        assert_eq!(
            log::LevelFilter::from(LevelFilter::Debug),
            log::LevelFilter::Debug
        );
        assert_eq!(
            log::LevelFilter::from(LevelFilter::Info),
            log::LevelFilter::Info
        );
        assert_eq!(
            log::LevelFilter::from(LevelFilter::Warn),
            log::LevelFilter::Warn
        );
        assert_eq!(
            log::LevelFilter::from(LevelFilter::Error),
            log::LevelFilter::Error
        );
    }

    #[test]
    fn levelfilter_from_str_all_variants() {
        use itertools::Itertools;

        #[derive(Deserialize)]
        struct Foo {
            #[allow(dead_code)]
            level: LevelFilter,
        }

        for (level, level_enum) in [
            ("off", LevelFilter::Off),
            ("trace", LevelFilter::Trace),
            ("debug", LevelFilter::Debug),
            ("info", LevelFilter::Info),
            ("warn", LevelFilter::Warn),
            ("warning", LevelFilter::Warn),
            ("error", LevelFilter::Error),
        ] {
            let multi = level.chars().map(|_| 0..=1).multi_cartesian_product();
            for combination in multi {
                let variant = level
                    .chars()
                    .zip_eq(combination)
                    .map(|(c, v)| match v {
                        0 => c.to_ascii_lowercase(),
                        1 => c.to_ascii_uppercase(),
                        _ => unreachable!(),
                    })
                    .collect::<String>();

                let ex = format!("{{ \"level\": \"{}\" }}", variant);
                assert_eq!(LevelFilter::from_str(&variant), Ok(level_enum));
                assert!(serde_json::from_str::<Foo>(&ex).is_ok(), "{ex}");
            }
        }
        let ex = "{{ \"level\": \"blah\" }}".to_string();
        assert!(
            serde_json::from_str::<Foo>(&ex).is_err(),
            "expected error got {ex:#?}"
        );
        assert_eq!(
            LevelFilter::from_str("bad"),
            Err(LevelFilterFromStrError(String::from("bad")))
        );
    }

    #[test]
    fn logger() {
        // Get temp file path.
        let file = utils::tempfile::TempFile::new().unwrap();
        let path = file.as_path().to_str().unwrap().to_string();
        drop(file);

        // Create temp file.
        let target = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();

        // Create logger.
        let logger = Logger(Mutex::new(LoggerConfiguration {
            target: Some(target),
            filter: LogFilter {
                module: Some(String::from("module")),
            },
            format: LogFormat {
                show_level: true,
                show_log_origin: true,
            },
        }));

        // Assert results of enabled given specific metadata.
        assert!(logger.enabled(&Metadata::builder().level(Level::Warn).build()));
        assert!(logger.enabled(&Metadata::builder().level(Level::Debug).build()));

        // Log
        let metadata = Metadata::builder().level(Level::Error).build();
        let record = Record::builder()
            .args(format_args!("Error!"))
            .metadata(metadata)
            .file(Some("dir/app.rs"))
            .line(Some(200))
            .module_path(Some("module::server"))
            .build();
        logger.log(&record);

        // Test calling flush.
        logger.flush();

        // Asserts result of log.
        let contents = std::fs::read_to_string(&path).unwrap();
        let (_time, rest) = contents.split_once(' ').unwrap();
        let thread = thread::current().name().unwrap_or("-").to_string();
        assert_eq!(
            rest,
            format!("[{DEFAULT_INSTANCE_ID}:{thread}:ERROR:dir/app.rs:200] Error!\n")
        );

        std::fs::remove_file(path).unwrap();
    }
}
