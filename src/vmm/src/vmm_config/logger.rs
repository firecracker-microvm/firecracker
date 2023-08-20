// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Auxiliary module for configuring the logger.
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::str::FromStr;

use logger::LOGGER;
use serde::{Deserialize, Serialize};

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
}

/// This is required since we originally supported `Warning` and uppercase variants being used as
/// the log level filter. It would be a breaking change to no longer support this. In the next
/// breaking release this should be removed (replaced with `log::LevelFilter` and only supporting
/// its default deserialization).
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum LevelFilter {
    /// [`log::LevelFilter:Off`]
    #[serde(alias = "OFF")]
    Off,
    /// [`log::LevelFilter:Trace`]
    #[serde(alias = "TRACE")]
    Trace,
    /// [`log::LevelFilter:Debug`]
    #[serde(alias = "DEBUG")]
    Debug,
    /// [`log::LevelFilter:Info`]
    #[serde(alias = "INFO")]
    Info,
    /// [`log::LevelFilter:Warn`]
    #[serde(alias = "WARN", alias = "WARNING", alias = "Warning")]
    Warn,
    /// [`log::LevelFilter:Error`]
    #[serde(alias = "ERROR")]
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
impl From<log::LevelFilter> for LevelFilter {
    fn from(filter: log::LevelFilter) -> LevelFilter {
        match filter {
            log::LevelFilter::Off => LevelFilter::Off,
            log::LevelFilter::Trace => LevelFilter::Trace,
            log::LevelFilter::Debug => LevelFilter::Debug,
            log::LevelFilter::Info => LevelFilter::Info,
            log::LevelFilter::Warn => LevelFilter::Warn,
            log::LevelFilter::Error => LevelFilter::Error,
        }
    }
}
impl FromStr for LevelFilter {
    type Err = <log::LevelFilter as FromStr>::Err;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Warning" => Ok(Self::Warn),
            _ => log::LevelFilter::from_str(s).map(LevelFilter::from),
        }
    }
}

/// Error type for [`LoggerConfig::apply`].
#[derive(Debug, thiserror::Error)]
#[error("Failed to open target file: {0}")]
pub struct LoggerConfigApplyError(pub std::io::Error);

impl LoggerConfig {
    /// Applies this logger configuration the existing logger.
    pub fn apply(self) -> Result<(), LoggerConfigApplyError> {
        let mut guard = LOGGER.0.lock().unwrap();
        if let Some(level) = self.level {
            guard.filter.level = log::LevelFilter::from(level);
        }

        if let Some(log_path) = self.log_path {
            let file = std::fs::OpenOptions::new()
                .custom_flags(libc::O_NONBLOCK)
                .read(true)
                .write(true)
                .open(log_path)
                .map_err(LoggerConfigApplyError)?;

            guard.target = Some(file);
        }

        if let Some(show_level) = self.show_level {
            guard.format.show_level = show_level;
        }

        if let Some(show_log_origin) = self.show_log_origin {
            guard.format.show_level = show_log_origin;
        }

        Ok(())
    }
}
