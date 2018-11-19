// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{Display, Formatter, Result};

/// Enum used for setting the log level.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum LoggerLevel {
    /// When the level is set to `Error`, the logger will only contain entries
    /// that come from the `error` macro.
    Error,
    /// When the level is set to `Warning`, the logger will only contain entries
    /// that come from the `error` and `warn` macros.
    Warning,
    /// When the level is set to `Info`, the logger will only contain entries
    /// that come from the `error`, `warn` and `info` macros.
    Info,
    /// The most verbose log level.
    Debug,
}

/// Strongly typed structure used to describe the logger.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoggerConfig {
    /// Named pipe used as output for logs.
    pub log_fifo: String,
    /// Named pipe used as output for metrics.
    pub metrics_fifo: String,
    /// The level of the Logger.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<LoggerLevel>,
    /// When enabled, the logger will append to the output the severity of the log entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub show_level: Option<bool>,
    /// When enabled, the logger will append the origin of the log entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub show_log_origin: Option<bool>,
}

/// Errors associated with actions on the `LoggerConfig`.
#[derive(Debug)]
pub enum LoggerConfigError {
    /// Cannot initialize the logger due to bad user input.
    InitializationFailure(String),
}

impl Display for LoggerConfigError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        use self::LoggerConfigError::*;
        match *self {
            InitializationFailure(ref err_msg) => write!(f, "{}", err_msg),
        }
    }
}
