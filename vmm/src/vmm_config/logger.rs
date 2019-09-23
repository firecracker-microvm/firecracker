// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Auxiliary module for configuring the logger.
extern crate serde_json;

use libc::O_NONBLOCK;
use std::fmt::{Display, Formatter};
use std::fs::{File, OpenOptions};
use std::io::{LineWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use self::serde_json::Value;

type Result<T> = std::result::Result<T, std::io::Error>;

/// Structure `LoggerWriter` used for writing to a FIFO.
pub struct LoggerWriter {
    line_writer: Mutex<LineWriter<File>>,
}

impl LoggerWriter {
    /// Create and open a FIFO for writing to it.
    /// In order to not block the instance if nobody is consuming the logs that are flushed to the
    /// two pipes, we are opening them with `O_NONBLOCK` flag. In this case, writing to a pipe will
    /// start failing when reaching 64K of unconsumed content. Simultaneously,
    /// the `missed_metrics_count` metric will get increased.
    ///
    pub fn new(fifo_path: &str) -> Result<LoggerWriter> {
        let fifo = PathBuf::from(fifo_path);
        OpenOptions::new()
            .custom_flags(O_NONBLOCK)
            .read(true)
            .write(true)
            .open(&fifo)
            .map(|t| LoggerWriter {
                line_writer: Mutex::new(LineWriter::new(t)),
            })
    }

    fn get_line_writer(&self) -> MutexGuard<LineWriter<File>> {
        match self.line_writer.lock() {
            Ok(guard) => guard,
            // If a thread panics while holding this lock, the writer within should still be usable.
            // (we might get an incomplete log line or something like that).
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl Write for LoggerWriter {
    fn write(&mut self, msg: &[u8]) -> Result<(usize)> {
        let mut line_writer = self.get_line_writer();
        line_writer.write_all(msg).map(|()| msg.len())
    }

    fn flush(&mut self) -> Result<()> {
        let mut line_writer = self.get_line_writer();
        line_writer.flush()
    }
}

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
    #[serde(default = "default_level")]
    pub level: LoggerLevel,
    /// When enabled, the logger will append to the output the severity of the log entry.
    #[serde(default)]
    pub show_level: bool,
    /// When enabled, the logger will append the origin of the log entry.
    #[serde(default)]
    pub show_log_origin: bool,
    /// Additional logging options.
    #[cfg(target_arch = "x86_64")]
    #[serde(default = "default_log_options")]
    pub options: Value,
}

fn default_level() -> LoggerLevel {
    LoggerLevel::Warning
}

fn default_log_options() -> Value {
    Value::Array(vec![])
}

/// Errors associated with actions on the `LoggerConfig`.
#[derive(Debug)]
pub enum LoggerConfigError {
    /// Cannot initialize the logger due to bad user input.
    InitializationFailure(String),
    /// Cannot flush the metrics.
    FlushMetrics(String),
}

impl Display for LoggerConfigError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::LoggerConfigError::*;
        match *self {
            InitializationFailure(ref err_msg) => write!(f, "{}", err_msg.replace("\"", "")),
            FlushMetrics(ref err_msg) => write!(f, "{}", err_msg.replace("\"", "")),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate tempfile;

    use self::tempfile::NamedTempFile;
    use super::*;

    #[test]
    fn test_log_writer() {
        let log_file_temp =
            NamedTempFile::new().expect("Failed to create temporary output logging file.");
        let good_file = String::from(log_file_temp.path().to_path_buf().to_str().unwrap());
        let res = LoggerWriter::new(&good_file);
        assert!(res.is_ok());

        let mut fw = res.unwrap();
        let msg = String::from("some message");
        assert!(fw.write(&msg.as_bytes()).is_ok());
        assert!(fw.flush().is_ok());
    }
}
