// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Auxiliary module for configuring the logger.

extern crate logger as logger_crate;

use std::fmt::{Display, Formatter};
use std::path::PathBuf;

use self::logger_crate::{LevelFilter, LOGGER};
use super::{open_file_nonblock, FcLineWriter};
use vmm_config::instance_info::InstanceInfo;

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

impl LoggerLevel {
    /// Converts from a logger level value of type String to the corresponding LoggerLevel variant
    /// or returns an error if the parsing failed.
    pub fn from_string(level: String) -> std::result::Result<Self, LoggerConfigError> {
        match level.as_str() {
            "Error" => Ok(LoggerLevel::Error),
            "Warning" => Ok(LoggerLevel::Warning),
            "Info" => Ok(LoggerLevel::Info),
            "Debug" => Ok(LoggerLevel::Debug),
            invalid_value => Err(LoggerConfigError::InitializationFailure(
                invalid_value.to_string(),
            )),
        }
    }
}

impl Default for LoggerLevel {
    fn default() -> LoggerLevel {
        LoggerLevel::Warning
    }
}

impl Into<LevelFilter> for LoggerLevel {
    fn into(self) -> LevelFilter {
        match self {
            LoggerLevel::Error => LevelFilter::Error,
            LoggerLevel::Warning => LevelFilter::Warn,
            LoggerLevel::Info => LevelFilter::Info,
            LoggerLevel::Debug => LevelFilter::Debug,
        }
    }
}

/// Strongly typed structure used to describe the logger.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoggerConfig {
    /// Named pipe or file used as output for logs.
    pub log_path: PathBuf,
    /// The level of the Logger.
    #[serde(default = "LoggerLevel::default")]
    pub level: LoggerLevel,
    /// When enabled, the logger will append to the output the severity of the log entry.
    #[serde(default)]
    pub show_level: bool,
    /// When enabled, the logger will append the origin of the log entry.
    #[serde(default)]
    pub show_log_origin: bool,
}

impl LoggerConfig {
    /// Creates a new LoggerConfig.
    pub fn new(
        log_path: PathBuf,
        level: LoggerLevel,
        show_level: bool,
        show_log_origin: bool,
    ) -> LoggerConfig {
        LoggerConfig {
            log_path,
            level,
            show_level,
            show_log_origin,
        }
    }
}

/// Errors associated with actions on the `LoggerConfig`.
#[derive(Debug)]
pub enum LoggerConfigError {
    /// Cannot initialize the logger due to bad user input.
    InitializationFailure(String),
}

impl Display for LoggerConfigError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::LoggerConfigError::*;
        match *self {
            InitializationFailure(ref err_msg) => write!(f, "{}", err_msg.replace("\"", "")),
        }
    }
}

/// Configures the logger as described in `logger_cfg`.
pub fn init_logger(
    logger_cfg: LoggerConfig,
    instance_info: &InstanceInfo,
) -> std::result::Result<(), LoggerConfigError> {
    LOGGER
        .set_max_level(logger_cfg.level.into())
        .set_include_origin(logger_cfg.show_log_origin, logger_cfg.show_log_origin)
        .set_include_level(logger_cfg.show_level);

    let writer = FcLineWriter::new(
        open_file_nonblock(&logger_cfg.log_path)
            .map_err(|e| LoggerConfigError::InitializationFailure(e.to_string()))?,
    );
    LOGGER
        .init(
            format!(
                "Running {} v{}",
                instance_info.app_name, instance_info.vmm_version
            ),
            Box::new(writer),
        )
        .map_err(|e| LoggerConfigError::InitializationFailure(e.to_string()))
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader};

    use super::*;
    use utils::tempfile::TempFile;
    use utils::time::TimestampUs;

    use Vmm;

    #[test]
    fn test_init_logger() {
        let default_instance_info = InstanceInfo {
            id: "".to_string(),
            started: false,
            vmm_version: "some_version".to_string(),
            app_name: "".to_string(),
        };

        // Error case: initializing logger with invalid pipe returns error.
        let desc = LoggerConfig {
            log_path: PathBuf::from("not_found_file_log"),
            level: LoggerLevel::Debug,
            show_level: false,
            show_log_origin: false,
        };
        assert!(init_logger(desc, &default_instance_info).is_err());

        // Initializing logger with valid pipe is ok.
        let log_file = TempFile::new().unwrap();
        let desc = LoggerConfig {
            log_path: log_file.as_path().to_path_buf(),
            level: LoggerLevel::Info,
            show_level: true,
            show_log_origin: true,
        };

        assert!(init_logger(desc.clone(), &default_instance_info).is_ok());
        assert!(init_logger(desc, &default_instance_info).is_err());

        // Validate logfile works.
        warn!("this is a test");

        let mut reader = BufReader::new(log_file.into_file());

        let mut line = String::new();
        loop {
            if line.contains("this is a test") {
                break;
            }
            if reader.read_line(&mut line).unwrap() == 0 {
                // If it ever gets here, this assert will fail.
                assert!(line.contains("this is a test"));
            }
        }

        // Validate logging the boot time works.
        Vmm::log_boot_time(&TimestampUs::default());
        let mut line = String::new();
        loop {
            if line.contains("Guest-boot-time =") {
                break;
            }
            if reader.read_line(&mut line).unwrap() == 0 {
                // If it ever gets here, this assert will fail.
                assert!(line.contains("Guest-boot-time ="));
            }
        }
    }

    #[test]
    fn test_error_display() {
        assert_eq!(
            format!(
                "{}",
                LoggerConfigError::InitializationFailure(String::from(
                    "Failed to initialize logger"
                ))
            ),
            "Failed to initialize logger"
        );
    }

    #[test]
    fn test_new_logger_config() {
        let logger_config =
            LoggerConfig::new(PathBuf::from("log"), LoggerLevel::Debug, false, true);
        assert_eq!(logger_config.log_path, PathBuf::from("log"));
        assert_eq!(logger_config.level, LoggerLevel::Debug);
        assert_eq!(logger_config.show_level, false);
        assert_eq!(logger_config.show_log_origin, true);
    }

    #[test]
    fn test_parse_level() {
        // Check `from_string()` behaviour for different scenarios.
        assert_eq!(
            format!(
                "{}",
                LoggerLevel::from_string("random_value".to_string()).unwrap_err()
            ),
            "random_value"
        );
        assert_eq!(
            LoggerLevel::from_string("Error".to_string()).unwrap(),
            LoggerLevel::Error
        );
        assert_eq!(
            LoggerLevel::from_string("Warning".to_string()).unwrap(),
            LoggerLevel::Warning
        );
        assert_eq!(
            LoggerLevel::from_string("Info".to_string()).unwrap(),
            LoggerLevel::Info
        );
        assert_eq!(
            LoggerLevel::from_string("Debug".to_string()).unwrap(),
            LoggerLevel::Debug
        );
    }
}
