// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Enumeration of errors returned by the logger.

use std;
use std::error::Error;
use std::fmt;

/// Describes the errors which may occur while handling logging scenarios.
#[derive(Debug)]
pub enum LoggerError {
    /// First attempt at initialization failed.
    NeverInitialized(String),
    /// The logger is locked while preinitializing.
    IsPreinitializing,
    /// The logger is locked while initializing.
    IsInitializing,
    /// The logger does not allow reinitialization.
    AlreadyInitialized,
    /// Invalid logger option specified.
    InvalidLogOption(String),
    /// Writing to specified buffer failed.
    LogWrite(std::io::Error),
    /// Flushing messages stored in buffer to disk failed.
    LogFlush(std::io::Error),
    /// Error in the logging of the metrics.
    LogMetricFailure(String),
}

impl fmt::Display for LoggerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let printable = match *self {
            LoggerError::NeverInitialized(ref e) => e.to_string(),
            LoggerError::IsPreinitializing => {
                "The logger is preinitializing. Can't perform the requested action right now."
                    .to_string()
            }
            LoggerError::IsInitializing => {
                "The logger is initializing. Can't perform the requested action right now."
                    .to_string()
            }
            LoggerError::AlreadyInitialized => {
                "Reinitialization of logger not allowed.".to_string()
            }
            LoggerError::InvalidLogOption(ref s) => format!("Invalid log option: {}", s),
            LoggerError::LogWrite(ref e) => {
                format!("Failed to write logs. Error: {}", e.description())
            }
            LoggerError::LogFlush(ref e) => {
                format!("Failed to flush logs. Error: {}", e.description())
            }
            LoggerError::LogMetricFailure(ref e) => e.to_string(),
        };
        write!(f, "{}", printable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    #[test]
    fn test_error_messages() {
        assert!(format!(
            "{:?}",
            LoggerError::NeverInitialized(String::from("Bad Log Path Provided"))
        )
        .contains("NeverInitialized"));
        assert_eq!(
            format!(
                "{}",
                LoggerError::NeverInitialized(String::from("Bad Log Path Provided"))
            ),
            "Bad Log Path Provided"
        );

        assert!(format!("{:?}", LoggerError::AlreadyInitialized).contains("AlreadyInitialized"));
        assert_eq!(
            format!("{}", LoggerError::AlreadyInitialized),
            "Reinitialization of logger not allowed."
        );

        assert_eq!(
            format!("{}", LoggerError::IsPreinitializing),
            "The logger is preinitializing. Can't perform the requested action right now."
        );

        assert_eq!(
            format!("{}", LoggerError::InvalidLogOption("dirty-log".to_string())),
            "Invalid log option: dirty-log"
        );

        assert_eq!(
            format!("{}", LoggerError::IsInitializing),
            "The logger is initializing. Can't perform the requested action right now."
        );

        assert!(format!(
            "{:?}",
            LoggerError::LogWrite(std::io::Error::new(ErrorKind::Interrupted, "write"))
        )
        .contains("LogWrite"));
        assert_eq!(
            format!(
                "{}",
                LoggerError::LogWrite(std::io::Error::new(ErrorKind::Interrupted, "write"))
            ),
            "Failed to write logs. Error: write"
        );

        assert!(format!(
            "{:?}",
            LoggerError::LogFlush(std::io::Error::new(ErrorKind::Interrupted, "flush"))
        )
        .contains("LogFlush"));
        assert_eq!(
            format!(
                "{}",
                LoggerError::LogFlush(std::io::Error::new(ErrorKind::Interrupted, "flush"))
            ),
            "Failed to flush logs. Error: flush"
        );

        assert!(format!(
            "{:?}",
            LoggerError::LogMetricFailure("Failure in the logging of the metrics.".to_string())
        )
        .contains("LogMetricFailure"));
        assert_eq!(
            format!(
                "{}",
                LoggerError::LogMetricFailure("Failed to log metrics.".to_string())
            ),
            "Failed to log metrics."
        );
    }
}
