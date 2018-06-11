//! Errors returned by the logger.

use std;
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum LoggerError {
    /// First attempt at initialization failed.
    NeverInitialized(String),
    /// The logger does not allow reinitialization.
    AlreadyInitialized,
    /// Creating log file fails.
    CreateLogFile(std::io::Error),
    /// Writing to log file fails.
    FileLogWrite(std::io::Error),
    /// Flushing to disk fails.
    FileLogFlush(std::io::Error),
    /// Error obtaining lock on mutex.
    MutexLockFailure(String),
    /// Error in the logging of the metrics.
    LogMetricFailure(String),
    /// Signals not logging a metric due to rate limiting.
    LogMetricRateLimit,
}

impl fmt::Display for LoggerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let printable = match *self {
            LoggerError::NeverInitialized(ref e) => format!("{}", e),
            LoggerError::AlreadyInitialized => {
                format!("{}", "Reinitialization of logger not allowed.")
            }
            LoggerError::CreateLogFile(ref e) => {
                format!("Failed to create log file. Error: {}", e.description())
            }
            LoggerError::FileLogWrite(ref e) => {
                format!("Failed to write to log file. Error: {}", e.description())
            }
            LoggerError::FileLogFlush(ref e) => {
                format!("Failed to flush log file. Error: {}", e.description())
            }
            LoggerError::MutexLockFailure(ref e) => format!("{}", e),
            LoggerError::LogMetricFailure(ref e) => format!("{}", e),
            LoggerError::LogMetricRateLimit => format!("{}", "Metric will not yet be logged."),
        };
        write!(f, "{}", printable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    #[test]
    fn test_formatting() {
        assert!(
            format!(
                "{:?}",
                LoggerError::NeverInitialized(String::from("Bad Log Path Provided"))
            ).contains("NeverInitialized")
        );
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

        assert!(
            format!(
                "{:?}",
                LoggerError::FileLogWrite(std::io::Error::new(ErrorKind::Interrupted, "write"))
            ).contains("FileLogWrite")
        );
        assert_eq!(
            format!(
                "{}",
                LoggerError::FileLogWrite(std::io::Error::new(ErrorKind::Interrupted, "write"))
            ),
            "Failed to write to log file. Error: write"
        );

        assert!(
            format!(
                "{:?}",
                LoggerError::FileLogFlush(std::io::Error::new(ErrorKind::Interrupted, "flush"))
            ).contains("FileLogFlush")
        );
        assert_eq!(
            format!(
                "{}",
                LoggerError::FileLogFlush(std::io::Error::new(ErrorKind::Interrupted, "flush"))
            ),
            "Failed to flush log file. Error: flush"
        );

        assert!(
            format!(
                "{:?}",
                LoggerError::MutexLockFailure(String::from("Mutex lock"))
            ).contains("MutexLockFailure")
        );
        assert_eq!(
            format!(
                "{}",
                LoggerError::MutexLockFailure(String::from("Mutex lock"))
            ),
            "Mutex lock"
        );

        assert!(
            format!(
                "{:?}",
                LoggerError::LogMetricFailure("Failure in the logging of the metrics.".to_string())
            ).contains("LogMetricFailure")
        );
        assert_eq!(
            format!(
                "{}",
                LoggerError::LogMetricFailure("Failure in the logging of the metrics.".to_string())
            ),
            "Failure in the logging of the metrics."
        );

        assert!(format!("{:?}", LoggerError::LogMetricRateLimit).contains("LogMetricRateLimit"));
        assert_eq!(
            format!("{}", LoggerError::LogMetricRateLimit),
            "Metric will not yet be logged."
        );
    }
}
