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
    FileLogLock(String),
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
            LoggerError::FileLogLock(ref e) => format!("{}", e),
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
        assert!(format!("{:?}", LoggerError::AlreadyInitialized).contains("AlreadyInitialized"));
        assert!(
            format!(
                "{:?}",
                LoggerError::Poisoned(String::from("Never Initialized"))
            ).contains("Poisoned")
        );
        assert!(
            format!(
                "{:?}",
                LoggerError::FileLogWrite(std::io::Error::new(ErrorKind::Interrupted, "write"))
            ).contains("FileLogWrite")
        );
        assert!(
            format!(
                "{:?}",
                LoggerError::FileLogFlush(std::io::Error::new(ErrorKind::Interrupted, "flush"))
            ).contains("FileLogFlush")
        );
        assert!(
            format!(
                "{:?}",
                LoggerError::FileLogLock(String::from("File log lock"))
            ).contains("FileLogLock")
        );
    }
}
