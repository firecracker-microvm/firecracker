//! Errors returned by the logger.

use std;
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum LoggerError {
    /// First attempt at initialization failed.
    NeverInitialized(String),
    /// Initialization has previously failed and can not be retried.
    Poisoned(String),
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
            LoggerError::NeverInitialized(ref e) => e,
            LoggerError::Poisoned(ref e) => e,
            LoggerError::CreateLogFile(ref e) => e.description(),
            LoggerError::FileLogWrite(ref e) => e.description(),
            LoggerError::FileLogFlush(ref e) => e.description(),
            LoggerError::FileLogLock(ref e) => e,
        };
        write!(f, "{}", printable)
    }
}

