// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![deny(missing_docs)]
//! Utility for sending log related messages and metrics to two different storing destinations or
//! simply to stdout/stderr. The logging destination is specified upon the initialization of the
//! logging system.
//!
//! # Enabling logging
//! There are 2 ways to enable the logging functionality:
//!
//! 1) Calling `LOGGER.preinit()`. This will enable the logger to work in limited mode.
//! In this mode the logger can only write messages to stdout or stderr.
//! The logger can be preinitialized any number of times before calling `LOGGER.init()`.
//!
//! 2) Calling `LOGGER.init()`. This will enable the logger to work in full mode.
//! In this mode the logger can write both messages and metrics to arbitrary buffers.
//! The logger can be initialized only once. Any call to the `LOGGER.init()` following that will
//! fail with an explicit error.
//!
//! ## Example for logging to stdout/stderr
//!
//! ```
//! #[macro_use]
//! extern crate logger;
//! use logger::{AppInfo, LOGGER};
//! use std::ops::Deref;
//!
//! fn main() {
//!     // Optionally preinitialize the logger.
//!     if let Err(e) = LOGGER.deref().preinit(Some("MY-INSTANCE".to_string())) {
//!         println!("Could not preinitialize the log subsystem: {}", e);
//!         return;
//!     }
//!     warn!("this is a warning");
//!     error!("this is an error");
//! }
//! ```
//! ## Example for logging to a `File`:
//!
//! ```
//! extern crate libc;
//! extern crate tempfile;
//!
//! use libc::c_char;
//! use std::io::Cursor;
//!
//! #[macro_use]
//! extern crate logger;
//! use logger::{AppInfo, LOGGER};
//!
//! fn main() {
//!     let mut logs = Cursor::new(vec![0; 15]);
//!     let mut metrics = Cursor::new(vec![0; 15]);
//!
//!     // Initialize the logger to log to a FIFO that was created beforehand.
//!     assert!(LOGGER
//!         .init(
//!             &AppInfo::new("Firecracker", "1.0"),
//!             Box::new(logs),
//!             Box::new(metrics),
//!         )
//!         .is_ok());
//!     // The following messages should appear in the in-memory buffer `logs`.
//!     warn!("this is a warning");
//!     error!("this is an error");
//! }
//! ```

//! # Plain log format
//! The current logging system is built upon the upstream crate 'log' and reexports the macros
//! provided by it for flushing plain log content. Log messages are printed through the use of five
//! macros:
//! * error!(<string>)
//! * warning!(<string>)
//! * info!(<string>)
//! * debug!(<string>)
//! * trace!(<string>)
//!
//! Each call to the desired macro will flush a line of the following format:
//! ```<timestamp> [<instance_id>:<level>:<file path>:<line number>] <log content>```.
//! The first component is always the timestamp which has the `%Y-%m-%dT%H:%M:%S.%f` format.
//! The level will depend on the macro used to flush a line and will be one of the following:
//! `ERROR`, `WARN`, `INFO`, `DEBUG`, `TRACE`.
//! The file path and the line provides the exact location of where the call to the macro was made.
//! ## Example of a log line:
//! ```bash
//! 2018-11-07T05:34:25.180751152 [anonymous-instance:ERROR:vmm/src/lib.rs:1173] Failed to log
//! metrics: Failed to write logs. Error: operation would block
//! ```
//!
//! # Metrics format
//! The metrics are flushed in JSON format each 60 seconds. The first field will always be the
//! timestamp followed by the JSON representation of the structures representing each component on
//! which we are capturing specific metrics.
//!
//! ## JSON example with metrics:
//! ```bash
//! {
//!  "utc_timestamp_ms": 1541591155180,
//!  "api_server": {
//!    "process_startup_time_us": 0,
//!    "process_startup_time_cpu_us": 0
//!  },
//!  "block": {
//!    "activate_fails": 0,
//!    "cfg_fails": 0,
//!    "event_fails": 0,
//!    "flush_count": 0,
//!    "queue_event_count": 0,
//!    "read_count": 0,
//!    "write_count": 0
//!  }
//! }
//! ```
//! The example above means that inside the structure representing all the metrics there is a field
//! named `block` which is in turn a serializable child structure collecting metrics for
//! the block device such as `activate_fails`, `cfg_fails`, etc.
//!
//! # Limitations
//! Metrics are only logged to buffers. Logs can be flushed either to stdout/stderr or to a
//! byte-oriented sink (File, FIFO, Ring Buffer etc).

// Workaround to `macro_reexport`.
#[macro_use]
extern crate lazy_static;
extern crate libc;
extern crate log;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate utils;

pub mod error;
pub mod metrics;

use std::error::Error;
use std::io::Write;
use std::ops::Deref;
use std::result;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, RwLock};

use error::LoggerError;
pub use log::Level::*;
pub use log::*;
use log::{set_logger, set_max_level, Log, Metadata, Record};
pub use metrics::{Metric, METRICS};
use utils::time::LocalTime;

/// Type for returning functions outcome.
pub type Result<T> = result::Result<T, LoggerError>;

// Values used by the Logger.
const IN_PREFIX_SEPARATOR: &str = ":";
const MSG_SEPARATOR: &str = " ";
const DEFAULT_LEVEL: Level = Level::Warn;

// Synchronization primitives used to run a one-time global initialization.
const UNINITIALIZED: usize = 0;
const PREINITIALIZING: usize = 1;
const INITIALIZING: usize = 2;
const INITIALIZED: usize = 3;

static STATE: AtomicUsize = AtomicUsize::new(0);

lazy_static! {
    static ref _LOGGER_INNER: Logger = Logger::new();
}

lazy_static! {
    /// Static instance used for handling human-readable logs.
    ///
    pub static ref LOGGER: &'static Logger = {
        set_logger(_LOGGER_INNER.deref()).expect("Failed to set logger");
        _LOGGER_INNER.deref()
    };
}

/// Enum representing logging options that can be activated from the API.
#[repr(usize)]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum LogOption {
    /// Enable KVM dirty page tracking and a metric that counts dirty pages.
    LogDirtyPages = 1,
}

/// A structure containing info about the App that uses the logger.
pub struct AppInfo {
    name: String,
    version: String,
}

impl AppInfo {
    /// Creates a new instance of AppInfo.
    /// # Arguments
    ///
    /// * `name` - Name of the application using this logger.
    /// * `version` - Version of the application using this logger.
    pub fn new(name: &str, version: &str) -> AppInfo {
        AppInfo {
            name: name.to_string(),
            version: version.to_string(),
        }
    }
}

/// Logger representing the logging subsystem.
// All member fields have types which are Sync, and exhibit interior mutability, so
// we can call logging operations using a non-mut static global variable.
pub struct Logger {
    show_level: AtomicBool,
    show_file_path: AtomicBool,
    show_line_numbers: AtomicBool,
    level: AtomicUsize,
    // Human readable logs will be outputted here.
    log_buf: Mutex<Option<Box<dyn Write + Send>>>,
    // Metrics will get flushed here.
    metrics_buf: Mutex<Option<Box<dyn Write + Send>>>,
    instance_id: RwLock<String>,
    flags: AtomicUsize,
}

// Auxiliary function to flush a message to a entity implementing `Write` and `Send` traits.
// This is used by the internal logger to either flush human-readable logs or metrics.
fn write_to_destination(mut msg: String, buffer: &mut (dyn Write + Send)) -> Result<()> {
    msg = format!("{}\n", msg);
    buffer
        .write(&msg.as_bytes())
        .map_err(LoggerError::LogWrite)?;
    buffer.flush().map_err(LoggerError::LogFlush)
}

impl Logger {
    // Creates a new instance of the current logger.
    //
    // The default log level is `WARN` and the default destination is stdout/stderr based on level.
    fn new() -> Logger {
        Logger {
            show_level: AtomicBool::new(true),
            show_line_numbers: AtomicBool::new(true),
            show_file_path: AtomicBool::new(true),
            level:
                // DEFAULT_LEVEL is warn so the destination output is stderr.
                AtomicUsize::new(DEFAULT_LEVEL as usize),
            log_buf: Mutex::new(None),
            metrics_buf: Mutex::new(None),
            instance_id: RwLock::new(String::new()),
            flags: AtomicUsize::new(0),
        }
    }

    /// Returns the configured flags for the logger.
    pub fn flags(&self) -> usize {
        self.flags.load(Ordering::Relaxed)
    }

    fn show_level(&self) -> bool {
        self.show_level.load(Ordering::Relaxed)
    }

    fn show_file_path(&self) -> bool {
        self.show_file_path.load(Ordering::Relaxed)
    }

    fn show_line_numbers(&self) -> bool {
        self.show_line_numbers.load(Ordering::Relaxed)
    }

    /// Configure flags for the logger.
    pub fn set_flags(&self, options: &[LogOption]) -> Result<()> {
        let mut flags = 0;
        for option in options.iter() {
            flags |= option.clone() as usize;
        }
        self.flags.store(flags, Ordering::SeqCst);
        Ok(())
    }

    /// Enables or disables including the level in the log message's tag portion.
    ///
    /// # Arguments
    ///
    /// * `option` - Boolean deciding whether to include log level in log message.
    ///
    /// # Example
    ///
    /// ```
    /// #[macro_use]
    /// extern crate log;
    /// extern crate logger;
    /// use logger::LOGGER;
    /// use std::ops::Deref;
    ///
    /// fn main() {
    ///     let l = LOGGER.deref();
    ///     l.set_include_level(true);
    ///     assert!(l.preinit(Some("MY-INSTANCE".to_string())).is_ok());
    ///     warn!("A warning log message with level included");
    /// }
    /// ```
    /// The code above will more or less print:
    /// ```bash
    /// 2018-11-07T05:34:25.180751152 [MY-INSTANCE:WARN:logger/src/lib.rs:290] A warning log
    /// message with level included
    /// ```
    pub fn set_include_level(&self, option: bool) {
        self.show_level.store(option, Ordering::Relaxed);
    }

    /// Enables or disables including the file path and the line numbers in the tag of
    /// the log message. Not including the file path will also hide the line numbers from the tag.
    ///
    /// # Arguments
    ///
    /// * `file_path` - Boolean deciding whether to include file path of the log message's origin.
    /// * `line_numbers` - Boolean deciding whether to include the line number of the file where the
    /// log message orginated.
    ///
    /// # Example
    ///
    /// ```
    /// #[macro_use]
    /// extern crate logger;
    /// use logger::LOGGER;
    /// use std::ops::Deref;
    ///
    /// fn main() {
    ///     let l = LOGGER.deref();
    ///     l.set_include_origin(false, false);
    ///     assert!(l.preinit(Some("MY-INSTANCE".to_string())).is_ok());
    ///
    ///     warn!("A warning log message with log origin disabled");
    /// }
    /// ```
    /// The code above will more or less print:
    /// ```bash
    /// 2018-11-07T05:34:25.180751152 [MY-INSTANCE:WARN] A warning log message with log origin
    /// disabled
    /// ```
    pub fn set_include_origin(&self, file_path: bool, line_numbers: bool) {
        self.show_file_path.store(file_path, Ordering::Relaxed);
        // If the file path is not shown, do not show line numbers either.
        self.show_line_numbers
            .store(file_path && line_numbers, Ordering::Relaxed);
    }

    /// Sets the ID for this logger session.
    pub fn set_instance_id(&self, instance_id: String) {
        let mut id_guard = match self.instance_id.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *id_guard = instance_id;
    }

    /// Explicitly sets the log level for the Logger.
    /// The default level is WARN. So, ERROR and WARN statements will be shown (i.e. all that is
    /// bigger than the level code).
    ///
    /// # Arguments
    ///
    /// * `level` - Set the highest log level.
    /// # Example
    ///
    /// ```
    /// #[macro_use]
    /// extern crate logger;
    /// extern crate log;
    /// use logger::LOGGER;
    /// use std::ops::Deref;
    ///
    /// fn main() {
    ///     let l = LOGGER.deref();
    ///     l.set_level(log::Level::Info);
    ///     assert!(l.preinit(Some("MY-INSTANCE".to_string())).is_ok());
    ///     info!("An informational log message");
    /// }
    /// ```
    /// The code above will more or less print:
    /// ```bash
    /// 2018-11-07T05:34:25.180751152 [MY-INSTANCE:INFO:logger/src/lib.rs:389] An informational log
    /// message
    /// ```
    pub fn set_level(&self, level: Level) {
        self.level.store(level as usize, Ordering::Relaxed);
    }

    /// Creates the first portion (to the left of the separator)
    /// of the log statement based on the logger settings.
    fn create_prefix(&self, record: &Record) -> String {
        let ins_id = match self.instance_id.read() {
            Ok(guard) => guard.to_string(),
            Err(poisoned) => poisoned.into_inner().to_string(),
        };

        let level = if self.show_level() {
            record.level().to_string()
        } else {
            "".to_string()
        };

        let pth = if self.show_file_path() {
            record.file().unwrap_or("unknown").to_string()
        } else {
            "".to_string()
        };

        let line = if self.show_line_numbers() {
            if let Some(ln) = record.line() {
                ln.to_string()
            } else {
                "".to_string()
            }
        } else {
            "".to_string()
        };

        let mut prefix: Vec<String> = vec![ins_id, level, pth, line];
        prefix.retain(|i| !i.is_empty());
        format!(" [{}]", prefix.join(IN_PREFIX_SEPARATOR))
    }

    fn log_buf_guard(&self) -> MutexGuard<Option<Box<dyn Write + Send>>> {
        match self.log_buf.lock() {
            Ok(guard) => guard,
            // If a thread panics while holding this lock, the writer within should still be usable.
            // (we might get an incomplete log line or something like that).
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn metrics_buf_guard(&self) -> MutexGuard<Option<Box<dyn Write + Send>>> {
        match self.metrics_buf.lock() {
            Ok(guard) => guard,
            // If a thread panics while holding this lock, the writer within should still be usable.
            // (we might get an incomplete log line or something like that).
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Try to change the state of the logger.
    /// This method will succeed only if the logger is UNINITIALIZED.
    fn try_lock(&self, locked_state: usize) -> Result<()> {
        match STATE.compare_and_swap(UNINITIALIZED, locked_state, Ordering::SeqCst) {
            PREINITIALIZING => {
                // If the logger is preinitializing, an error will be returned.
                METRICS.logger.log_fails.inc();
                return Err(LoggerError::IsPreinitializing);
            }
            INITIALIZING => {
                // If the logger is initializing, an error will be returned.
                METRICS.logger.log_fails.inc();
                return Err(LoggerError::IsInitializing);
            }
            INITIALIZED => {
                // If the logger was already initialized, an error will be returned.
                METRICS.logger.log_fails.inc();
                return Err(LoggerError::AlreadyInitialized);
            }
            _ => {}
        }

        Ok(())
    }

    /// Preconfigure the logger prior to initialization.
    /// Performs the most basic steps in order to enable the logger to write to stdout or stderr
    /// even before calling LOGGER.init(). Calling this method is optional.
    /// This function can be called any number of times before the initialization.
    /// Any calls made after the initialization will result in `Err()`.
    ///
    /// # Arguments
    ///
    /// * `instance_id` - Unique string identifying this logger session.
    ///                   This id is temporary and will be overwritten upon initialization.
    ///
    /// # Example
    ///
    /// ```
    /// extern crate logger;
    /// use logger::LOGGER;
    /// use std::ops::Deref;
    ///
    /// fn main() {
    ///     LOGGER
    ///         .deref()
    ///         .preinit(Some("MY-INSTANCE".to_string()))
    ///         .unwrap();
    /// }
    /// ```
    pub fn preinit(&self, instance_id: Option<String>) -> Result<()> {
        self.try_lock(PREINITIALIZING)?;

        if let Some(some_instance_id) = instance_id {
            self.set_instance_id(some_instance_id);
        }

        set_max_level(Level::Trace.to_level_filter());

        STATE.store(UNINITIALIZED, Ordering::SeqCst);

        Ok(())
    }

    /// Initialize log system (once and only once).
    /// Every call made after the first will have no effect besides returning `Ok` or `Err`.
    ///
    /// # Arguments
    ///
    /// * `app_info` - Info about the app that uses the logger.
    /// * `instance_id` - Unique string identifying this logger session.
    /// * `log_dest` - Buffer for plain text logs. Needs to implements `Write` and `Send`.
    /// * `metrics_dest` - Buffer for JSON formatted metrics. Needs to implement `Write` and `Send`.
    /// * `options` - Logger options.
    ///
    /// # Example
    ///
    /// ```
    /// extern crate logger;
    /// use logger::{AppInfo, LOGGER};
    ///
    /// use std::io::Cursor;
    ///
    /// fn main() {
    ///     let mut logs = Cursor::new(vec![0; 15]);
    ///     let mut metrics = Cursor::new(vec![0; 15]);
    ///
    ///     LOGGER.init(
    ///         &AppInfo::new("Firecracker", "1.0"),
    ///         Box::new(logs),
    ///         Box::new(metrics),
    ///     );
    /// }
    /// ```
    pub fn init(
        &self,
        app_info: &AppInfo,
        log_dest: Box<dyn Write + Send>,
        metrics_dest: Box<dyn Write + Send>,
    ) -> Result<()> {
        self.try_lock(INITIALIZING)?;
        {
            let mut g = self.log_buf_guard();
            *g = Some(log_dest);
        }

        {
            let mut g = self.metrics_buf_guard();

            *g = Some(metrics_dest);
        }

        set_max_level(Level::Trace.to_level_filter());

        STATE.store(INITIALIZED, Ordering::SeqCst);
        self.log_helper(
            format!("Running {} v{}", app_info.name, app_info.version),
            Level::Info,
        );

        Ok(())
    }

    // In a future PR we'll update the way things are written to the selected destination to avoid
    // the creation and allocation of unnecessary intermediate Strings. The log_helper method takes
    // care of the common logic involved in both writing regular log messages, and dumping metrics.
    fn log_helper(&self, msg: String, msg_level: Level) {
        if STATE.load(Ordering::Relaxed) == INITIALIZED {
            if let Some(guard) = self.log_buf_guard().as_mut() {
                if write_to_destination(msg, guard).is_err() {
                    // No reason to log the error to stderr here, just increment the metric.
                    METRICS.logger.missed_log_count.inc();
                }
            } else {
                panic!("Failed to write to the provided metrics destination due to poisoned lock");
            }
        } else if msg_level <= Level::Warn {
            eprintln!("{}", msg);
        } else {
            println!("{}", msg);
        }
    }

    /// Flushes metrics to the destination provided as argument upon initialization of the logger.
    /// Upon failure, an error is returned if logger is initialized and metrics could not be flushed.
    /// Upon success, the function will return `True` (if logger was initialized and metrics were
    /// successfully flushed to disk) or `False` (if logger was not yet initialized).
    pub fn log_metrics(&self) -> Result<bool> {
        // Check that the logger is initialized.
        if STATE.load(Ordering::Relaxed) == INITIALIZED {
            match serde_json::to_string(METRICS.deref()) {
                Ok(msg) => {
                    if let Some(guard) = self.metrics_buf_guard().as_mut() {
                        write_to_destination(msg, guard)
                            .map_err(|e| {
                                METRICS.logger.missed_metrics_count.inc();
                                e
                            })
                            .map(|()| true)?;
                    } else {
                        panic!("Failed to write to the provided metrics destination due to poisoned lock");
                    }
                }
                Err(e) => {
                    METRICS.logger.metrics_fails.inc();
                    return Err(LoggerError::LogMetricFailure(e.description().to_string()));
                }
            }
        }
        // If the logger is not initialized, no error is thrown but we do let the user know that
        // metrics were not flushed.
        Ok(false)
    }
}

/// Implements the "Log" trait from the externally used "log" crate.
impl Log for Logger {
    // Test whether the level of the log line should be outputted or not based on the currently
    // configured level. If the configured level is "warning" but the line is logged through "info!"
    // marco then it will not get logged.
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() as usize <= self.level.load(Ordering::SeqCst)
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let msg = format!(
                "{}{}{}{}",
                LocalTime::now(),
                self.create_prefix(&record),
                MSG_SEPARATOR,
                record.args()
            );
            self.log_helper(msg, record.metadata().level());
        }
    }

    // This is currently not used.
    fn flush(&self) {}
}

#[cfg(test)]
mod tests {
    extern crate tempfile;
    use self::tempfile::NamedTempFile;
    use super::*;
    use log::MetadataBuilder;

    use std::fs::File;
    use std::io::BufRead;
    use std::io::BufReader;

    const TEST_INSTANCE_ID: &str = "TEST-INSTANCE-ID";
    const TEST_APP_NAME: &str = "Firecracker";
    const TEST_APP_VERSION: &str = "1.0";

    fn validate_logs(
        log_path: &str,
        expected: &[(&'static str, &'static str, &'static str, &'static str)],
    ) -> bool {
        let f = File::open(log_path).unwrap();
        let mut reader = BufReader::new(f);

        let mut line = String::new();
        // The first line should contain the firecracker version.
        reader.read_line(&mut line).unwrap();
        assert!(line.contains(TEST_APP_VERSION));
        for tuple in expected {
            line.clear();
            // Read an actual log line.
            reader.read_line(&mut line).unwrap();
            assert!(line.contains(&tuple.0));
            assert!(line.contains(&tuple.1));
            assert!(line.contains(&tuple.2));
        }
        false
    }

    #[test]
    fn test_default_values() {
        let l = Logger::new();
        assert_eq!(l.level.load(Ordering::Relaxed), log::Level::Warn as usize);
        assert_eq!(l.show_line_numbers(), true);
        assert_eq!(l.show_level(), true);
        assert_eq!(l.flags.load(Ordering::Relaxed), 0);
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_init() {
        let app_info = AppInfo::new(TEST_APP_NAME, TEST_APP_VERSION);
        let l = LOGGER.deref();

        l.set_include_origin(false, true);
        assert_eq!(l.show_line_numbers(), false);

        l.set_include_origin(true, true);
        l.set_include_level(true);
        l.set_level(log::Level::Info);
        assert_eq!(l.show_line_numbers(), true);
        assert_eq!(l.show_file_path(), true);
        assert_eq!(l.show_level(), true);

        // Trying to log metrics when logger is not initialized, should not throw error.
        let res = l.log_metrics();
        assert!(res.is_ok() && !res.unwrap());

        l.set_instance_id(TEST_INSTANCE_ID.to_string());

        // Test flag configuration.
        assert!(l.set_flags(&[]).is_ok());
        assert_eq!(l.flags(), 0);
        assert!(l.set_flags(&[LogOption::LogDirtyPages]).is_ok());
        assert_eq!(l.flags(), LogOption::LogDirtyPages as usize);

        // Assert that metrics cannot be flushed to stdout/stderr.
        let res = l.log_metrics();
        assert!(res.is_ok() && !res.unwrap());

        // Assert that preinitialization works any number of times.
        assert!(l.preinit(Some(TEST_INSTANCE_ID.to_string())).is_ok());
        assert!(l.preinit(None).is_ok());
        assert!(l.preinit(Some(TEST_INSTANCE_ID.to_string())).is_ok());

        info!("info");
        warn!("warning");
        error!("error");

        // Assert that initialization works only once.
        let log_file_temp =
            NamedTempFile::new().expect("Failed to create temporary output logging file.");
        let log_file = String::from(log_file_temp.path().to_path_buf().to_str().unwrap());
        let metrics_file_temp =
            NamedTempFile::new().expect("Failed to create temporary metrics logging file.");
        l.set_instance_id(TEST_INSTANCE_ID.to_string());
        assert!(l
            .init(
                &app_info,
                Box::new(log_file_temp),
                Box::new(metrics_file_temp),
            )
            .is_ok());

        info!("info");
        warn!("warning");

        assert!(l
            .init(
                &app_info,
                Box::new(NamedTempFile::new().unwrap()),
                Box::new(NamedTempFile::new().unwrap()),
            )
            .is_err());

        info!("info");
        warn!("warning");
        error!("error");

        // Here we also test that the last initialization had no effect given that the
        // logging system can only be initialized with byte-oriented sinks once per program.
        validate_logs(
            &log_file,
            &[
                (TEST_INSTANCE_ID, "INFO", "lib.rs", "info"),
                (TEST_INSTANCE_ID, "WARN", "lib.rs", "warn"),
                (TEST_INSTANCE_ID, "INFO", "lib.rs", "info"),
                (TEST_INSTANCE_ID, "WARN", "lib.rs", "warn"),
                (TEST_INSTANCE_ID, "ERROR", "lib.rs", "error"),
            ],
        );

        assert!(l.log_metrics().is_ok());

        STATE.store(UNINITIALIZED, Ordering::SeqCst);

        l.set_include_level(true);
        l.set_include_origin(false, false);
        let error_metadata = MetadataBuilder::new().level(Level::Error).build();
        let log_record = log::Record::builder().metadata(error_metadata).build();
        Logger::log(&l, &log_record);

        assert_eq!(l.show_level(), true);
        assert_eq!(l.show_file_path(), false);
        assert_eq!(l.show_line_numbers(), false);

        l.set_include_level(false);
        l.set_include_origin(true, true);
        let error_metadata = MetadataBuilder::new().level(Level::Info).build();
        let log_record = log::Record::builder().metadata(error_metadata).build();
        Logger::log(&l, &log_record);

        assert_eq!(l.show_level(), false);
        assert_eq!(l.show_file_path(), true);
        assert_eq!(l.show_line_numbers(), true);
    }
}
