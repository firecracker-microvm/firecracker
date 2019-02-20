// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![deny(missing_docs)]
//! Utility for sending log related messages and metrics to two different named pipes (FIFO) or
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
//! In this mode the logger can write both messages and metrics to pipes.
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
//! ## Example for logging to FIFOs
//!
//! ```
//! extern crate libc;
//! extern crate tempfile;
//!
//! use self::tempfile::NamedTempFile;
//! use std::ops::Deref;
//!
//! #[macro_use]
//! extern crate logger;
//! use logger::{AppInfo, LOGGER};
//!
//! fn main() {
//!     let log_file_temp =
//!            NamedTempFile::new().expect("Failed to create temporary output logging file.");
//!     let metrics_file_temp =
//!            NamedTempFile::new().expect("Failed to create temporary metrics logging file.");
//!     let logs = String::from(log_file_temp.path().to_path_buf().to_str().unwrap());
//!     let metrics = String::from(metrics_file_temp.path().to_path_buf().to_str().unwrap());
//!
//!     unsafe {
//!          libc::mkfifo(logs.as_bytes().as_ptr() as *const i8, 0o644);
//!      }
//!     unsafe {
//!          libc::mkfifo(metrics.as_bytes().as_ptr() as *const i8, 0o644);
//!     }
//!     // Initialize the logger to log to a FIFO that was created beforehand.
//!     assert!(LOGGER.deref().init(
//!                 &AppInfo::new("Firecracker", "1.0"),
//!                 "MY-INSTANCE",
//!                 logs,
//!                 metrics,
//!                 &vec![]
//!             ).is_ok());
//!     // The following messages should appear in the `log_file_temp` file.
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
//! In order to not block the instance if nobody is consuming the logs that are flushed to the two
//! pipes, we are opening them with `O_NONBLOCK` flag. In this case, writing to a pipe will
//! start failing when reaching 64K of unconsumed content. Simultaneously, the `missed_metrics_count`
//! metric will get increased.
//! Metrics are only logged to pipes. Logs can be flushed either to stdout/stderr or to a pipe.

extern crate chrono;
// workaround to macro_reexport
#[macro_use]
extern crate lazy_static;
extern crate libc;
extern crate log;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate time;

pub mod error;
pub mod metrics;
mod writers;

use std::error::Error;
use std::ops::Deref;
use std::result;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering, ATOMIC_USIZE_INIT};
use std::sync::{Mutex, MutexGuard, RwLock};

use chrono::Local;
use serde_json::Value;

use error::LoggerError;
pub use log::Level::*;
pub use log::*;
use log::{set_logger, set_max_level, Log, Metadata, Record};
pub use metrics::{Metric, METRICS};
use writers::*;

/// Type for returning functions outcome.
///
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

static STATE: AtomicUsize = ATOMIC_USIZE_INIT;

// Time format
const TIME_FMT: &str = "%Y-%m-%dT%H:%M:%S.%f";

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

// Output sources for the log subsystem.
#[derive(PartialEq, Clone, Copy)]
#[repr(usize)]
enum Destination {
    Stderr,
    Stdout,
    Pipe,
}

/// Enum representing logging options that can be activated from the API.
///
#[derive(PartialEq)]
#[repr(usize)]
pub enum LogOption {
    /// Enable KVM dirty page tracking and a metric that counts dirty pages.
    LogDirtyPages = 1,
}

impl FromStr for LogOption {
    type Err = LoggerError;

    fn from_str(s: &str) -> Result<LogOption> {
        match s {
            "LogDirtyPages" => Ok(LogOption::LogDirtyPages),
            _ => Err(LoggerError::InvalidLogOption(s.to_string())),
        }
    }
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
    /// * `name` - App name.
    /// * `version` - App version.
    pub fn new(name: &str, version: &str) -> AppInfo {
        AppInfo {
            name: name.to_string(),
            version: version.to_string(),
        }
    }
}

// Each log level also has a code and a destination output associated with it.
struct LevelInfo {
    // Numeric representation of the chosen log level.
    code: AtomicUsize,
    // Numeric representation of the chosen log destination.
    writer: AtomicUsize,
}

impl LevelInfo {
    fn code(&self) -> usize {
        self.code.load(Ordering::Relaxed)
    }

    fn set_code(&self, level: Level) {
        self.code.store(level as usize, Ordering::Relaxed)
    }

    fn writer(&self) -> usize {
        self.writer.load(Ordering::Relaxed)
    }

    fn set_writer(&self, destination: Destination) {
        self.writer.store(destination as usize, Ordering::Relaxed)
    }
}

/// Logger representing the logging subsystem.
///
// All member fields have types which are Sync, and exhibit interior mutability, so
// we can call logging operations using a non-mut static global variable.
pub struct Logger {
    show_level: AtomicBool,
    show_file_path: AtomicBool,
    show_line_numbers: AtomicBool,
    level_info: LevelInfo,
    // Used in case we want to send logs to a FIFO.
    log_fifo: Mutex<Option<PipeLogWriter>>,
    // Used in case we want to send metrics to a FIFO.
    metrics_fifo: Mutex<Option<PipeLogWriter>>,
    instance_id: RwLock<String>,
    flags: AtomicUsize,
}

// Auxiliary function to get the default destination for some code level.
fn get_default_destination(level: Level) -> Destination {
    match level {
        Level::Error => Destination::Stderr,
        Level::Warn => Destination::Stderr,
        Level::Info => Destination::Stdout,
        Level::Debug => Destination::Stdout,
        Level::Trace => Destination::Stdout,
    }
}

// Auxiliary function to flush a message to a PipeLogWriter.
// This is used by the internal logger to either flush human-readable logs or metrics.
fn log_to_fifo(mut msg: String, fifo_writer: &mut PipeLogWriter) -> Result<()> {
    msg = format!("{}\n", msg);
    fifo_writer.write(&msg)?;
    // No need to call flush here since the write will handle the flush on its own given that
    // our messages always has a newline.
    Ok(())
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
            level_info: LevelInfo {
                // DEFAULT_LEVEL is warn so the destination output is stderr.
                code: AtomicUsize::new(DEFAULT_LEVEL as usize),
                writer: AtomicUsize::new(Destination::Stderr as usize),
            },
            log_fifo: Mutex::new(None),
            metrics_fifo: Mutex::new(None),
            instance_id: RwLock::new(String::new()),
            flags: AtomicUsize::new(0),
        }
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

    /// Explicitly sets the log level for the Logger.
    /// User needs to say the level code(error, warn...) and the output destination will be
    /// updated if and only if the logger was not initialized to log to a FIFO.
    /// The default level is WARN. So, ERROR and WARN statements will be shown (i.e. all that is
    /// bigger than the level code).
    /// If level is decreased at INFO, ERROR, WARN and INFO statements will be outputted, etc.
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
    /// 2018-11-07T05:34:25.180751152 [MY-INSTANCE:INFO:logger/src/lib.rs:353] An informational log
    /// message
    /// ```
    pub fn set_level(&self, level: Level) {
        self.level_info.set_code(level);
        if self.level_info.writer() != Destination::Pipe as usize {
            self.level_info.set_writer(get_default_destination(level));
        }
    }

    /// Returns the configured flags for the logger.
    ///
    pub fn flags(&self) -> usize {
        self.flags.load(Ordering::Relaxed)
    }

    /// Creates the first portion (to the left of the separator)
    /// of the log statement based on the logger settings.
    ///
    fn create_prefix(&self, record: &Record) -> String {
        let mut res = String::from(" [");

        {
            // It's safe to unwrap here, because `instance_id` is only written to
            // during log initialization, so there aren't any writers that could
            // poison the lock.
            let id_guard = self
                .instance_id
                .read()
                .expect("Failed to read instance ID due to poisoned lock");
            res.push_str(id_guard.as_ref());
        }

        if self.show_level() {
            res.push_str(IN_PREFIX_SEPARATOR);
            res.push_str(record.level().to_string().as_str());
        }

        if self.show_file_path() {
            let pth = record.file().unwrap_or("unknown");
            res.push_str(IN_PREFIX_SEPARATOR);
            res.push_str(pth);
        }

        if self.show_line_numbers() {
            if let Some(ln) = record.line() {
                res.push_str(IN_PREFIX_SEPARATOR);
                res.push_str(ln.to_string().as_ref());
            }
        }

        res.push_str("]");
        res
    }

    fn log_fifo_guard(&self) -> MutexGuard<Option<PipeLogWriter>> {
        match self.log_fifo.lock() {
            Ok(guard) => guard,
            // If a thread panics while holding this lock, the writer within should still be usable.
            // (we might get an incomplete log line or something like that).
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn metrics_fifo_guard(&self) -> MutexGuard<Option<PipeLogWriter>> {
        match self.metrics_fifo.lock() {
            Ok(guard) => guard,
            // If a thread panics while holding this lock, the writer within should still be usable.
            // (we might get an incomplete log line or something like that).
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn set_flags(options: &Vec<Value>) -> Result<()> {
        let mut flags = 0;
        for option in options.iter() {
            if let Value::String(s_opt) = option {
                flags |= LogOption::from_str(s_opt.as_str())
                    .map_err(|_| LoggerError::InvalidLogOption(s_opt.clone()))?
                    as usize;
            } else {
                return Err(LoggerError::InvalidLogOption(format!("{:?}", option)));
            }
        }
        LOGGER.flags.store(flags, Ordering::SeqCst);
        Ok(())
    }

    /// Try to change the state of the logger.
    /// This method will succeed only if the logger is UNINITIALIZED.
    ///
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
    /// Any calls made after the initialization will result in Err()
    /// appropriately (read description of error's enum items).
    ///
    /// # Arguments
    ///
    /// * `instance_id` - Unique string identifying this logger session. This id is temporary and will be overwritten upon initialization.
    ///
    /// # Example
    ///
    /// ```
    /// extern crate logger;
    /// use logger::LOGGER;
    /// use std::ops::Deref;
    ///
    /// fn main() {
    ///     LOGGER.deref().preinit(Some("MY-INSTANCE".to_string())).unwrap();
    /// }
    /// ```
    pub fn preinit(&self, instance_id: Option<String>) -> Result<()> {
        self.try_lock(PREINITIALIZING)?;

        if let Some(some_instance_id) = instance_id {
            // Use a block in order to avoid poisoning the lock in case of an unrelated error.
            {
                let mut id_guard = self
                    .instance_id
                    .write()
                    .expect("Failed to set instance ID due to poisoned lock");
                *id_guard = some_instance_id.to_string();
            }
        }

        set_max_level(Level::Trace.to_level_filter());

        STATE.store(UNINITIALIZED, Ordering::SeqCst);

        Ok(())
    }

    /// Initialize log system (once and only once).
    /// Every call made after the first will have no effect besides return `Ok` or `Err`
    /// appropriately (read description of error's enum items).
    ///
    /// # Arguments
    ///
    /// * `app_info` - Info about the app that uses the logger.
    /// * `instance_id` - Unique string identifying this logger session.
    /// * `log_pipe` - Path to a FIFO used for logging plain text.
    /// * `metrics_pipe` - Path to a FIFO used for logging JSON formatted metrics.
    /// * `options` - Logger options
    ///
    /// # Example
    ///
    /// ```
    /// extern crate logger;
    /// use logger::{AppInfo, LOGGER};
    /// use std::ops::Deref;
    ///
    /// fn main() {
    ///     LOGGER.deref().init(
    ///         &AppInfo::new("Firecracker", "1.0"),
    ///         "MY-INSTANCE",
    ///         "/tmp/log".to_string(),
    ///         "/tmp/metrics".to_string(),
    ///         &vec![]
    ///     );
    /// }
    /// ```
    pub fn init(
        &self,
        app_info: &AppInfo,
        instance_id: &str,
        log_pipe: String,
        metrics_pipe: String,
        options: &Vec<Value>,
    ) -> Result<()> {
        self.try_lock(INITIALIZING)?;

        // Use a block in order to avoid poisoning the lock in case of an unrelated error.
        {
            let mut id_guard = self
                .instance_id
                .write()
                .expect("Failed to set instance ID due to poisoned lock");
            *id_guard = instance_id.to_string();
        }

        match PipeLogWriter::new(&log_pipe) {
            Ok(t) => {
                // The mutex shouldn't be poisoned before init otherwise panic!.
                let mut g = LOGGER.log_fifo_guard();
                *g = Some(t);
            }
            Err(ref e) => {
                STATE.store(UNINITIALIZED, Ordering::SeqCst);
                return Err(LoggerError::NeverInitialized(format!(
                    "Could not open logging fifo: {}",
                    e
                )));
            }
        };

        match PipeLogWriter::new(&metrics_pipe) {
            Ok(t) => {
                // The mutex shouldn't be poisoned before init otherwise panic!.
                let mut g = LOGGER.metrics_fifo_guard();
                *g = Some(t);
            }
            Err(ref e) => {
                STATE.store(UNINITIALIZED, Ordering::SeqCst);
                return Err(LoggerError::NeverInitialized(format!(
                    "Could not open metrics fifo: {}",
                    e
                )));
            }
        };

        if let Err(e) = Logger::set_flags(options) {
            STATE.store(UNINITIALIZED, Ordering::SeqCst);
            return Err(LoggerError::NeverInitialized(format!(
                "Could not set option flags: {}",
                e
            )));
        }

        set_max_level(Level::Trace.to_level_filter());

        self.log_helper(
            format!("Running {} v{}", app_info.name, app_info.version),
            Some(Destination::Pipe),
        );
        LOGGER.level_info.set_writer(Destination::Pipe);
        STATE.store(INITIALIZED, Ordering::SeqCst);

        Ok(())
    }

    // In a future PR we'll update the way things are written to the selected destination to avoid
    // the creation and allocation of unnecessary intermediate Strings. The log_helper method takes
    // care of the common logic involved in both writing regular log messages, and dumping metrics.
    fn log_helper(&self, msg: String, maybe_forced_destination: Option<Destination>) {
        let destination = maybe_forced_destination
            .map(|forced_destination| forced_destination as usize)
            .unwrap_or(self.level_info.writer());

        // We have the awkward IF's for now because we can't use just "<enum_variant> as usize
        // on the left side of a match arm for some reason.
        match destination {
            x if x == Destination::Pipe as usize => {
                // Unwrap is safe cause the Destination is a Pipe.
                if let Err(_) = log_to_fifo(
                    msg,
                    self.log_fifo_guard()
                        .as_mut()
                        .expect("Failed to write to fifo due to poisoned lock"),
                ) {
                    // No reason to log the error to stderr here, just increment the metric.
                    METRICS.logger.missed_log_count.inc();
                }
            }
            x if x == Destination::Stderr as usize => {
                eprintln!("{}", msg);
            }
            x if x == Destination::Stdout as usize => {
                println!("{}", msg);
            }
            // This is hit on major program logic error.
            _ => panic!("Invalid logger.level_info.writer!"),
        }
    }

    /// Flushes metrics to the FIFO provided as argument upon initialization of the logger.
    ///
    pub fn log_metrics(&self) -> Result<()> {
        // Check that the logger is initialized.
        if STATE.load(Ordering::Relaxed) == INITIALIZED {
            match serde_json::to_string(METRICS.deref()) {
                Ok(msg) => {
                    // Check that the destination is indeed a FIFO.
                    if self.level_info.writer() == Destination::Pipe as usize {
                        log_to_fifo(
                            msg,
                            self.metrics_fifo_guard()
                                .as_mut()
                                .expect("Failed to write to fifo due to poisoned lock"),
                        )
                        .map_err(|e| {
                            METRICS.logger.missed_metrics_count.inc();
                            e
                        })?;
                    }
                    // We are not logging metrics if the Destination is not a PIPE.
                    Ok(())
                }
                Err(e) => {
                    METRICS.logger.metrics_fails.inc();
                    return Err(LoggerError::LogMetricFailure(e.description().to_string()));
                }
            }
        } else {
            METRICS.logger.metrics_fails.inc();
            return Err(LoggerError::LogMetricFailure(
                "Logger was not initialized.".to_string(),
            ));
        }
    }
}

/// Implements the "Log" trait from the externally used "log" crate.
///
impl Log for Logger {
    // Test whether the level of the log line should be outputted or not based on the currently
    // configured level. If the configured level is "warning" but the line is logged through "info!"
    // marco then it will not get logged.
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() as usize <= self.level_info.code()
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let msg = format!(
                "{}{}{}{}",
                Local::now().format(TIME_FMT),
                self.create_prefix(&record),
                MSG_SEPARATOR,
                record.args()
            );

            self.log_helper(msg, None);
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
        assert_eq!(l.level_info.code(), log::Level::Warn as usize);
        assert_eq!(l.level_info.writer(), Destination::Stderr as usize);
        assert_eq!(l.show_line_numbers(), true);
        assert_eq!(l.show_level(), true);
        assert_eq!(l.flags.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_init() {
        let app_info = AppInfo::new(TEST_APP_NAME, TEST_APP_VERSION);

        let log_file_temp =
            NamedTempFile::new().expect("Failed to create temporary output logging file.");
        let log_file = String::from(log_file_temp.path().to_path_buf().to_str().unwrap());

        let metrics_file_temp =
            NamedTempFile::new().expect("Failed to create temporary metrics logging file.");
        let metrics_file = String::from(metrics_file_temp.path().to_path_buf().to_str().unwrap());

        let l = LOGGER.deref();

        l.set_include_origin(false, true);
        assert_eq!(l.show_line_numbers(), false);

        l.set_include_origin(true, true);
        l.set_include_level(true);
        l.set_level(log::Level::Info);
        assert_eq!(l.show_line_numbers(), true);
        assert_eq!(l.show_file_path(), true);
        assert_eq!(l.show_level(), true);

        assert!(l.log_metrics().is_err());

        // Assert that initialization with invalid options is not allowed.
        assert_eq!(
            format!(
                "{:?}",
                l.init(&app_info, TEST_INSTANCE_ID, log_file.clone(), metrics_file.clone(), &vec![Value::Bool(true)])
                    .err()
            ),
            "Some(NeverInitialized(\"Could not set option flags: Invalid log option: Bool(true)\"))"
        );
        assert_eq!(
            format!(
                "{:?}",
                l.init(
                    &app_info,
                    TEST_INSTANCE_ID,
                    log_file.clone(),
                    metrics_file.clone(),
                    &vec![Value::String("foobar".to_string())]
                )
                .err()
            ),
            "Some(NeverInitialized(\"Could not set option flags: Invalid log option: foobar\"))"
        );

        // Assert that metrics cannot be flushed to stdout/stderr.
        assert!(l.log_metrics().is_err());

        // Assert that preinitialization works any number of times.
        assert!(l.preinit(Some(TEST_INSTANCE_ID.to_string())).is_ok());
        assert!(l.preinit(None).is_ok());
        assert!(l.preinit(Some(TEST_INSTANCE_ID.to_string())).is_ok());

        info!("info");
        warn!("warning");
        error!("error");

        // Assert that initialization works only once.
        assert!(l
            .init(
                &app_info,
                TEST_INSTANCE_ID,
                log_file.clone(),
                metrics_file.clone(),
                &vec![Value::String("LogDirtyPages".to_string())]
            )
            .is_ok());

        info!("info");
        warn!("warning");

        assert!(l
            .init(
                &app_info,
                TEST_INSTANCE_ID,
                log_file.clone(),
                metrics_file.clone(),
                &vec![]
            )
            .is_err());

        info!("info");
        warn!("warning");
        error!("error");

        l.flush();

        // Here we also test that the last initialization had no effect given that the
        // logging system can only be initialized with pipes once per program.
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
        let log_file_temp =
            NamedTempFile::new().expect("Failed to create temporary output logging file.");
        let log_file = String::from(log_file_temp.path().to_path_buf().to_str().unwrap());

        // Exercise the case when there is an error in opening file.
        STATE.store(UNINITIALIZED, Ordering::SeqCst);
        assert!(l
            .init(
                &app_info,
                TEST_INSTANCE_ID,
                String::from(""),
                metrics_file.clone(),
                &vec![]
            )
            .is_err());

        let res = l.init(
            &app_info,
            TEST_INSTANCE_ID,
            log_file.clone(),
            String::from(""),
            &vec![],
        );
        assert!(res.is_err());

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

        STATE.store(INITIALIZED, Ordering::SeqCst);
        let l = Logger::new();

        assert_eq!(
            format!(
                "{:?}",
                l.init(
                    &app_info,
                    TEST_INSTANCE_ID,
                    log_file.clone(),
                    metrics_file.clone(),
                    &vec![]
                )
                .err()
            ),
            "Some(AlreadyInitialized)"
        );
    }

    #[test]
    fn test_get_default_destination() {
        assert!(get_default_destination(log::Level::Error) == Destination::Stderr);
        assert!(get_default_destination(log::Level::Warn) == Destination::Stderr);
        assert!(get_default_destination(log::Level::Info) == Destination::Stdout);
        assert!(get_default_destination(log::Level::Debug) == Destination::Stdout);
        assert!(get_default_destination(log::Level::Trace) == Destination::Stdout);
    }
}
