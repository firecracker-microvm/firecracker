//! Sends log messages and metrics to either stdout, stderr or two FIFOs specified upon init.
//!
//! Every function exported by this module is thread-safe.
//! Each function will silently fail until
//! `LOGGER.init()` is called and returns `Ok`.
//!
//! # Examples
//!
//! ```
//! #[macro_use]
//! extern crate logger;
//! use logger::LOGGER;
//! use std::ops::Deref;
//!
//! fn main() {
//!     if let Err(e) = LOGGER.deref().init("MY-INSTANCE", None, None) {
//!         println!("Could not initialize the log subsystem: {:?}", e);
//!         return;
//!     }
//!     warn!("this is a warning");
//!     error!("this is an error");
//! }
//! ```
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
mod metrics;
mod writers;

use std::error::Error;
use std::ops::Deref;
use std::result;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering, ATOMIC_USIZE_INIT};
use std::sync::{Mutex, MutexGuard, RwLock};

use chrono::Local;

use error::LoggerError;
pub use log::Level::*;
pub use log::*;
use log::{set_logger, set_max_level, Log, Metadata, Record};
pub use metrics::{Metric, METRICS};
use writers::*;

/// Type used by the Logger for returning functions outcome.
///
pub type Result<T> = result::Result<T, LoggerError>;

/// Values used by the Logger.
///
const IN_PREFIX_SEPARATOR: &str = ":";
const MSG_SEPARATOR: &str = " ";
const DEFAULT_LEVEL: Level = Level::Warn;

/// Synchronization primitives used to run a one-time global initialization.
///
const UNINITIALIZED: usize = 0;
const INITIALIZING: usize = 1;
const INITIALIZED: usize = 2;

static STATE: AtomicUsize = ATOMIC_USIZE_INIT;

/// Time format
const TIME_FMT: &str = "%Y-%m-%dT%H:%M:%S.%f";

lazy_static! {
    /// Static instance used for handling human-readable logs.
    ///
    pub static ref LOGGER: Logger = Logger::new();
}

/// Output sources for the log subsystem.
///
#[derive(PartialEq, Clone, Copy)]
#[repr(usize)]
enum Destination {
    Stderr,
    Stdout,
    Pipe,
}

/// Each log level also has a code and a destination output associated with it.
///
pub struct LevelInfo {
    // this represents the numeric representation of the chosen log::Level variant
    code: AtomicUsize,
    // this represents the numeric representation of the chosen Destination variant
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
}

/// Auxiliary function to get the default destination for some code level.
///
fn get_default_destination(level: Level) -> Destination {
    match level {
        Level::Error => Destination::Stderr,
        Level::Warn => Destination::Stderr,
        Level::Info => Destination::Stdout,
        Level::Debug => Destination::Stdout,
        Level::Trace => Destination::Stdout,
    }
}

/// Auxiliary function to flush a message to a PipeLogWriter.
/// This is used by the internal logger to either flush human-readable logs or metrics.
fn log_to_fifo(mut msg: String, fifo_writer: &mut PipeLogWriter) -> Result<()> {
    msg = format!("{}\n", msg);
    fifo_writer.write(&msg)?;
    // No need to call flush here since the write will handle the flush on its own given that
    // our messages always has a newline.
    Ok(())
}

impl Logger {
    /// Creates a new instance of the current logger.
    ///
    /// The default level is Warning.
    /// The default separator between the tag and the log message is " ".
    /// The default separator inside the tag is ":".
    /// The tag of the log message is the text to the left of the separator.
    ///
    pub fn new() -> Logger {
        Logger {
            show_level: AtomicBool::new(true),
            show_line_numbers: AtomicBool::new(true),
            show_file_path: AtomicBool::new(true),
            level_info: LevelInfo {
                // DEFAULT_LEVEL is warn so the destination output is stderr
                code: AtomicUsize::new(DEFAULT_LEVEL as usize),
                writer: AtomicUsize::new(Destination::Stderr as usize),
            },
            log_fifo: Mutex::new(None),
            metrics_fifo: Mutex::new(None),
            instance_id: RwLock::new(String::new()),
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
    ///     l.init("MY-INSTANCE", None, None).unwrap();
    ///
    ///     warn!("This will print 'WARN' surrounded by square brackets followed by log message");
    /// }
    /// ```
    pub fn set_include_level(&self, option: bool) {
        self.show_level.store(option, Ordering::Relaxed);
    }

    /// Enables or disables including the file path and the line numbers in the tag of
    /// the log message.
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
    ///     l.set_include_origin(true, true);
    ///     l.init("MY-INSTANCE", None, None).unwrap();
    ///
    ///     warn!("This will print '[WARN:file_path.rs:155]' followed by log message");
    /// }
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
    ///     l.init("MY-INSTANCE", None, None).unwrap();
    /// }
    /// ```
    pub fn set_level(&self, level: Level) {
        self.level_info.set_code(level);
        if self.level_info.writer() != Destination::Pipe as usize {
            self.level_info.set_writer(get_default_destination(level));
        }
    }

    /// Creates the first portion (to the left of the separator)
    /// of the log statement based on the logger settings.
    ///
    fn create_prefix(&self, record: &Record) -> String {
        let mut res = String::from(" [");

        {
            // It's safe to unrwap here, because instance_id is only written to
            // during log initialization, so there aren't any writers that could
            // poison the lock.
            let id_guard = self.instance_id.read().unwrap();
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

    /// Initialize log system (once and only once).
    /// Every call made after the first will have no effect besides return `Ok` or `Err`
    /// appropriately (read description of error's enum items).
    ///
    /// # Example
    ///
    /// ```
    /// extern crate logger;
    /// use logger::LOGGER;
    /// use std::ops::Deref;
    ///
    /// fn main() {
    ///     LOGGER.deref().init("MY-INSTANCE", None, None).unwrap();
    /// }
    /// ```
    pub fn init(
        &self,
        instance_id: &str,
        log_pipe: Option<String>,
        metrics_pipe: Option<String>,
    ) -> Result<()> {
        // If the logger was already initialized, error will be returned.
        if STATE.compare_and_swap(UNINITIALIZED, INITIALIZING, Ordering::SeqCst) != UNINITIALIZED {
            METRICS.logger.log_fails.inc();
            return Err(LoggerError::AlreadyInitialized);
        }

        {
            let mut id_guard = self.instance_id.write().unwrap();
            *id_guard = instance_id.to_string();
        }

        if let Some(path) = log_pipe.as_ref() {
            match PipeLogWriter::new(path) {
                Ok(t) => {
                    // The mutex shouldn't be poisoned before init otherwise panic!.
                    let mut g = LOGGER.log_fifo_guard();
                    *g = Some(t);
                    LOGGER.level_info.set_writer(Destination::Pipe);
                }
                Err(ref e) => {
                    STATE.store(UNINITIALIZED, Ordering::SeqCst);
                    return Err(LoggerError::NeverInitialized(format!(
                        "Could not open logging fifo: {}",
                        e
                    )));
                }
            };
        }

        if let Some(path) = metrics_pipe.as_ref() {
            match PipeLogWriter::new(path) {
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
        }
        set_max_level(Level::Trace.to_level_filter());

        if let Err(e) = set_logger(LOGGER.deref()) {
            STATE.store(UNINITIALIZED, Ordering::SeqCst);
            return Err(LoggerError::NeverInitialized(format!("{}", e)));
        }

        STATE.store(INITIALIZED, Ordering::SeqCst);
        Ok(())
    }

    // In a future PR we'll update the way things are written to the selected destination to avoid
    // the creation and allocation of unnecessary intermediate Strings. The log_helper method takes
    // care of the common logic involved in both writing regular log messages, and dumping metrics.
    fn log_helper(&self, msg: String) {
        // We have the awkward IF's for now because we can't use just "<enum_variant> as usize
        // on the left side of a match arm for some reason.
        match self.level_info.writer() {
            x if x == Destination::Pipe as usize => {
                // Unwrap is safe cause the Destination is a Pipe.
                if let Err(_) = log_to_fifo(msg, self.log_fifo_guard().as_mut().unwrap()) {
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
                        log_to_fifo(msg, self.metrics_fifo_guard().as_mut().unwrap()).map_err(
                            |e| {
                                METRICS.logger.missed_metrics_count.inc();
                                e
                            },
                        )?;
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
                "Failed to log metrics. Logger was not initialized.".to_string(),
            ));
        }
    }
}

/// Implements trait log from the externally used log crate.
///
impl Log for Logger {
    // Test whether a log level is enabled for the current module.
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

            self.log_helper(msg);
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

    fn validate_logs(
        log_path: &str,
        expected: &[(&'static str, &'static str, &'static str, &'static str)],
    ) -> bool {
        let f = File::open(log_path).unwrap();
        let mut reader = BufReader::new(f);

        let mut line = String::new();
        for tuple in expected {
            line.clear();
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
    }

    #[test]
    fn test_init_with_file() {
        const TEST_INSTANCE_ID: &str = "TEST-INSTANCE-ID";

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

        let log_file_temp =
            NamedTempFile::new().expect("Failed to create temporary output logging file.");
        let metrics_file_temp =
            NamedTempFile::new().expect("Failed to create temporary metrics logging file.");
        let log_file = String::from(log_file_temp.path().to_path_buf().to_str().unwrap());
        let metrics_file = String::from(metrics_file_temp.path().to_path_buf().to_str().unwrap());

        assert!(
            l.init(TEST_INSTANCE_ID, Some(log_file.clone()), Some(metrics_file))
                .is_ok()
        );

        info!("info");
        warn!("warning");

        assert!(l.init(TEST_INSTANCE_ID, None, None).is_err());

        info!("info");
        warn!("warning");
        error!("error");

        l.flush();

        // Here we also test that the second initialization had no effect given that the
        // logging system can only be initialized once per program.
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

        // Exercise the case when there is an error in opening file.
        STATE.store(UNINITIALIZED, Ordering::SeqCst);
        assert!(l.init("TEST-ID", Some(String::from("")), None).is_err());
        let res = l.init("TEST-ID", Some(log_file.clone()), Some(String::from("")));
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
            format!("{:?}", l.init("TEST-ID", None, None).err()),
            "Some(AlreadyInitialized)"
        );

        STATE.store(UNINITIALIZED, Ordering::SeqCst);
        let res = l.init("TEST-ID", Some(log_file.clone()), None);
        assert!(res.is_err());
        assert_eq!(
            format!("{:?}", res.err().unwrap()),
            "NeverInitialized(\"attempted to set a logger after \
             the logging system was already initialized\")"
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
