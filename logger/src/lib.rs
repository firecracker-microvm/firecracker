//! Sends log messages to either stdout, stderr or a file provided as argument to the init.
//!
//! Every function exported by this module is thread-safe.
//! Each function will silently fail until
//! `log::init()` is called and returns `Ok`.
//!
//! # Examples
//!
//! ```
//! #[macro_use]
//! extern crate log;
//! extern crate logger;
//! use logger::Logger;
//!
//! fn main() {
//!     if let Err(e) = Logger::new().init(None) {
//!         println!("Could not initialize the log subsystem: {:?}", e);
//!         return;
//!     }
//!     warn!("this is a warning");
//!     error!("this is a error");
//! }
//! ```
extern crate chrono;
// workaround to macro_reexport
#[macro_use]
extern crate lazy_static;
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
use std::sync::{Mutex, MutexGuard};

use chrono::Local;

use error::LoggerError;
pub use log::Level::*;
pub use log::*;
use log::{set_logger, set_max_level, Log, Metadata, Record};
pub use metrics::{Metric, METRICS};
use writers::*;

/// Types used by the Logger.
///
pub type Result<T> = result::Result<T, LoggerError>;

/// Values used by the Logger.
///
pub const IN_PREFIX_SEPARATOR: &str = ":";
pub const MSG_SEPARATOR: &str = " ";
pub const DEFAULT_LEVEL: Level = Level::Warn;

/// Synchronization primitives used to run a one-time global initialization.
///
const UNINITIALIZED: usize = 0;
const INITIALIZING: usize = 1;
const INITIALIZED: usize = 2;

static STATE: AtomicUsize = ATOMIC_USIZE_INIT;

/// Time format
const TIME_FMT: &str = "%Y-%m-%dT%H:%M:%S.%f";

lazy_static! {
    pub static ref LOGGER: Logger = Logger::new();
}

/// Output sources for the log subsystem.
///
#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(usize)]
enum Destination {
    Stderr,
    Stdout,
    File,
}

/// Each log level also has a code and a destination output associated with it.
///
#[derive(Debug)]
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

// All member fields have types which are Sync, and exhibit interior mutability, so
// we can call logging operations using a non-mut static global variable.
#[derive(Debug)]
pub struct Logger {
    show_level: AtomicBool,
    show_file_path: AtomicBool,
    show_line_numbers: AtomicBool,
    level_info: LevelInfo,

    // used in case we want to log to a file
    file: Mutex<Option<FileLogWriter>>,
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
            file: Mutex::new(None),
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
    /// ```rust
    /// #[macro_use]
    /// extern crate log;
    /// extern crate logger;
    /// use logger::Logger;
    ///
    /// fn main() {
    ///     Logger::new()
    ///         .set_include_level(true)
    ///         .init(None)
    ///         .unwrap();
    ///
    ///     warn!("This will print 'WARN' surrounded by square brackets followed by log message");
    /// }
    /// ```
    pub fn set_include_level(&self, option: bool) {
        self.show_level.store(option, Ordering::Relaxed);
    }

    /// Enables or disables including the file path and the line numbers in the tag of the log message.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[macro_use]
    /// extern crate log;
    /// extern crate logger;
    /// use logger::Logger;
    ///
    /// fn main() {
    ///     Logger::new()
    ///         .set_include_origin(true, true)
    ///         .init(None)
    ///         .unwrap();
    ///
    ///     warn!("This will print '[WARN:file_path.rs:155]' followed by log message");
    /// }
    /// ```
    pub fn set_include_origin(&self, file_path: bool, line_numbers: bool) {
        self.show_file_path.store(file_path, Ordering::Relaxed);
        // if the file path is not shown, do not show line numbers either
        self.show_line_numbers
            .store(file_path && line_numbers, Ordering::Relaxed);
    }

    /// Explicitly sets the log level for the Logger.
    /// User needs to say the level code(error, warn...) and the output destination will be updated if and only if the
    /// logger was not initialized to log to a file.
    /// The default level is WARN. So, ERROR and WARN statements will be shown (basically, all that is bigger
    /// than the level code).
    /// If level is decreased at INFO, ERROR, WARN and INFO statements will be outputted, etc.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[macro_use]
    /// extern crate log;
    /// extern crate logger;
    /// use logger::Logger;
    ///
    /// fn main() {
    ///     Logger::new()
    ///         .set_level(log::Level::Info)
    ///         .init(None)
    ///         .unwrap();
    /// }
    /// ```
    pub fn set_level(&self, level: Level) {
        self.level_info.set_code(level);
        if self.level_info.writer() != Destination::File as usize {
            self.level_info.set_writer(get_default_destination(level));
        }
    }

    /// Creates the first portion (to the left of the separator)
    /// of the log statement based on the logger settings.
    ///
    fn create_prefix(&self, record: &Record) -> String {
        let level_str = if self.show_level() {
            record.level().to_string()
        } else {
            String::new()
        };

        let file_path_str = if self.show_file_path() {
            let pth = record.file().unwrap_or("unknown");
            if self.show_level() {
                format!("{}{}", IN_PREFIX_SEPARATOR, pth)
            } else {
                pth.into()
            }
        } else {
            String::new()
        };

        let line_str = if self.show_line_numbers() {
            if let Some(l) = record.line() {
                format!("{}{}", IN_PREFIX_SEPARATOR, l)
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        format!("[{}{}{}]", level_str, file_path_str, line_str)
    }

    fn file_guard(&self) -> MutexGuard<Option<FileLogWriter>> {
        match self.file.lock() {
            Ok(guard) => guard,
            // If a thread panics while holding this lock, the writer within should still be usable.
            // (we might get an incomplete log line or something like that).
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Initialize log subsystem (once and only once).
    /// Every call made after the first will have no effect besides return `Ok` or `Err`
    /// appropriately (read description of error's enum items).
    ///
    /// # Example
    ///
    /// ```rust
    /// extern crate logger;
    /// use logger::Logger;
    ///
    /// fn main() {
    ///     Logger::new()
    ///         .init(None)
    ///         .unwrap();
    /// }
    /// ```

    pub fn init(&self, log_path: Option<String>) -> Result<()> {
        // if the logger was already initialized, return error
        if STATE.compare_and_swap(UNINITIALIZED, INITIALIZING, Ordering::SeqCst) != UNINITIALIZED {
            return Err(LoggerError::AlreadyInitialized);
        }

        // otherwise try initialization
        if let Some(path) = log_path.as_ref() {
            match FileLogWriter::new(path) {
                Ok(t) => {
                    // the mutex shouldn't be poisoned before init; PANIC!
                    let mut g = LOGGER.file_guard();
                    *g = Some(t);
                    LOGGER.level_info.set_writer(Destination::File);
                }
                Err(ref e) => {
                    STATE.store(UNINITIALIZED, Ordering::SeqCst);
                    return Err(LoggerError::NeverInitialized(format!("{}", e)));
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
    fn log_helper(&self, mut msg: String) {
        // We have the awkward IF's for now because we can't use just "<enum_variant> as usize
        // on the left side of a match arm for some reason.
        match self.level_info.writer() {
            x if x == Destination::File as usize => {
                let mut g = self.file_guard();
                // the unwrap() is safe because writer == Destination::File
                let fw = g.as_mut().unwrap();
                msg = format!("{}\n", msg);
                if let Err(e) = fw.write(&msg) {
                    eprintln!("logger: Could not write to log file {}", e);
                }

                let _ = fw.flush();
            }
            x if x == Destination::Stderr as usize => {
                eprintln!("{}", msg);
            }
            x if x == Destination::Stdout as usize => {
                println!("{}", msg);
            }
            // major program logic error
            _ => panic!("Invalid logger.level_info.writer!"),
        }
    }

    pub fn log_metrics(&self) -> Result<()> {
        // Log metrics only if the logger has been initialized.
        if STATE.load(Ordering::Relaxed) == INITIALIZED {
            match serde_json::to_string(METRICS.deref()) {
                Ok(msg) => {
                    self.log_helper(msg);
                    Ok(())
                }
                Err(e) => {
                    return Err(LoggerError::LogMetricFailure(e.description().to_string()));
                }
            }
        } else {
            return Err(LoggerError::LogMetricFailure(
                "Failed to log metrics. Logger was not initialized.".to_string(),
            ));
        }
    }
}

/// Implements trait log from the externally used log crate
///
impl Log for Logger {
    // test whether a log level is enabled for the current module
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() as usize <= self.level_info.code()
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let msg = format!(
                "{} {}{}{}",
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
    use super::*;
    use log::MetadataBuilder;

    use std::fs::{remove_file, File};
    use std::io::BufRead;
    use std::io::BufReader;

    fn log_file_str() -> String {
        String::from("tmp.log")
    }

    fn validate_logs(
        log_path: &str,
        expected: &[(&'static str, &'static str, &'static str)],
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
        assert!(l.init(Some(log_file_str())).is_ok());
        info!("info");
        warn!("warning");

        assert!(l.init(None).is_err());

        info!("info");
        warn!("warning");
        error!("error");

        // here we also test that the second initialization had no effect given that the
        // logging system can only be initialized once per program
        validate_logs(
            &log_file_str(),
            &[
                ("[INFO", "lib.rs", "info"),
                ("[WARN", "lib.rs", "warn"),
                ("[INFO", "lib.rs", "info"),
                ("[WARN", "lib.rs", "warn"),
                ("[ERROR", "lib.rs", "error"),
            ],
        );

        assert!(l.log_metrics().is_ok());

        remove_file(log_file_str()).unwrap();

        // exercise the case when there is an error in opening file
        STATE.store(UNINITIALIZED, Ordering::SeqCst);
        assert!(l.init(Some(String::from(""))).is_err());

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
            format!("{:?}", l.init(None).err()),
            "Some(AlreadyInitialized)"
        );

        STATE.store(UNINITIALIZED, Ordering::SeqCst);
        let res = format!("{:?}", l.init(Some(log_file_str())).err().unwrap());
        remove_file(log_file_str()).unwrap();
        assert_eq!(
            res,
            "NeverInitialized(\"attempted to set a logger after \
             the logging system was already initialized\")"
        );
    }

    #[test]
    fn test_get_default_destination() {
        assert_eq!(
            get_default_destination(log::Level::Error),
            Destination::Stderr
        );
        assert_eq!(
            get_default_destination(log::Level::Warn),
            Destination::Stderr
        );
        assert_eq!(
            get_default_destination(log::Level::Info),
            Destination::Stdout
        );
        assert_eq!(
            get_default_destination(log::Level::Debug),
            Destination::Stdout
        );
        assert_eq!(
            get_default_destination(log::Level::Trace),
            Destination::Stdout
        );
    }
}
