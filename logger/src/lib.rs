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
// workaround to macro_reexport
#[macro_use]
extern crate lazy_static;
extern crate log;
extern crate time;
pub use log::Level::*;
pub use log::*;

mod error;
mod metrics;
mod writers;

use error::LoggerError;
use log::{set_boxed_logger, set_max_level, Log, Metadata, Record};
use metrics::get_metrics;

use std::result;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};

use writers::*;

/// Output sources for the log subsystem.
///
#[derive(Debug, PartialEq, Clone, Copy)]
enum Destination {
    Stderr,
    Stdout,
    File,
}

/// Each log level also has a code and a destination output associated with it.
///
#[derive(Debug)]
pub struct LevelInfo {
    code: Level,
    writer: Destination,
}

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

/// Logger representing the logging subsystem.
///
#[derive(Debug)]
pub struct Logger {
    show_level: bool,
    show_file_path: bool,
    show_line_numbers: bool,
    level_info: LevelInfo,
    // used in case we want to log to a file
    file: Option<Arc<FileLogWriter>>,
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
            show_level: true,
            show_line_numbers: true,
            show_file_path: true,
            level_info: LevelInfo {
                // DEFAULT_LEVEL is warn so the destination output is stderr
                code: DEFAULT_LEVEL,
                writer: Destination::Stderr,
            },
            file: None,
        }
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
    pub fn set_include_level(&mut self, option: bool) {
        self.show_level = option;
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
    pub fn set_include_origin(&mut self, file_path: bool, line_numbers: bool) {
        self.show_file_path = file_path;
        self.show_line_numbers = line_numbers;

        //buut if the file path is not shown, do not show line numbers either
        if !self.show_file_path {
            self.show_line_numbers = false;
        }
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
    pub fn set_level(&mut self, level: Level) {
        self.level_info.code = level;
        if self.level_info.writer != Destination::File {
            self.level_info.writer = get_default_destination(level);
        }
    }

    /// Creates the first portion (to the left of the separator)
    /// of the log statement based on the logger settings.
    ///
    fn create_prefix(&self, record: &Record) -> String {
        let level_str = if self.show_level {
            record.level().to_string()
        } else {
            String::new()
        };

        let file_path_str = if self.show_file_path {
            let pth = record.file().unwrap_or("unknown");
            if self.show_level {
                format!("{}{}", IN_PREFIX_SEPARATOR, pth)
            } else {
                pth.into()
            }
        } else {
            String::new()
        };

        let line_str = if self.show_line_numbers {
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
    pub fn init(mut self, log_path: Option<String>) -> Result<()> {
        // if the logger was already initialized, return error
        if STATE.compare_and_swap(UNINITIALIZED, INITIALIZING, Ordering::SeqCst) != UNINITIALIZED {
            return Err(LoggerError::AlreadyInitialized);
        }

        // otherwise try initialization
        if let Some(path) = log_path.as_ref() {
            match FileLogWriter::new(path) {
                Ok(t) => {
                    self.file = Some(Arc::new(t));
                    self.level_info.writer = Destination::File;
                }
                Err(ref e) => {
                    STATE.store(UNINITIALIZED, Ordering::SeqCst);
                    return Err(LoggerError::NeverInitialized(format!("{}", e)));
                }
            };
        }

        set_max_level(Level::Trace.to_level_filter());

        if let Err(e) = set_boxed_logger(Box::new(self)) {
            STATE.store(UNINITIALIZED, Ordering::SeqCst);
            return Err(LoggerError::NeverInitialized(format!("{}", e)));
        }

        STATE.store(INITIALIZED, Ordering::SeqCst);
        Ok(())
    }
}

/// Implements trait log from the externally used log crate
///
impl Log for Logger {
    // test whether a log level is enabled for the current module
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level_info.code || metadata.level() == Level::Trace
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let mut msg = format!(
                "{}{}{}",
                self.create_prefix(&record),
                MSG_SEPARATOR,
                record.args()
            );

            if record.level().eq(&log::Level::Trace) {
                let mut guard = match get_metrics().lock() {
                    Ok(g) => g,
                    Err(e) => {
                        eprintln!(
                            "{}",
                            LoggerError::MutexLockFailure(format!(
                                "Getting lock on metrics mutex failed. Error: {:?}",
                                e
                            ))
                        );
                        return;
                    }
                };
                let metric_key = String::from(format!("{}", (record.args())));
                let mut metric = guard.get_mut(&metric_key);
                match metric {
                    Some(ref mut m) => match m.log_metric() {
                        Ok(t) => msg = t,
                        Err(e) => match e {
                            LoggerError::LogMetricFailure => {
                                panic!("Logging metrics encountered illogical events")
                            }
                            LoggerError::LogMetricRateLimit => return,
                            _ => (),
                        },
                    },
                    None => eprintln!("No metric {} found", format!("{}", (record.args()))), // should this be a panic??
                }
            }

            match self.level_info.writer {
                Destination::Stderr => {
                    eprintln!("{}", msg);
                }
                Destination::Stdout => {
                    println!("{}", msg);
                }
                Destination::File => {
                    if let Some(fw) = self.file.as_ref() {
                        msg = format!("{}\n", msg);
                        if let Err(e) = fw.write(&msg) {
                            eprintln!("logger: Could not write to log file {}", e);
                        }
                        self.flush();
                    } else {
                        // if destination of log is a file but no file writer was found,
                        // should print error
                        eprintln!("logger: Could not find a file to write to");
                    }
                }
            }
        }
    }

    fn flush(&self) {
        if let Some(fw) = self.file.as_ref() {
            if let Err(e) = fw.flush() {
                eprintln!("logger: Could not flush log content to disk {}", e);
            }
        }
        // everything else flushes by itself
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::MetadataBuilder;

    use metrics::LogMetric::{MetricGetInstanceInfoFailures, MetricGetInstanceInfoRate};
    use std::fs::{copy, remove_file, File};
    use std::io::BufRead;
    use std::io::BufReader;
    use std::thread::sleep;
    use std::time::Duration;

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
        assert_eq!(l.level_info.code, log::Level::Warn);
        assert_eq!(l.level_info.writer, Destination::Stderr);
        assert_eq!(l.show_line_numbers, true);
        assert_eq!(l.show_level, true);
        format!("{:?}", l.level_info.code);
        format!("{:?}", l.level_info.writer);
        format!("{:?}", l.show_line_numbers);
        format!("{:?}", l);
    }

    #[test]
    fn test_init() {
        let mut l = Logger::new();
        l.set_include_origin(false, true);
        assert_eq!(l.show_line_numbers, false);

        let mut l = Logger::new();
        l.set_include_origin(true, true);
        l.set_include_level(true);
        l.set_level(log::Level::Info);
        assert_eq!(l.show_line_numbers, true);
        assert_eq!(l.show_file_path, true);
        assert_eq!(l.show_level, true);

        assert!(l.init(Some(log_file_str())).is_ok());
        info!("info");
        warn!("warning");

        let l = Logger::new();
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

        // testing logging metric
        trace!("{:?}", MetricGetInstanceInfoFailures);
        trace!("{:?}", MetricGetInstanceInfoRate);
        sleep(Duration::from_secs(3));
        trace!("{:?}", MetricGetInstanceInfoFailures);
        trace!("{:?}", MetricGetInstanceInfoRate);
        sleep(Duration::from_secs(3));
        trace!("{:?}", MetricGetInstanceInfoFailures);
        trace!("{:?}", MetricGetInstanceInfoRate);

        // leaving this commented so that you can test this RFC
        copy(log_file_str(), "rfc.log").unwrap();
        remove_file(log_file_str()).unwrap();

        // exercise the case when there is an error in opening file
        let l = Logger::new();
        STATE.store(UNINITIALIZED, Ordering::SeqCst);
        assert!(l.init(Some(String::from(""))).is_err());

        let mut l = Logger::new();
        l.set_include_level(true);
        l.set_include_origin(false, false);
        let error_metadata = MetadataBuilder::new().level(Level::Error).build();
        let log_record = log::Record::builder().metadata(error_metadata).build();
        Logger::log(&l, &log_record);

        assert_eq!(l.show_level, true);
        assert_eq!(l.show_file_path, false);
        assert_eq!(l.show_line_numbers, false);

        let mut l = Logger::new();
        l.set_include_level(false);
        l.set_include_origin(true, true);
        let error_metadata = MetadataBuilder::new().level(Level::Info).build();
        let log_record = log::Record::builder().metadata(error_metadata).build();
        Logger::log(&l, &log_record);

        assert_eq!(l.show_level, false);
        assert_eq!(l.show_file_path, true);
        assert_eq!(l.show_line_numbers, true);

        STATE.store(INITIALIZED, Ordering::SeqCst);
        let l = Logger::new();

        assert_eq!(
            format!("{:?}", l.init(None).err()),
            "Some(AlreadyInitialized)"
        );

        let l = Logger::new();
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
