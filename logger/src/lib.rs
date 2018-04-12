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
// workaround to marco_reexport
extern crate log;
pub use log::*;

mod error;
mod writers;

use error::LoggerError;
use log::{set_boxed_logger, set_max_level, Level, Log, Metadata, Record};
use std::result;
use std::sync::{Arc, Once, ONCE_INIT};
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
static INIT: Once = ONCE_INIT;
static mut INIT_RES: Result<()> = Ok(());

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
    pub fn set_include_level(mut self, option: bool) -> Self {
        self.show_level = option;
        self
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
    pub fn set_include_origin(mut self, file_path: bool, line_numbers: bool) -> Self {
        self.show_file_path = file_path;
        self.show_line_numbers = line_numbers;

        //buut if the file path is not shown, do not show line numbers either
        if !self.show_file_path {
            self.show_line_numbers = false;
        }

        self
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
    pub fn set_level(mut self, level: Level) -> Self {
        self.level_info.code = level;
        if self.level_info.writer != Destination::File {
            self.level_info.writer = get_default_destination(level);
        }
        self
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
        unsafe {
            if INIT_RES.is_err() {
                INIT_RES = Err(LoggerError::Poisoned(format!(
                    "{}",
                    INIT_RES.as_ref().err().unwrap()
                )));
                return Err(LoggerError::Poisoned(format!(
                    "{}",
                    INIT_RES.as_ref().err().unwrap()
                )));
            }
            INIT.call_once(|| {
                if let Some(path) = log_path.as_ref() {
                    match FileLogWriter::new(path) {
                        Ok(t) => {
                            self.file = Some(Arc::new(t));
                            self.level_info.writer = Destination::File;
                        }
                        Err(ref e) => {
                            INIT_RES = Err(LoggerError::NeverInitialized(format!("{}", e)));
                        }
                    };
                }
                set_max_level(self.level_info.code.to_level_filter());

                if let Err(e) = set_boxed_logger(Box::new(self)) {
                    INIT_RES = Err(LoggerError::NeverInitialized(format!("{}", e)))
                }
            });
            if INIT_RES.is_err() {
                return Err(LoggerError::NeverInitialized(format!(
                    "{}",
                    INIT_RES.as_ref().err().unwrap()
                )));
            }
        }
        Ok(())
    }
}

/// Implements trait log from the externally used log crate
///
impl Log for Logger {
    // test whether a log level is enabled for the current module
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level_info.code
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let mut msg = format!(
                "{}{}{}",
                self.create_prefix(&record),
                MSG_SEPARATOR,
                record.args()
            );

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
