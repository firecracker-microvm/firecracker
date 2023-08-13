// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::convert::From;
use std::fmt;
use std::io::LineWriter;
use std::os::unix::fs::OpenOptionsExt;
use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tracing::Event;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::format::{self, FormatEvent, FormatFields};
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use tracing_subscriber::fmt::{FmtContext, Layer as FmtLayer};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::{LookupSpan, Registry};
use tracing_subscriber::reload::Layer as ReloadLayer;
use tracing_subscriber::util::SubscriberInitExt;

type ReloadError = tracing_subscriber::reload::Error;

// TODO: See below doc comment.
/// Mimic of `log::Level`.
///
/// This is used instead of `log::Level` to support:
/// 1. Aliasing `Warn` as `Warning` to avoid a breaking change in the API (which previously only
///    accepted `Warning`).
/// 2. Setting the default to `Warn` to avoid a breaking change.
///
/// This alias, custom `Default` and type should be removed in the next breaking update to simplify
/// the code and API (and `log::Level` should be used in place).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum Level {
    /// The “error” level.
    ///
    /// Designates very serious errors.
    #[serde(alias = "ERROR")]
    Error,
    /// The “warn” level.
    ///
    /// Designates hazardous situations.
    #[serde(alias = "WARNING", alias = "Warning")]
    Warn,
    /// The “info” level.
    ///
    /// Designates useful information.
    #[serde(alias = "INFO")]
    Info,
    /// The “debug” level.
    ///
    /// Designates lower priority information.
    #[serde(alias = "DEBUG")]
    Debug,
    /// The “trace” level.
    ///
    /// Designates very low priority, often extremely verbose, information.
    #[serde(alias = "TRACE")]
    Trace,
}
impl Default for Level {
    fn default() -> Self {
        Self::Warn
    }
}
impl From<Level> for tracing::Level {
    fn from(level: Level) -> tracing::Level {
        match level {
            Level::Error => tracing::Level::ERROR,
            Level::Warn => tracing::Level::WARN,
            Level::Info => tracing::Level::INFO,
            Level::Debug => tracing::Level::DEBUG,
            Level::Trace => tracing::Level::TRACE,
        }
    }
}
impl From<log::Level> for Level {
    fn from(level: log::Level) -> Level {
        match level {
            log::Level::Error => Level::Error,
            log::Level::Warn => Level::Warn,
            log::Level::Info => Level::Info,
            log::Level::Debug => Level::Debug,
            log::Level::Trace => Level::Trace,
        }
    }
}
impl FromStr for Level {
    type Err = <log::Level as FromStr>::Err;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        // This is required to avoid a breaking change.
        match s {
            "ERROR" => Ok(Level::Error),
            "WARNING" | "Warning" => Ok(Level::Warn),
            "INFO" => Ok(Level::Info),
            "DEBUG" => Ok(Level::Debug),
            "TRACE" => Ok(Level::Trace),
            _ => log::Level::from_str(s).map(Level::from),
        }
    }
}

/// Strongly typed structure used to describe the logger.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoggerConfig {
    /// Named pipe or file used as output for logs.
    pub log_path: Option<std::path::PathBuf>,
    /// The level of the Logger.
    pub level: Option<Level>,
    /// When enabled, the logger will append to the output the severity of the log entry.
    pub show_level: Option<bool>,
    /// When enabled, the logger will append the origin of the log entry.
    pub show_log_origin: Option<bool>,
}

/// Error type for [`LoggerConfig::init`].
#[derive(Debug, thiserror::Error)]
pub enum InitLoggerError {
    /// Failed to initialize logger.
    #[error("Failed to initialize logger: {0}")]
    Init(tracing_subscriber::util::TryInitError),
    /// Failed to open target file.
    #[error("Failed to open target file: {0}")]
    File(std::io::Error),
}

/// Error type for [`LoggerConfig::update`].
#[derive(Debug, thiserror::Error)]
pub enum UpdateLoggerError {
    /// Failed to open target file.
    #[error("Failed to open target file: {0}")]
    File(std::io::Error),
    /// Failed to modify format subscriber writer.
    #[error("Failed to modify format subscriber writer: {0}")]
    Fmt(ReloadError),
    /// Failed to modify filter level.
    #[error("Failed to modify filter level: {0}")]
    Filter(ReloadError),
}

type FmtHandle = tracing_subscriber::reload::Handle<
    tracing_subscriber::fmt::Layer<
        tracing_subscriber::layer::Layered<
            tracing_subscriber::reload::Layer<
                tracing_subscriber::filter::LevelFilter,
                tracing_subscriber::registry::Registry,
            >,
            tracing_subscriber::registry::Registry,
        >,
        tracing_subscriber::fmt::format::DefaultFields,
        LoggerFormatter,
        tracing_subscriber::fmt::writer::BoxMakeWriter,
    >,
    tracing_subscriber::layer::Layered<
        tracing_subscriber::reload::Layer<
            tracing_subscriber::filter::LevelFilter,
            tracing_subscriber::registry::Registry,
        >,
        tracing_subscriber::registry::Registry,
    >,
>;
type FilterHandle = tracing_subscriber::reload::Handle<
    tracing_subscriber::filter::LevelFilter,
    tracing_subscriber::registry::Registry,
>;

/// Handles that allow re-configuring the logger.
#[derive(Debug)]
pub struct LoggerHandles {
    filter: FilterHandle,
    fmt: FmtHandle,
}

impl LoggerConfig {
    /// Initializes the logger.
    ///
    /// Returns handles that can be used to dynamically re-configure the logger.
    pub fn init(&self) -> Result<LoggerHandles, InitLoggerError> {
        // Setup filter
        let (filter, filter_handle) = {
            let level = tracing::Level::from(self.level.unwrap_or_default());
            let filter_subscriber = LevelFilter::from_level(level);
            ReloadLayer::new(filter_subscriber)
        };

        // Setup fmt layer
        let (fmt, fmt_handle) = {
            let fmt_writer = match &self.log_path {
                Some(path) => {
                    // In case we open a FIFO, in order to not block the instance if nobody is
                    // consuming the message that is flushed to the two pipes, we are opening it
                    // with `O_NONBLOCK` flag. In this case, writing to a pipe will start failing
                    // when reaching 64K of unconsumed content.
                    let file = std::fs::OpenOptions::new()
                        .custom_flags(libc::O_NONBLOCK)
                        .read(true)
                        .write(true)
                        .open(path)
                        .map_err(InitLoggerError::File)?;
                    // Wrap file to satisfy `tracing_subscriber::fmt::MakeWriter`.
                    let writer = Mutex::new(LineWriter::new(file));
                    BoxMakeWriter::new(writer)
                }
                None => BoxMakeWriter::new(std::io::stdout),
            };
            let fmt_subscriber = FmtLayer::new()
                .event_format(LoggerFormatter::new(
                    self.show_level.unwrap_or_default(),
                    self.show_log_origin.unwrap_or_default(),
                ))
                .with_writer(fmt_writer);
            ReloadLayer::new(fmt_subscriber)
        };

        Registry::default()
            .with(filter)
            .with(fmt)
            .try_init()
            .map_err(InitLoggerError::Init)?;

        tracing::error!("Error level logs enabled.");
        tracing::warn!("Warn level logs enabled.");
        tracing::info!("Info level logs enabled.");
        tracing::debug!("Debug level logs enabled.");
        tracing::trace!("Trace level logs enabled.");

        Ok(LoggerHandles {
            filter: filter_handle,
            fmt: fmt_handle,
        })
    }
    /// Updates the logger using the given handles.
    pub fn update(
        &self,
        LoggerHandles { filter, fmt }: &LoggerHandles,
    ) -> Result<(), UpdateLoggerError> {
        // Update the log path
        if let Some(log_path) = &self.log_path {
            // In case we open a FIFO, in order to not block the instance if nobody is consuming the
            // message that is flushed to the two pipes, we are opening it with `O_NONBLOCK` flag.
            // In this case, writing to a pipe will start failing when reaching 64K of unconsumed
            // content.
            let file = std::fs::OpenOptions::new()
                .custom_flags(libc::O_NONBLOCK)
                .read(true)
                .write(true)
                .open(log_path)
                .map_err(UpdateLoggerError::File)?;

            fmt.modify(|f| *f.writer_mut() = BoxMakeWriter::new(Mutex::new(LineWriter::new(file))))
                .map_err(UpdateLoggerError::Fmt)?;
        }

        // Update the filter level
        if let Some(level) = self.level {
            filter
                .modify(|f| *f = LevelFilter::from_level(tracing::Level::from(level)))
                .map_err(UpdateLoggerError::Filter)?;
        }

        // Update if the logger shows the level
        if let Some(show_level) = self.show_level {
            SHOW_LEVEL.store(show_level, SeqCst);
        }

        // Updates if the logger shows the origin
        if let Some(show_log_origin) = self.show_log_origin {
            SHOW_LOG_ORIGIN.store(show_log_origin, SeqCst);
        }

        Ok(())
    }
}

#[derive(Debug)]
struct LoggerFormatter;
impl LoggerFormatter {
    pub fn new(show_level: bool, show_log_origin: bool) -> Self {
        SHOW_LEVEL.store(show_level, SeqCst);
        SHOW_LOG_ORIGIN.store(show_log_origin, SeqCst);
        Self
    }
}

static SHOW_LEVEL: AtomicBool = AtomicBool::new(false);
static SHOW_LOG_ORIGIN: AtomicBool = AtomicBool::new(false);

impl<S, N> FormatEvent<S, N> for LoggerFormatter
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        writer: format::Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        tracing_subscriber::fmt::format::Format::default()
            .with_thread_names(true)
            .with_ansi(false)
            .with_level(SHOW_LEVEL.load(SeqCst))
            .with_file(SHOW_LOG_ORIGIN.load(SeqCst))
            .with_line_number(SHOW_LOG_ORIGIN.load(SeqCst))
            .format_event(ctx, writer, event)
    }
}
