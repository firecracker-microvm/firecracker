// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::convert::From;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{BufWriter, LineWriter};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tracing::Event;
use tracing_subscriber::fmt::format::{self, FormatEvent, FormatFields};
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use tracing_subscriber::fmt::{FmtContext, Layer as FmtLayer};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::{LookupSpan, Registry};
use tracing_subscriber::reload::Layer as ReloadLayer;
use tracing_subscriber::util::SubscriberInitExt;

type ReloadError = tracing_subscriber::reload::Error;

// TODO: See below doc comment.
/// Mimic of `log::LevelFilter`.
///
/// This is used instead of `log::LevelFilter` to support aliasing `Warn` as `Warning` to avoid a
/// breaking change in the API (which previously only accepted `Warning`).
///
/// This alias should be removed in the next breaking update to simplify
/// the code and API (and `log::LevelFilter` should be used in place).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum LevelFilter {
    /// A level lower than all log levels.
    Off,
    /// Corresponds to the `Error` log level.
    #[serde(alias = "ERROR")]
    Error,
    /// Corresponds to the `Warn` log level.
    #[serde(alias = "WARNING", alias = "Warning")]
    Warn,
    /// Corresponds to the `Info` log level.
    #[serde(alias = "INFO")]
    Info,
    /// Corresponds to the `Debug` log level.
    #[serde(alias = "DEBUG")]
    Debug,
    /// Corresponds to the `Trace` log level.
    #[serde(alias = "TRACE")]
    Trace,
}

fn from_log(level: log::LevelFilter) -> tracing_subscriber::filter::LevelFilter {
    match level {
        log::LevelFilter::Off => tracing_subscriber::filter::LevelFilter::OFF,
        log::LevelFilter::Error => tracing_subscriber::filter::LevelFilter::ERROR,
        log::LevelFilter::Warn => tracing_subscriber::filter::LevelFilter::WARN,
        log::LevelFilter::Info => tracing_subscriber::filter::LevelFilter::INFO,
        log::LevelFilter::Debug => tracing_subscriber::filter::LevelFilter::DEBUG,
        log::LevelFilter::Trace => tracing_subscriber::filter::LevelFilter::TRACE,
    }
}

impl From<LevelFilter> for log::LevelFilter {
    fn from(level: LevelFilter) -> log::LevelFilter {
        match level {
            LevelFilter::Off => log::LevelFilter::Off,
            LevelFilter::Error => log::LevelFilter::Error,
            LevelFilter::Warn => log::LevelFilter::Warn,
            LevelFilter::Info => log::LevelFilter::Info,
            LevelFilter::Debug => log::LevelFilter::Debug,
            LevelFilter::Trace => log::LevelFilter::Trace,
        }
    }
}
impl From<log::LevelFilter> for LevelFilter {
    fn from(level: log::LevelFilter) -> LevelFilter {
        match level {
            log::LevelFilter::Off => LevelFilter::Off,
            log::LevelFilter::Error => LevelFilter::Error,
            log::LevelFilter::Warn => LevelFilter::Warn,
            log::LevelFilter::Info => LevelFilter::Info,
            log::LevelFilter::Debug => LevelFilter::Debug,
            log::LevelFilter::Trace => LevelFilter::Trace,
        }
    }
}
impl FromStr for LevelFilter {
    type Err = <log::LevelFilter as FromStr>::Err;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        // This is required to avoid a breaking change.
        match s {
            "OFF" => Ok(LevelFilter::Off),
            "ERROR" => Ok(LevelFilter::Error),
            "WARNING" | "Warning" => Ok(LevelFilter::Warn),
            "INFO" => Ok(LevelFilter::Info),
            "DEBUG" => Ok(LevelFilter::Debug),
            "TRACE" => Ok(LevelFilter::Trace),
            _ => log::LevelFilter::from_str(s).map(LevelFilter::from),
        }
    }
}

/// Strongly typed structure used to describe the logger.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoggerConfig {
    /// Named pipe or file used as output for logs.
    pub log_path: Option<PathBuf>,
    // TODO Deprecate this API argument.
    /// The level of the Logger.
    pub level: Option<LevelFilter>,
    /// When enabled, the logger will append to the output the severity of the log entry.
    pub show_level: Option<bool>,
    /// When enabled, the logger will append the origin of the log entry.
    pub show_log_origin: Option<bool>,
    /// Filter components. If this is `Some` it overrides `self.level`.
    pub filter: Option<FilterArgs>,
    /// Named pipe or file used as output for profile.
    pub profile_path: Option<PathBuf>,
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
    /// Failed to modify format layer writer.
    #[error("Failed to modify format layer writer: {0}")]
    Fmt(ReloadError),
    /// Failed to modify level filter.
    #[error("Failed to modify level filter: {0}")]
    Level(ReloadError),
}

/// The filter arguments for logs.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct FilterArgs {
    /// A filepath to filter by e.g. `src/main.rs`.
    file: Option<String>,
    /// A module path to filter by e.g. `vmm::vmm_config`.
    module: Option<String>,
    /// A level to filter by e.g. `tracing::Level::INFO`.
    level: Option<log::LevelFilter>,
}

// Initialize filter to default.
static FILTER: Mutex<FilterArgs> = Mutex::new(FilterArgs {
    file: None,
    module: None,
    level: Some(log::LevelFilter::Warn),
});

// `type_alias_impl_trait` is the nightly feature required to move this to a `type FmtHandle = ..`
// and remove these polluting generics.
/// Handles that allow re-configuring the logger.
#[derive(Debug)]
pub struct LoggerHandles<F, G> {
    fmt: FmtHandle<F, G>,
}

type FmtHandle<F, G> = tracing_subscriber::reload::Handle<
    tracing_subscriber::fmt::Layer<
        tracing_subscriber::layer::Layered<
            tracing_subscriber::filter::FilterFn<F>,
            tracing_subscriber::registry::Registry,
        >,
        tracing_subscriber::fmt::format::DefaultFields,
        LoggerFormatter,
        tracing_subscriber::fmt::writer::BoxMakeWriter,
    >,
    tracing_subscriber::layer::Layered<
        tracing_subscriber::filter::FilterFn<G>,
        tracing_subscriber::registry::Registry,
    >,
>;

/// An alias for the specific [`tracing_flame::FlushGuard`] used to flush the
/// [`tracing_flame::FlameLayer`].
pub type FlameGuard = tracing_flame::FlushGuard<BufWriter<std::fs::File>>;

impl LoggerConfig {
    /// Initializes the logger.
    ///
    /// Returns handles that can be used to dynamically re-configure the logger.
    pub fn init(
        self,
    ) -> Result<
        (
            LoggerHandles<
                impl Fn(&tracing::Metadata<'_>) -> bool,
                impl Fn(&tracing::Metadata<'_>) -> bool,
            >,
            Option<FlameGuard>,
        ),
        InitLoggerError,
    > {
        // Update default filter to match passed arguments.
        match (self.level, self.filter) {
            (_, Some(filter)) => {
                *FILTER.lock().unwrap() = filter;
            }
            (Some(level), None) => {
                *FILTER.lock().unwrap() = FilterArgs {
                    file: None,
                    module: None,
                    level: Some(log::LevelFilter::from(level)),
                };
            }
            (None, None) => {}
        }

        // Setup filter layer
        let filter = tracing_subscriber::filter::FilterFn::new(|metadata| {
            let args = FILTER.lock().unwrap();
            let file_cond = args.file.as_ref().map_or(true, |f| {
                metadata
                    .file()
                    .map(|file| file.starts_with(f))
                    .unwrap_or(false)
            });
            let module_cond = args.module.as_ref().map_or(true, |m| {
                metadata
                    .module_path()
                    .map(|module_path| module_path.starts_with(m))
                    .unwrap_or(false)
            });
            let level_cond = args
                .level
                .map_or(true, |l| *metadata.level() <= from_log(l));
            file_cond && module_cond && level_cond
        });

        // Setup fmt layer
        let (fmt, fmt_handle) = {
            let fmt_writer = match &self.log_path {
                Some(path) => {
                    // In case we open a FIFO, in order to not block the instance if nobody is
                    // consuming the message that is flushed to the two pipes, we are opening it
                    // with `O_NONBLOCK` flag. In this case, writing to a pipe will start failing
                    // when reaching 64K of unconsumed content.
                    let file = OpenOptions::new()
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

        // Setup flame layer
        let flame_guard = if let Some(profile_path) = self.profile_path {
            let writer = OpenOptions::new().write(true).open(profile_path).unwrap();
            let buffer = BufWriter::new(writer);
            let flame_layer = tracing_flame::FlameLayer::new(buffer);
            let guard = flame_layer.flush_on_drop();

            Registry::default()
                .with(filter)
                .with(fmt)
                .with(flame_layer)
                .try_init()
                .map_err(InitLoggerError::Init)?;

            Some(guard)
        } else {
            Registry::default()
                .with(filter)
                .with(fmt)
                .try_init()
                .map_err(InitLoggerError::Init)?;
            None
        };

        tracing::error!("Error level logs enabled.");
        tracing::warn!("Warn level logs enabled.");
        tracing::info!("Info level logs enabled.");
        tracing::debug!("Debug level logs enabled.");
        tracing::trace!("Trace level logs enabled.");

        Ok((LoggerHandles { fmt: fmt_handle }, flame_guard))
    }
    /// Updates the logger using the given handles.
    pub fn update(
        self,
        LoggerHandles { fmt }: &LoggerHandles<
            impl Fn(&tracing::Metadata<'_>) -> bool,
            impl Fn(&tracing::Metadata<'_>) -> bool,
        >,
    ) -> Result<(), UpdateLoggerError> {
        // Update the log path
        if let Some(log_path) = &self.log_path {
            // In case we open a FIFO, in order to not block the instance if nobody is consuming the
            // message that is flushed to the two pipes, we are opening it with `O_NONBLOCK` flag.
            // In this case, writing to a pipe will start failing when reaching 64K of unconsumed
            // content.
            let file = OpenOptions::new()
                .custom_flags(libc::O_NONBLOCK)
                .read(true)
                .write(true)
                .open(log_path)
                .map_err(UpdateLoggerError::File)?;

            fmt.modify(|f| *f.writer_mut() = BoxMakeWriter::new(Mutex::new(LineWriter::new(file))))
                .map_err(UpdateLoggerError::Fmt)?;
        }

        // Update the filter
        match (self.level, self.filter) {
            (_, Some(filter)) => {
                *FILTER.lock().unwrap() = filter;
            }
            (Some(level), None) => {
                *FILTER.lock().unwrap() = FilterArgs {
                    file: None,
                    module: None,
                    level: Some(log::LevelFilter::from(level)),
                };
            }
            (None, None) => {}
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
