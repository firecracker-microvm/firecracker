// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use core::fmt;
use std::convert::{From, TryInto};
use std::fs::{File, OpenOptions};
use std::io::{self, LineWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::str::FromStr;
use std::sync::Mutex;

use libc::O_NONBLOCK;
use rate_limiter::{BucketUpdate, RateLimiter, TokenBucket};
use serde::{Deserialize, Serialize};
use tracing_core::{Event, Subscriber};
use tracing_subscriber::fmt::format::{self, FormatEvent, FormatFields};
use tracing_subscriber::fmt::{FmtContext, Layer};
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry::LookupSpan;

/// Wrapper for configuring the balloon device.
pub mod balloon;
/// Wrapper for configuring the microVM boot source.
pub mod boot_source;
/// Wrapper for configuring the block devices.
pub mod drive;
/// Wrapper for configuring the entropy device attached to the microVM.
pub mod entropy;
/// Wrapper over the microVM general information attached to the microVM.
pub mod instance_info;
/// Wrapper for configuring the memory and CPU of the microVM.
pub mod machine_config;
/// Wrapper for configuring the metrics.
pub mod metrics;
/// Wrapper for configuring the MMDS.
pub mod mmds;
/// Wrapper for configuring the network devices attached to the microVM.
pub mod net;
/// Wrapper for configuring microVM snapshots and the microVM state.
pub mod snapshot;
/// Wrapper for configuring the vsock devices attached to the microVM.
pub mod vsock;

// TODO: Migrate the VMM public-facing code (i.e. interface) to use stateless structures,
// for receiving data/args, such as the below `RateLimiterConfig` and `TokenBucketConfig`.
// Also todo: find a better suffix than `Config`; it should illustrate the static nature
// of the enclosed data.
// Currently, data is passed around using live/stateful objects. Switching to static/stateless
// objects will simplify both the ownership model and serialization.
// Public access would then be more tightly regulated via `VmmAction`s, consisting of tuples like
// (entry-point-into-VMM-logic, stateless-args-structure).

/// A public-facing, stateless structure, holding all the data we need to create a TokenBucket
/// (live) object.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct TokenBucketConfig {
    /// See TokenBucket::size.
    pub size: u64,
    /// See TokenBucket::one_time_burst.
    pub one_time_burst: Option<u64>,
    /// See TokenBucket::refill_time.
    pub refill_time: u64,
}

impl From<&TokenBucket> for TokenBucketConfig {
    fn from(tb: &TokenBucket) -> Self {
        let one_time_burst = match tb.initial_one_time_burst() {
            0 => None,
            v => Some(v),
        };
        TokenBucketConfig {
            size: tb.capacity(),
            one_time_burst,
            refill_time: tb.refill_time_ms(),
        }
    }
}

/// A public-facing, stateless structure, holding all the data we need to create a RateLimiter
/// (live) object.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimiterConfig {
    /// Data used to initialize the RateLimiter::bandwidth bucket.
    pub bandwidth: Option<TokenBucketConfig>,
    /// Data used to initialize the RateLimiter::ops bucket.
    pub ops: Option<TokenBucketConfig>,
}

/// A public-facing, stateless structure, specifying RateLimiter properties updates.
#[derive(Debug)]
pub struct RateLimiterUpdate {
    /// Possible update to the RateLimiter::bandwidth bucket.
    pub bandwidth: BucketUpdate,
    /// Possible update to the RateLimiter::ops bucket.
    pub ops: BucketUpdate,
}

fn get_bucket_update(tb_cfg: &Option<TokenBucketConfig>) -> BucketUpdate {
    match tb_cfg {
        // There is data to update.
        Some(tb_cfg) => {
            TokenBucket::new(
                tb_cfg.size,
                tb_cfg.one_time_burst.unwrap_or(0),
                tb_cfg.refill_time,
            )
            // Updated active rate-limiter.
            .map(BucketUpdate::Update)
            // Updated/deactivated rate-limiter
            .unwrap_or(BucketUpdate::Disabled)
        }
        // No update to the rate-limiter.
        None => BucketUpdate::None,
    }
}

impl From<Option<RateLimiterConfig>> for RateLimiterUpdate {
    fn from(cfg: Option<RateLimiterConfig>) -> Self {
        if let Some(cfg) = cfg {
            RateLimiterUpdate {
                bandwidth: get_bucket_update(&cfg.bandwidth),
                ops: get_bucket_update(&cfg.ops),
            }
        } else {
            // No update to the rate-limiter.
            RateLimiterUpdate {
                bandwidth: BucketUpdate::None,
                ops: BucketUpdate::None,
            }
        }
    }
}

impl TryInto<RateLimiter> for RateLimiterConfig {
    type Error = io::Error;

    fn try_into(self) -> std::result::Result<RateLimiter, Self::Error> {
        let bw = self.bandwidth.unwrap_or_default();
        let ops = self.ops.unwrap_or_default();
        RateLimiter::new(
            bw.size,
            bw.one_time_burst.unwrap_or(0),
            bw.refill_time,
            ops.size,
            ops.one_time_burst.unwrap_or(0),
            ops.refill_time,
        )
    }
}

impl From<&RateLimiter> for RateLimiterConfig {
    fn from(rl: &RateLimiter) -> Self {
        RateLimiterConfig {
            bandwidth: rl.bandwidth().map(TokenBucketConfig::from),
            ops: rl.ops().map(TokenBucketConfig::from),
        }
    }
}

impl RateLimiterConfig {
    // Option<T> already implements From<T> so we have to use a custom one.
    fn into_option(self) -> Option<RateLimiterConfig> {
        if self.bandwidth.is_some() || self.ops.is_some() {
            Some(self)
        } else {
            None
        }
    }
}

type Result<T> = std::result::Result<T, std::io::Error>;

/// Create and opens a File for writing to it.
/// In case we open a FIFO, in order to not block the instance if nobody is consuming the message
/// that is flushed to the two pipes, we are opening it with `O_NONBLOCK` flag.
/// In this case, writing to a pipe will start failing when reaching 64K of unconsumed content.
fn open_file_nonblock(path: &Path) -> Result<File> {
    OpenOptions::new()
        .custom_flags(O_NONBLOCK)
        .read(true)
        .write(true)
        .open(path)
}

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
    pub log_path: std::path::PathBuf,
    /// The level of the Logger.
    pub level: Option<Level>,
    /// When enabled, the logger will append to the output the severity of the log entry.
    pub show_level: Option<bool>,
    /// When enabled, the logger will append the origin of the log entry.
    pub show_log_origin: Option<bool>,
    /// Use the new logger format.
    pub new_format: Option<bool>,
}

/// Error with actions on the `LoggerConfig`.
#[derive(Debug, thiserror::Error)]
pub enum LoggerConfigError {
    /// Failed to initialize logger.
    #[error("Failed to initialize logger: {0}")]
    Init(tracing_subscriber::util::TryInitError),
    /// Failed to open target file.
    #[error("Failed to open target file: {0}")]
    File(std::io::Error),
    /// Failed to write initialization message.
    #[error("Failed to write initialization message: {0}")]
    Write(std::io::Error),
}

impl LoggerConfig {
    const INIT_MESSAGE: &str = concat!("Running Firecracker v", env!("FIRECRACKER_VERSION"), "\n");

    /// Initializes the logger.
    pub fn init(&self) -> std::result::Result<(), LoggerConfigError> {
        let level = tracing::Level::from(self.level.unwrap_or_default());
        let level_filter = tracing_subscriber::filter::LevelFilter::from_level(level);

        // In case we open a FIFO, in order to not block the instance if nobody is consuming the
        // message that is flushed to the two pipes, we are opening it with `O_NONBLOCK` flag.
        // In this case, writing to a pipe will start failing when reaching 64K of unconsumed
        // content.
        let mut file = std::fs::OpenOptions::new()
            .custom_flags(libc::O_NONBLOCK)
            .read(true)
            .write(true)
            .open(&self.log_path)
            .map_err(LoggerConfigError::File)?;

        // Write the initialization message.
        file.write_all(LoggerConfig::INIT_MESSAGE.as_bytes())
            .map_err(LoggerConfigError::File)?;

        // Wrap file to satisfy `tracing_subscriber::fmt::MakeWriter`.
        let writer = Mutex::new(LineWriter::new(file));

        // Initialize the layers.
        if self.new_format.unwrap_or_default() {
            tracing_subscriber::registry()
                .with(level_filter)
                .with(new_log(self, writer))
                .try_init()
        } else {
            tracing_subscriber::registry()
                .with(level_filter)
                .with(old_log(self, writer))
                .try_init()
        }
        .map_err(LoggerConfigError::Init)?;

        tracing::error!("Error level logs enabled.");
        tracing::warn!("Warn level logs enabled.");
        tracing::info!("Info level logs enabled.");
        tracing::debug!("Debug level logs enabled.");
        tracing::trace!("Trace level logs enabled.");

        Ok(())
    }
}

type FormatWriter = Mutex<LineWriter<File>>;

fn new_log<S: Subscriber + for<'span> LookupSpan<'span>>(
    config: &LoggerConfig,
    writer: FormatWriter,
) -> Layer<S, format::DefaultFields, format::Format, FormatWriter> {
    let show_origin = config.show_log_origin.unwrap_or_default();
    Layer::new()
        .with_level(config.show_level.unwrap_or_default())
        .with_file(show_origin)
        .with_line_number(show_origin)
        .with_writer(writer)
}
fn old_log<S: Subscriber + for<'span> LookupSpan<'span>>(
    config: &LoggerConfig,
    writer: FormatWriter,
) -> Layer<S, format::DefaultFields, OldLoggerFormatter, FormatWriter> {
    Layer::new()
        .event_format(OldLoggerFormatter {
            show_level: config.show_level.unwrap_or_default(),
            show_log_origin: config.show_log_origin.unwrap_or_default(),
        })
        .with_writer(writer)
}

// use std::sync::atomic::AtomicUsize;
// use std::sync::atomic::Ordering;
// static GURAD: AtomicUsize = AtomicUsize::new(0);

/// The log line should look lie this:
/// ```text
/// YYYY-MM-DDTHH:MM:SS.NNNNNNNNN [ID:THREAD:LEVEL:FILE:LINE] MESSAGE
/// ```
/// where LEVEL and FILE:LINE are both optional. e.g. with THREAD NAME as TN
/// ```text
/// 2018-09-09T12:52:00.123456789 [MYID:TN:WARN:/path/to/file.rs:52] warning
/// ```
struct OldLoggerFormatter {
    show_level: bool,
    show_log_origin: bool,
}

impl<S, N> FormatEvent<S, N> for OldLoggerFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: format::Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        // Format values from the event's's metadata:
        let metadata = event.metadata();

        let time = utils::time::LocalTime::now();
        let instance_id = logger::INSTANCE_ID
            .get()
            .map(String::as_str)
            .unwrap_or(logger::DEFAULT_INSTANCE_ID);
        let thread_id = std::thread::current()
            .name()
            .map(String::from)
            .unwrap_or(String::from("-"));

        // Write the time, instance ID and thread ID.
        write!(writer, "{time} [{instance_id}:{thread_id}")?;

        // Write the log level
        if self.show_level {
            write!(writer, ":{}", metadata.level())?;
        }

        // Write the log file and line.
        if self.show_log_origin {
            // Write the file
            write!(writer, ":{}", metadata.file().unwrap_or("unknown"))?;
            // Write the line
            if let Some(line) = metadata.line() {
                write!(writer, ":{line}")?;
            }
        }
        write!(writer, "] ")?;

        // Write fields on the event
        ctx.field_format().format_fields(writer.by_ref(), event)?;

        writeln!(writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIZE: u64 = 1024 * 1024;
    const ONE_TIME_BURST: u64 = 1024;
    const REFILL_TIME: u64 = 1000;

    #[test]
    fn test_rate_limiter_configs() {
        let rlconf = RateLimiterConfig {
            bandwidth: Some(TokenBucketConfig {
                size: SIZE,
                one_time_burst: Some(ONE_TIME_BURST),
                refill_time: REFILL_TIME,
            }),
            ops: Some(TokenBucketConfig {
                size: SIZE * 2,
                one_time_burst: None,
                refill_time: REFILL_TIME * 2,
            }),
        };
        let rl: RateLimiter = rlconf.try_into().unwrap();
        assert_eq!(rl.bandwidth().unwrap().capacity(), SIZE);
        assert_eq!(rl.bandwidth().unwrap().one_time_burst(), ONE_TIME_BURST);
        assert_eq!(rl.bandwidth().unwrap().refill_time_ms(), REFILL_TIME);
        assert_eq!(rl.ops().unwrap().capacity(), SIZE * 2);
        assert_eq!(rl.ops().unwrap().one_time_burst(), 0);
        assert_eq!(rl.ops().unwrap().refill_time_ms(), REFILL_TIME * 2);
    }

    #[test]
    fn test_generate_configs() {
        let bw_tb_cfg = TokenBucketConfig {
            size: SIZE,
            one_time_burst: Some(ONE_TIME_BURST),
            refill_time: REFILL_TIME,
        };
        let bw_tb = TokenBucket::new(SIZE, ONE_TIME_BURST, REFILL_TIME).unwrap();
        let generated_bw_tb_cfg = TokenBucketConfig::from(&bw_tb);
        assert_eq!(generated_bw_tb_cfg, bw_tb_cfg);

        let rl_conf = RateLimiterConfig {
            bandwidth: Some(bw_tb_cfg),
            ops: None,
        };
        let rl: RateLimiter = rl_conf.try_into().unwrap();
        let generated_rl_conf = RateLimiterConfig::from(&rl);
        assert_eq!(generated_rl_conf, rl_conf);
        assert_eq!(generated_rl_conf.into_option(), Some(rl_conf));
    }
}
