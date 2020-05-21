// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryInto;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use libc::O_NONBLOCK;

use rate_limiter::RateLimiter;

/// Wrapper for configuring the microVM boot source.
pub mod boot_source;
/// Wrapper for configuring the block devices.
pub mod drive;
/// Wrapper over the microVM general information attached to the microVM.
pub mod instance_info;
/// Wrapper for configuring the logger.
pub mod logger;
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
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq)]
pub struct TokenBucketConfig {
    /// See TokenBucket::size.
    pub size: u64,
    /// See TokenBucket::one_time_burst.
    pub one_time_burst: Option<u64>,
    /// See TokenBucket::refill_time.
    pub refill_time: u64,
}

/// A public-facing, stateless structure, holding all the data we need to create a RateLimiter
/// (live) object.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RateLimiterConfig {
    /// Data used to initialize the RateLimiter::bandwidth bucket.
    pub bandwidth: Option<TokenBucketConfig>,
    /// Data used to initialize the RateLimiter::ops bucket.
    pub ops: Option<TokenBucketConfig>,
}

impl TryInto<RateLimiter> for RateLimiterConfig {
    type Error = io::Error;

    fn try_into(self) -> std::result::Result<RateLimiter, Self::Error> {
        let bw = self.bandwidth.unwrap_or_default();
        let ops = self.ops.unwrap_or_default();
        RateLimiter::new(
            bw.size,
            bw.one_time_burst,
            bw.refill_time,
            ops.size,
            ops.one_time_burst,
            ops.refill_time,
        )
    }
}

type Result<T> = std::result::Result<T, std::io::Error>;

/// Create and opens a File for writing to it.
/// In case we open a FIFO, in order to not block the instance if nobody is consuming the message
/// that is flushed to the two pipes, we are opening it with `O_NONBLOCK` flag.
/// In this case, writing to a pipe will start failing when reaching 64K of unconsumed content.
fn open_file_nonblock(path: &PathBuf) -> Result<File> {
    OpenOptions::new()
        .custom_flags(O_NONBLOCK)
        .read(true)
        .write(true)
        .open(&path)
}

type FcLineWriter = io::LineWriter<File>;

#[cfg(test)]
mod tests {
    use std::io::Write;

    use utils::tempfile::TempFile;

    use super::*;

    #[test]
    fn test_rate_limiter_configs() {
        const SIZE: u64 = 1024 * 1024;
        const ONE_TIME_BURST: u64 = 1024;
        const REFILL_TIME: u64 = 1000;

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
    fn test_fifo_line_writer() {
        let log_file_temp =
            TempFile::new().expect("Failed to create temporary output logging file.");
        let good_file = log_file_temp.as_path().to_path_buf();
        let maybe_fifo = open_file_nonblock(&good_file);
        assert!(maybe_fifo.is_ok());
        let mut fw = FcLineWriter::new(maybe_fifo.unwrap());

        let msg = String::from("some message");
        assert!(fw.write(&msg.as_bytes()).is_ok());
        assert!(fw.flush().is_ok());
    }
}
