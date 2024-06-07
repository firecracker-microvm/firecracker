// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::convert::{From, TryInto};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use libc::O_NONBLOCK;
use serde::{Deserialize, Serialize};

use crate::rate_limiter::{BucketUpdate, RateLimiter, TokenBucket};

/// Wrapper for configuring the balloon device.
pub mod balloon;
/// Wrapper for configuring the microVM boot source.
pub mod boot_source;
/// Wrapper for configuring the block devices.
pub mod drive;
/// Wrapper for configuring the entropy device attached to the microVM.
pub mod entropy;
/// Wrapper over hotplug configuration.
#[cfg(target_arch = "x86_64")]
pub mod hotplug;
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

    fn try_into(self) -> Result<RateLimiter, Self::Error> {
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
    /// [`Option<T>`] already implements [`From<T>`] so we have to use a custom
    /// one.
    pub fn into_option(self) -> Option<RateLimiterConfig> {
        if self.bandwidth.is_some() || self.ops.is_some() {
            Some(self)
        } else {
            None
        }
    }
}

/// Create and opens a File for writing to it.
/// In case we open a FIFO, in order to not block the instance if nobody is consuming the message
/// that is flushed to the two pipes, we are opening it with `O_NONBLOCK` flag.
/// In this case, writing to a pipe will start failing when reaching 64K of unconsumed content.
fn open_file_nonblock(path: &Path) -> Result<File, std::io::Error> {
    OpenOptions::new()
        .custom_flags(O_NONBLOCK)
        .read(true)
        .write(true)
        .open(path)
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
