// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::convert::{From, TryInto};
use std::io;

use serde::de::DeserializeOwned;
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
/// Wrapper over the microVM general information attached to the microVM.
pub mod instance_info;
/// Wrapper for configuring the memory and CPU of the microVM.
pub mod machine_config;
/// Wrapper for configuring memory hotplug.
pub mod memory_hotplug;
/// Wrapper for configuring the metrics.
pub mod metrics;
/// Wrapper for configuring the MMDS.
pub mod mmds;
/// Wrapper for configuring the network devices attached to the microVM.
pub mod net;
/// Wrapper for configuring the pmem devises attached to the microVM.
pub mod pmem;
/// Wrapper for configuring microVM snapshots and the microVM state.
pub mod serial;
pub mod snapshot;
/// Wrapper for configuring the vsock devices attached to the microVM.
pub mod vsock;

/// Marker trait for stateless payloads that can be sent through the VMM API without
/// carrying live state.
pub trait StatelessArgs: DeserializeOwned + Send + Sync + 'static {}

impl<T> StatelessArgs for T where T: DeserializeOwned + Send + Sync + 'static {}

/// Tuple-like wrapper pairing a VMM entrypoint with stateless arguments.
#[derive(Debug)]
pub struct VmmActionPayload<F, A> {
    /// Function/closure that acts as the VMM entrypoint.
    pub entrypoint: F,
    /// Stateless arguments forwarded to the entrypoint.
    pub args: A,
}

impl<F, A> VmmActionPayload<F, A> {
    /// Creates a new payload pairing an entrypoint with its arguments.
    #[inline]
    pub fn new(entrypoint: F, args: A) -> Self {
        Self { entrypoint, args }
    }
}

impl<F, A, R> VmmActionPayload<F, A>
where
    F: FnOnce(A) -> R,
    A: StatelessArgs,
{
    /// Dispatches the entrypoint with the provided stateless arguments.
    #[inline]
    pub fn dispatch(self) -> R {
        (self.entrypoint)(self.args)
    }
}

/// A public-facing, stateless structure, holding all the data we need to create a TokenBucket
/// (live) object.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct TokenBucketSpec {
    /// See TokenBucket::size.
    pub size: u64,
    /// See TokenBucket::one_time_burst.
    pub one_time_burst: Option<u64>,
    /// See TokenBucket::refill_time.
    pub refill_time: u64,
}

impl From<&TokenBucket> for TokenBucketSpec {
    fn from(tb: &TokenBucket) -> Self {
        let one_time_burst = match tb.initial_one_time_burst() {
            0 => None,
            v => Some(v),
        };
        TokenBucketSpec {
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
pub struct RateLimiterSpec {
    /// Data used to initialize the RateLimiter::bandwidth bucket.
    pub bandwidth: Option<TokenBucketSpec>,
    /// Data used to initialize the RateLimiter::ops bucket.
    pub ops: Option<TokenBucketSpec>,
}

/// A public-facing, stateless structure, specifying RateLimiter properties updates.
#[derive(Debug)]
pub struct RateLimiterUpdate {
    /// Possible update to the RateLimiter::bandwidth bucket.
    pub bandwidth: BucketUpdate,
    /// Possible update to the RateLimiter::ops bucket.
    pub ops: BucketUpdate,
}

fn get_bucket_update(tb_spec: &Option<TokenBucketSpec>) -> BucketUpdate {
    match tb_spec {
        // There is data to update.
        Some(tb_spec) => {
            TokenBucket::new(
                tb_spec.size,
                tb_spec.one_time_burst.unwrap_or(0),
                tb_spec.refill_time,
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

impl From<Option<RateLimiterSpec>> for RateLimiterUpdate {
    fn from(spec: Option<RateLimiterSpec>) -> Self {
        if let Some(spec) = spec {
            RateLimiterUpdate {
                bandwidth: get_bucket_update(&spec.bandwidth),
                ops: get_bucket_update(&spec.ops),
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

impl TryInto<RateLimiter> for RateLimiterSpec {
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

impl From<&RateLimiter> for RateLimiterSpec {
    fn from(rl: &RateLimiter) -> Self {
        RateLimiterSpec {
            bandwidth: rl.bandwidth().map(TokenBucketSpec::from),
            ops: rl.ops().map(TokenBucketSpec::from),
        }
    }
}

impl RateLimiterSpec {
    /// [`Option<T>`] already implements [`From<T>`] so we have to use a custom
    /// one.
    pub fn into_option(self) -> Option<RateLimiterSpec> {
        if self.bandwidth.is_some() || self.ops.is_some() {
            Some(self)
        } else {
            None
        }
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
        let rl_spec = RateLimiterSpec {
            bandwidth: Some(TokenBucketSpec {
                size: SIZE,
                one_time_burst: Some(ONE_TIME_BURST),
                refill_time: REFILL_TIME,
            }),
            ops: Some(TokenBucketSpec {
                size: SIZE * 2,
                one_time_burst: None,
                refill_time: REFILL_TIME * 2,
            }),
        };
        let rl: RateLimiter = rl_spec.try_into().unwrap();
        assert_eq!(rl.bandwidth().unwrap().capacity(), SIZE);
        assert_eq!(rl.bandwidth().unwrap().one_time_burst(), ONE_TIME_BURST);
        assert_eq!(rl.bandwidth().unwrap().refill_time_ms(), REFILL_TIME);
        assert_eq!(rl.ops().unwrap().capacity(), SIZE * 2);
        assert_eq!(rl.ops().unwrap().one_time_burst(), 0);
        assert_eq!(rl.ops().unwrap().refill_time_ms(), REFILL_TIME * 2);
    }

    #[test]
    fn test_generate_configs() {
        let bw_tb_spec = TokenBucketSpec {
            size: SIZE,
            one_time_burst: Some(ONE_TIME_BURST),
            refill_time: REFILL_TIME,
        };
        let bw_tb = TokenBucket::new(SIZE, ONE_TIME_BURST, REFILL_TIME).unwrap();
        let generated_bw_tb_spec = TokenBucketSpec::from(&bw_tb);
        assert_eq!(generated_bw_tb_spec, bw_tb_spec);

        let rl_spec = RateLimiterSpec {
            bandwidth: Some(bw_tb_spec),
            ops: None,
        };
        let rl: RateLimiter = rl_spec.try_into().unwrap();
        let generated_rl_spec = RateLimiterSpec::from(&rl);
        assert_eq!(generated_rl_spec, rl_spec);
        assert_eq!(generated_rl_spec.into_option(), Some(rl_spec));
    }
}
