// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use rate_limiter::{RateLimiter, TokenBucket};
use std::io;

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
/// Wrapper for configuring the network devices attached to the microVM.
pub mod net;
#[cfg(feature = "vsock")]
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

impl TokenBucketConfig {
    /// Convert the stateless `self` into a live `TokenBucket` object.
    pub fn into_token_bucket(self) -> TokenBucket {
        // This would look nicer if we were to implement `Into<TokenBucket>` (or, more generally,
        // `Into<LiveCounterpart>`), but some constructors may fail, and until `TryInto` makes into
        // the stable channel, we'll settle for the unenforceable convention of implementing
        // an `into_<live_counterpart>()` member for these stateless structures.
        TokenBucket::new(self.size, self.one_time_burst, self.refill_time)
    }
}

/// A public-facing, stateless structure, holding all the data we need to create a RateLimiter
/// (live) object.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq)]
pub struct RateLimiterConfig {
    /// Data used to initialize the RateLimiter::bandwidth bucket.
    pub bandwidth: Option<TokenBucketConfig>,
    /// Data used to initialize the RateLimiter::ops bucket.
    pub ops: Option<TokenBucketConfig>,
}

impl RateLimiterConfig {
    /// Convert the stateless `self` into a live `RateLimiter` object.
    pub fn into_rate_limiter(self) -> Result<RateLimiter, io::Error> {
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
    /// Updates the configuration, merging in new options from `new_config`.
    pub fn update(&mut self, new_config: &RateLimiterConfig) {
        if new_config.bandwidth.is_some() {
            self.bandwidth = new_config.bandwidth;
        }
        if new_config.ops.is_some() {
            self.ops = new_config.ops;
        }
    }
}
