// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the structures needed for saving/restoring a RateLimiter.

use super::*;
use snapshot::Persist;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;

/// State for saving a TokenBucket.
#[derive(Versionize)]
pub struct TokenBucketState {
    size: u64,
    one_time_burst: u64,
    refill_time: u64,
    budget: u64,
    elapsed_ns: u64,
}

impl Persist<'_> for TokenBucket {
    type State = TokenBucketState;
    type ConstructorArgs = ();
    type Error = io::Error;

    fn save(&self) -> Self::State {
        TokenBucketState {
            size: self.size,
            one_time_burst: self.one_time_burst,
            refill_time: self.refill_time,
            budget: self.budget,
            elapsed_ns: self.last_update.elapsed().as_nanos() as u64,
        }
    }

    fn restore(_: Self::ConstructorArgs, state: &Self::State) -> Result<Self, Self::Error> {
        let now = Instant::now();
        let last_update = now
            .checked_sub(Duration::from_nanos(state.elapsed_ns))
            .unwrap_or(now);

        let mut token_bucket =
            TokenBucket::new(state.size, state.one_time_burst, state.refill_time)
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;

        token_bucket.budget = state.budget;
        token_bucket.last_update = last_update;

        Ok(token_bucket)
    }
}

/// State for saving a RateLimiter.
#[derive(Versionize)]
pub struct RateLimiterState {
    ops: Option<TokenBucketState>,
    bandwidth: Option<TokenBucketState>,
}

impl Persist<'_> for RateLimiter {
    type State = RateLimiterState;
    type ConstructorArgs = ();
    type Error = io::Error;

    fn save(&self) -> Self::State {
        RateLimiterState {
            ops: self.ops.as_ref().map(|ops| ops.save()),
            bandwidth: self.bandwidth.as_ref().map(|bw| bw.save()),
        }
    }

    fn restore(_: Self::ConstructorArgs, state: &Self::State) -> Result<Self, Self::Error> {
        let rate_limiter = RateLimiter {
            // Safe to unwrap because TokenBucket::restore doesn't return errors.
            ops: state
                .ops
                .as_ref()
                .map(|ops| TokenBucket::restore((), ops).unwrap()),
            bandwidth: state
                .bandwidth
                .as_ref()
                .map(|bw| TokenBucket::restore((), bw).unwrap()),
            timer_fd: TimerFd::new_custom(ClockId::Monotonic, true, true)?,
            timer_active: false,
        };

        Ok(rate_limiter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket_persistence() {
        let mut tb = TokenBucket::new(1000, 2000, 3000).unwrap();

        // Check that TokenBucket restores correctly if untouched.
        let restored_tb = TokenBucket::restore((), &tb.save()).unwrap();
        assert!(tb.partial_eq(&restored_tb));

        // Check that TokenBucket restores correctly after partially consuming tokens.
        tb.reduce(100);
        let restored_tb = TokenBucket::restore((), &tb.save()).unwrap();
        assert!(tb.partial_eq(&restored_tb));

        // Check that TokenBucket restores correctly after replenishing tokens.
        tb.replenish(100);
        let restored_tb = TokenBucket::restore((), &tb.save()).unwrap();
        assert!(tb.partial_eq(&restored_tb));

        // Test serialization.
        let mut mem = vec![0; 4096];
        let version_map = VersionMap::new();
        tb.save()
            .serialize(&mut mem.as_mut_slice(), &version_map, 1)
            .unwrap();

        let restored_tb = TokenBucket::restore(
            (),
            &TokenBucketState::deserialize(&mut mem.as_slice(), &version_map, 1).unwrap(),
        )
        .unwrap();
        assert!(tb.partial_eq(&restored_tb));
    }

    #[test]
    fn test_rate_limiter_persistence() {
        let refill_time = 100_000;
        let mut rate_limiter = RateLimiter::new(100, 0, refill_time, 10, 0, refill_time).unwrap();

        // Check that RateLimiter restores correctly if untouched.
        let restored_rate_limiter =
            RateLimiter::restore((), &rate_limiter.save()).expect("Unable to restore rate limiter");

        assert!(rate_limiter
            .ops()
            .unwrap()
            .partial_eq(&restored_rate_limiter.ops().unwrap()));
        assert!(rate_limiter
            .bandwidth()
            .unwrap()
            .partial_eq(&restored_rate_limiter.bandwidth().unwrap()));
        assert_eq!(
            restored_rate_limiter.timer_fd.get_state(),
            TimerState::Disarmed
        );

        // Check that RateLimiter restores correctly after partially consuming tokens.
        rate_limiter.consume(10, TokenType::Bytes);
        rate_limiter.consume(10, TokenType::Ops);
        let restored_rate_limiter =
            RateLimiter::restore((), &rate_limiter.save()).expect("Unable to restore rate limiter");

        assert!(rate_limiter
            .ops()
            .unwrap()
            .partial_eq(&restored_rate_limiter.ops().unwrap()));
        assert!(rate_limiter
            .bandwidth()
            .unwrap()
            .partial_eq(&restored_rate_limiter.bandwidth().unwrap()));
        assert_eq!(
            restored_rate_limiter.timer_fd.get_state(),
            TimerState::Disarmed
        );

        // Check that RateLimiter restores correctly after totally consuming tokens.
        rate_limiter.consume(1000, TokenType::Bytes);
        let restored_rate_limiter =
            RateLimiter::restore((), &rate_limiter.save()).expect("Unable to restore rate limiter");

        assert!(rate_limiter
            .ops()
            .unwrap()
            .partial_eq(&restored_rate_limiter.ops().unwrap()));
        assert!(rate_limiter
            .bandwidth()
            .unwrap()
            .partial_eq(&restored_rate_limiter.bandwidth().unwrap()));

        // Test serialization.
        let mut mem = vec![0; 4096];
        let version_map = VersionMap::new();
        rate_limiter
            .save()
            .serialize(&mut mem.as_mut_slice(), &version_map, 1)
            .unwrap();
        let restored_rate_limiter = RateLimiter::restore(
            (),
            &RateLimiterState::deserialize(&mut mem.as_slice(), &version_map, 1).unwrap(),
        )
        .unwrap();

        assert!(rate_limiter
            .ops()
            .unwrap()
            .partial_eq(&restored_rate_limiter.ops().unwrap()));
        assert!(rate_limiter
            .bandwidth()
            .unwrap()
            .partial_eq(&restored_rate_limiter.bandwidth().unwrap()));
    }
}
