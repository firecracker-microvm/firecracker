// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-callsite rate limiter for logging, reusing the existing `TokenBucket`
//! implementation. Each macro invocation site gets its own independent
//! `LogRateLimiter` instance via a `static`, so flooding one callsite does
//! not suppress unrelated log messages.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::logger::{IncMetric, METRICS};
use crate::rate_limiter::TokenBucket;

/// Maximum number of messages allowed per refill period.
pub const DEFAULT_BURST: u64 = 10;

/// Refill period in milliseconds (5 seconds).
pub const DEFAULT_REFILL_TIME_MS: u64 = 5000;

/// Per-callsite rate limiter wrapping a `TokenBucket` in a `Mutex`.
///
/// Uses `OnceLock` for lazy initialization since `TokenBucket::new()`
/// is not `const` (it calls `Instant::now()`).
#[derive(Debug)]
pub struct LogRateLimiter {
    inner: OnceLock<Mutex<TokenBucket>>,
    burst: u64,
    refill_time_ms: u64,
    suppressed: AtomicU64,
}

impl Default for LogRateLimiter {
    fn default() -> Self {
        Self::new(DEFAULT_BURST, DEFAULT_REFILL_TIME_MS)
    }
}

impl LogRateLimiter {
    /// Create a new uninitialized rate limiter with the given
    /// burst capacity and refill period.
    ///
    /// This is `const` so it can be used in `static` declarations.
    /// The inner `TokenBucket` is lazily initialized on first use.
    pub const fn new(burst: u64, refill_time_ms: u64) -> Self {
        Self {
            inner: OnceLock::new(),
            burst,
            refill_time_ms,
            suppressed: AtomicU64::new(0),
        }
    }

    /// Check whether a message should be emitted.
    ///
    /// Returns `true` if the message should be logged, `false` if
    /// it should be suppressed.
    pub fn check(&self) -> bool {
        let mutex = self.inner.get_or_init(|| {
            Mutex::new(
                TokenBucket::new(self.burst, 0, self.refill_time_ms)
                    .expect("invalid rate limiter configuration"),
            )
        });
        let mut bucket = mutex.lock().expect("rate limiter lock poisoned");
        matches!(
            bucket.reduce(1),
            crate::rate_limiter::BucketReduction::Success
        )
    }

    /// Check if log is should be emitted and print a warning if it was
    /// suppressed before. Marked to be never inlined since it is called in a
    /// lot of macros and would blow up the binary size otherwise.
    #[inline(never)]
    pub fn check_maybe_suppressed(&self) -> bool {
        if self.check() {
            let suppressed = self.suppressed.swap(0, Ordering::Relaxed);
            if 0 < suppressed {
                crate::logger::warn_unrestricted!(
                    "{suppressed} messages were suppressed due to rate limiting"
                );
            }
            true
        } else {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            METRICS.logger.rate_limited_log_count.inc();
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_burst_capacity_enforcement() {
        let limiter = LogRateLimiter::default();

        // First DEFAULT_BURST calls should be allowed.
        for _ in 0..DEFAULT_BURST {
            assert!(limiter.check(), "expected allow within burst");
        }

        // The next call should be suppressed.
        assert!(!limiter.check(), "expected suppress after burst");
        assert!(!limiter.check(), "expected suppress after burst");
    }

    #[test]
    fn test_callsite_independence() {
        let limiter_a = LogRateLimiter::default();
        let limiter_b = LogRateLimiter::default();

        // Exhaust limiter_a.
        for _ in 0..DEFAULT_BURST {
            limiter_a.check();
        }
        assert!(!limiter_a.check());

        // limiter_b should be unaffected.
        assert!(limiter_b.check());
    }

    #[test]
    fn test_refill_after_time() {
        // Use a short refill period to avoid slow tests.
        const TEST_BURST: u64 = 2;
        const TEST_REFILL_MS: u64 = 100;
        let limiter = LogRateLimiter::new(TEST_BURST, TEST_REFILL_MS);

        // Exhaust burst.
        for _ in 0..TEST_BURST {
            limiter.check();
        }
        assert!(!limiter.check());

        // Wait for refill.
        std::thread::sleep(std::time::Duration::from_millis(TEST_REFILL_MS * 2));
        assert!(limiter.check(), "expected allow after refill");
    }
}
