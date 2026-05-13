// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-callsite, lock-free rate limiter for logging.
//!
//! Each macro invocation site gets its own independent `LogRateLimiter`
//! instance via a `static`, so flooding one callsite does not suppress
//! unrelated log messages.
//!
//! # Algorithm
//!
//! Generic Cell Rate Algorithm (GCRA), stored in a single `AtomicU64`:
//!
//! ```text
//! bit 63                                                    bit 0
//!  ┌───────────────────┬────────────────────────────────────────┐
//!  │  suppressed (24)  │              tat_ms (40)               │
//!  └───────────────────┴────────────────────────────────────────┘
//! ```
//!
//! - `tat_ms`: theoretical arrival time, ms since process epoch.
//!   40 bits ≈ 34 years before wrap.
//! - `suppressed`: saturating count of denied calls awaiting a
//!   "messages were suppressed" report (max 16 777 215).
//!
//! On each call: `earliest = max(tat, now)`, `new_tat = earliest + T`
//! where `T = REFILL_MS / BURST`. Deny if `new_tat - now > REFILL_MS`,
//! otherwise CAS-advance `tat`. Equivalent to a token-bucket of capacity
//! `BURST` refilling `BURST` tokens per `REFILL_MS`.
//!
//! For the default config (`BURST = 10`, `REFILL_MS = 5000`):
//! `T = 500 ms`/token. After a cold start the bucket allows 10 calls
//! back-to-back, then one call every 500 ms thereafter.
//!
//! Guest-triggerable log paths **must** use the rate-limited macros
//! (`error!`, `warn!`, `info!`) to prevent log flooding. Reserve
//! `*_unrestricted!` for host-only paths (startup, snapshot save/
//! restore).

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crate::logger::{IncMetric, METRICS};

/// Maximum number of messages allowed per refill period.
pub const DEFAULT_BURST: u64 = 10;

/// Refill period in milliseconds (5 seconds).
pub const DEFAULT_REFILL_TIME_MS: u64 = 5000;

/// Process-wide reference point for `tat_ms`.
static EPOCH: OnceLock<Instant> = OnceLock::new();

/// Returns ms since the process epoch.
#[inline]
fn now_ms_since_epoch() -> u64 {
    let epoch = *EPOCH.get_or_init(Instant::now);
    let d = Instant::now().saturating_duration_since(epoch);
    d.as_secs() * 1_000 + u64::from(d.subsec_millis())
}

/// Per-callsite, lock-free rate limiter parameterised on burst capacity
/// and refill window. See [module docs](self) for the state layout.
#[derive(Debug)]
pub struct LogRateLimiter<const BURST: u64, const REFILL_MS: u64> {
    state: AtomicU64,
}

/// Convenience alias for the default-configured rate limiter, used by
/// the rate-limited log macros (10 messages per 5-second window).
pub type DefaultLogRateLimiter = LogRateLimiter<DEFAULT_BURST, DEFAULT_REFILL_TIME_MS>;

impl<const BURST: u64, const REFILL_MS: u64> Default for LogRateLimiter<BURST, REFILL_MS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const BURST: u64, const REFILL_MS: u64> LogRateLimiter<BURST, REFILL_MS> {
    /// Width of the `tat_ms` field in the packed state.
    const TAT_BITS: u32 = 40;

    /// Mask covering `tat_ms` (low bits).
    const TAT_MASK: u64 = (1u64 << Self::TAT_BITS) - 1;

    /// Maximum value the `suppressed` field can hold; further increments
    /// saturate at this value.
    const MAX_SUPPRESSED: u64 = u64::MAX >> Self::TAT_BITS;

    /// CAS-retry cap. Bounds pathological scheduler-induced livelock;
    /// on overflow the call is denied and the suppression metric bumped.
    const CAS_RETRY_LIMIT: u32 = 16;

    /// Milliseconds it takes to issue one token (the inter-token period).
    /// Validated at const-eval time: refusing to compile callsites that
    /// would round to 0 ms/token under integer division.
    const PERIOD_PER_TOKEN_MS: u64 = {
        assert!(BURST > 0, "LogRateLimiter BURST must be > 0");
        assert!(REFILL_MS > 0, "LogRateLimiter REFILL_MS must be > 0");
        let v = REFILL_MS / BURST;
        assert!(
            v > 0,
            "LogRateLimiter: REFILL_MS / BURST must yield at least 1 ms/token"
        );
        v
    };

    /// Maximum permitted "deficit" of the bucket — the largest gap
    /// between `tat` and `now` we accept before denying a call.
    /// Equal to `REFILL_MS`.
    const MAX_DEFICIT_MS: u64 = REFILL_MS;

    /// Pack `(tat_ms, suppressed)` into a single 64-bit state word.
    /// `suppressed` is saturated to `MAX_SUPPRESSED`.
    #[inline]
    const fn pack(tat_ms: u64, suppressed: u64) -> u64 {
        let s = if suppressed > Self::MAX_SUPPRESSED {
            Self::MAX_SUPPRESSED
        } else {
            suppressed
        };
        (s << Self::TAT_BITS) | (tat_ms & Self::TAT_MASK)
    }

    /// Unpack a 64-bit state word into `(tat_ms, suppressed)`.
    #[inline]
    const fn unpack(state: u64) -> (u64, u64) {
        (state & Self::TAT_MASK, state >> Self::TAT_BITS)
    }

    /// Create a fresh rate limiter. `const`-callable so it can appear in
    /// `static` declarations.
    pub const fn new() -> Self {
        // Force monomorphisation of the const-asserts above.
        let _ = Self::PERIOD_PER_TOKEN_MS;
        let _ = Self::MAX_DEFICIT_MS;
        Self {
            state: AtomicU64::new(0),
        }
    }

    /// Check if a log should be emitted, atomically updating both the
    /// token-bucket state and the suppressed counter.
    ///
    /// On allow: clears `suppressed` and emits a one-shot warning if
    /// any messages were suppressed since the last allowed emit.
    /// On deny: increments `suppressed` (saturating) and bumps the
    /// global `rate_limited_log_count` metric.
    #[inline(never)]
    pub fn check_maybe_suppressed(&self) -> bool {
        let now_ms = now_ms_since_epoch();
        for _ in 0..Self::CAS_RETRY_LIMIT {
            let state = self.state.load(Ordering::Relaxed);
            let (tat_ms, suppressed) = Self::unpack(state);

            let earliest = tat_ms.max(now_ms);
            let new_tat_ms = earliest.saturating_add(Self::PERIOD_PER_TOKEN_MS);

            let denied = new_tat_ms.saturating_sub(now_ms) > Self::MAX_DEFICIT_MS;
            let new_state = if denied {
                Self::pack(tat_ms, suppressed.saturating_add(1))
            } else {
                Self::pack(new_tat_ms, 0)
            };

            if self
                .state
                .compare_exchange_weak(state, new_state, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                if denied {
                    METRICS.logger.rate_limited_log_count.inc();
                } else if suppressed > 0 {
                    crate::logger::warn_unrestricted!(
                        "{suppressed} messages were suppressed due to rate limiting"
                    );
                }
                return !denied;
            }
        }
        METRICS.logger.rate_limited_log_count.inc();
        false
    }

    #[cfg(test)]
    fn suppressed_count(&self) -> u64 {
        Self::unpack(self.state.load(Ordering::Relaxed)).1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Limiter = DefaultLogRateLimiter;

    #[test]
    fn test_burst_capacity_enforcement() {
        let limiter = Limiter::default();

        for _ in 0..DEFAULT_BURST {
            assert!(limiter.check_maybe_suppressed());
        }
        assert!(!limiter.check_maybe_suppressed());
        assert!(!limiter.check_maybe_suppressed());
    }

    #[test]
    fn test_callsite_independence() {
        let limiter_a = Limiter::default();
        let limiter_b = Limiter::default();

        for _ in 0..DEFAULT_BURST {
            limiter_a.check_maybe_suppressed();
        }
        assert!(!limiter_a.check_maybe_suppressed());
        assert!(limiter_b.check_maybe_suppressed());
    }

    #[test]
    fn test_refill_after_time() {
        const TEST_BURST: u64 = 2;
        const TEST_REFILL_MS: u64 = 100;
        let limiter: LogRateLimiter<TEST_BURST, TEST_REFILL_MS> = LogRateLimiter::new();

        for _ in 0..TEST_BURST {
            assert!(limiter.check_maybe_suppressed());
        }
        assert!(!limiter.check_maybe_suppressed());

        std::thread::sleep(std::time::Duration::from_millis(TEST_REFILL_MS * 2));
        assert!(limiter.check_maybe_suppressed());
    }

    #[test]
    fn test_check_maybe_suppressed_increments_metric() {
        let limiter = Limiter::default();
        let baseline = METRICS.logger.rate_limited_log_count.count();

        for _ in 0..DEFAULT_BURST {
            assert!(limiter.check_maybe_suppressed());
        }
        assert_eq!(METRICS.logger.rate_limited_log_count.count(), baseline);

        for _ in 0..3 {
            assert!(!limiter.check_maybe_suppressed());
        }
        assert_eq!(METRICS.logger.rate_limited_log_count.count(), baseline + 3);
    }

    #[test]
    fn test_check_maybe_suppressed_state_machine() {
        const TEST_BURST: u64 = 1;
        const TEST_REFILL_MS: u64 = 50;
        let limiter: LogRateLimiter<TEST_BURST, TEST_REFILL_MS> = LogRateLimiter::new();

        assert!(limiter.check_maybe_suppressed());
        assert!(!limiter.check_maybe_suppressed());
        assert_eq!(limiter.suppressed_count(), 1);

        std::thread::sleep(std::time::Duration::from_millis(TEST_REFILL_MS * 2));
        assert!(limiter.check_maybe_suppressed());
        assert_eq!(limiter.suppressed_count(), 0);
    }

    #[test]
    fn test_suppressed_saturates_at_max() {
        // Inject a near-saturated state to avoid 16M real denies.
        type Tight = LogRateLimiter<1, 100>;
        let limiter = Tight::new();

        assert!(limiter.check_maybe_suppressed());
        let (tat_ms, _) = Tight::unpack(limiter.state.load(Ordering::Relaxed));
        limiter.state.store(
            Tight::pack(tat_ms, Tight::MAX_SUPPRESSED - 1),
            Ordering::Relaxed,
        );

        for _ in 0..5 {
            assert!(!limiter.check_maybe_suppressed());
        }
        assert_eq!(limiter.suppressed_count(), Tight::MAX_SUPPRESSED);
    }

    #[test]
    fn test_pack_unpack_roundtrip() {
        type L = DefaultLogRateLimiter;
        let cases: &[(u64, u64)] = &[
            (0, 0),
            (1, 0),
            (0, 1),
            (123_456_789, 42),
            (L::TAT_MASK, 0),
            (0, L::MAX_SUPPRESSED),
            (L::TAT_MASK, L::MAX_SUPPRESSED),
        ];
        for &(tat, sup) in cases {
            let (tat_back, sup_back) = L::unpack(L::pack(tat, sup));
            assert_eq!(tat_back, tat);
            assert_eq!(sup_back, sup);
        }
        let saturated = L::pack(0, L::MAX_SUPPRESSED + 1);
        assert_eq!(L::unpack(saturated).1, L::MAX_SUPPRESSED);
    }
}
