extern crate time;
extern crate timerfd;

use self::timerfd::{SetTimeFlags, TimerFd, TimerState};
use std::io::Result as IoResult;
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::Duration;

// interval at which the refill timer will run when limiter is at capacity
const REFILL_TIMER_INTERVAL_MS: u64 = 100;

// Euclid's two-thousand-year-old algorithm for finding the greatest common divisor.
fn gcd(x: u64, y: u64) -> u64 {
    let mut x = x;
    let mut y = y;
    while y != 0 {
        let t = y;
        y = x % y;
        x = t;
    }
    x
}

struct TokenBucket {
    // bucket defining traits
    total_capacity: u64,

    // internal state
    budget: u64,
    last_update: u64,

    // fields used for pre-processing optimizations
    processed_capacity: u64,
    processed_refill_time: u64,
}

impl TokenBucket {
    /// Creates a TokenBucket
    ///  @total_capacity: the total capacity of the token bucket
    ///  @complete_refill_time_ms: number of milliseconds for the token bucket to
    ///                            go from zero tokens to total capacity.
    pub fn new(total_capacity: u64, complete_refill_time_ms: u64) -> Self {
        // each 'time_delta' nanoseconds the bucket should refill with:
        //     count_tokens = (time_delta * total_capacity) / (complete_refill_time_ms * 1_000_000)

        // pre-process some fields to make the formula work with smaller numbers:

        // get the greatest common factor between total_capacity and complete_refill_time_ms
        let common_factor = gcd(total_capacity, complete_refill_time_ms);
        // will be exact division since common_factor is a factor of total_capacity
        let mut processed_capacity: u64 = total_capacity / common_factor;
        // will be exact division since common_factor is a factor of complete_refill_time_ms
        let mut processed_refill_time: u64 = complete_refill_time_ms / common_factor;

        let nanoseconds_in_one_millisecond = 1_000_000;
        // get the gcd between processed_capacity and nanoseconds_in_one_millisecond
        let common_factor = gcd(processed_capacity, nanoseconds_in_one_millisecond);
        // process/reduce the capacity factor even further
        processed_capacity /= common_factor;
        // processed_refill_time was ms; turn to nanoseconds and reduce by common_factor
        processed_refill_time *= nanoseconds_in_one_millisecond / common_factor;

        TokenBucket {
            total_capacity,
            // start off full
            budget: total_capacity,
            // last updated is now
            last_update: time::precise_time_ns(),
            // preprocessed capacity and refill time to make them smaller while keeping the ratio
            processed_capacity,
            processed_refill_time,
        }
    }

    /// Resets the token bucket: budget set to max capacity and last-updated set to now
    fn reset(&mut self) {
        self.budget = self.total_capacity;
        self.last_update = time::precise_time_ns();
    }

    // TODO (Issue #259): handle cases where a single request is larger than the full capacity
    // for such cases we need to support partial fulfilment of requests
    fn reduce(&mut self, tokens: u64) -> bool {
        let now = time::precise_time_ns();
        let time_delta = now - self.last_update;

        self.last_update = now;
        self.budget += (time_delta * self.processed_capacity) / self.processed_refill_time;

        if self.budget >= self.total_capacity {
            self.reset();
        }

        if tokens > self.budget {
            // if not enough tokens consume() fails, return false
            return false;
        }

        // use up tokens
        self.budget -= tokens;
        // consume() succeeded
        true
    }
}

pub enum TokenType {
    Bytes,
    Ops,
}

/// Rate Limiter that works on both bandwidth and ops/s limiting;
/// bytes/s and ops/s limiting can be used at the same time or individually.
/// Implementation uses a single timer through TimerFd to refresh either or
/// both token buckets.
///
/// Its internal buckets are 'passively' replenished as they're being used (as
/// part of consume() operations).
/// A timer is enabled and used to 'actively' replenish the token buckets when
/// limiting is in effect and consume() operations are disabled.
pub struct RateLimiter {
    bytes_token_bucket: Option<TokenBucket>,
    ops_token_bucket: Option<TokenBucket>,
    timer_fd: Option<TimerFd>,
    // internal flag to quickly determine timer state
    timer_active: bool,
    // cache the target state of the timer to avoid computing it over and over
    timer_future_state: TimerState,
}

impl RateLimiter {
    /// Creates a new Rate Limiter that can limit on both bytes/s and ops/s.
    /// If either bytes/ops capacity or refill_time are 0, the limiter is 'disabled'
    /// on that respective token type
    pub fn new(
        bytes_total_capacity: u64,
        bytes_complete_refill_time_ms: u64,
        ops_total_capacity: u64,
        ops_complete_refill_time_ms: u64,
    ) -> IoResult<Self> {
        // if either bytes token bucket capacity or refill time is 0, disable limiting on bytes/s
        let bytes_token_bucket = if bytes_total_capacity != 0 && bytes_complete_refill_time_ms != 0
        {
            Some(TokenBucket::new(
                bytes_total_capacity,
                bytes_complete_refill_time_ms,
            ))
        } else {
            None
        };

        // if either ops token bucket capacity or refill time is 0, disable limiting on ops/s
        let ops_token_bucket = if ops_total_capacity != 0 && ops_complete_refill_time_ms != 0 {
            Some(TokenBucket::new(
                ops_total_capacity,
                ops_complete_refill_time_ms,
            ))
        } else {
            None
        };

        // if limiting is disabled on all token types, don't even create a timer fd
        let timer_fd = if bytes_token_bucket.is_some() || ops_token_bucket.is_some() {
            Some(TimerFd::new()?)
        } else {
            None
        };

        Ok(RateLimiter {
            bytes_token_bucket,
            ops_token_bucket,
            timer_fd,
            timer_active: false,
            // cache this instead of building it each time
            timer_future_state: TimerState::Oneshot(Duration::from_millis(
                REFILL_TIMER_INTERVAL_MS,
            )),
        })
    }

    /// Attempts to consume tokens and returns whether that is possible
    pub fn consume(&mut self, tokens: u64, token_type: TokenType) -> bool {
        // identify the required token bucket
        let token_bucket = match token_type {
            TokenType::Bytes => self.bytes_token_bucket.as_mut(),
            TokenType::Ops => self.ops_token_bucket.as_mut(),
        };
        // try to consume from the token bucket
        let success = match token_bucket {
            Some(bucket) => bucket.reduce(tokens),
            // if bucket is not present rate limiting is disabled on token type,
            // consume() will always succeed.
            None => true,
        };
        // when we report budget is over, there will be no further calls here,
        // register a timer to replenish the bucket and resume processing;
        // make sure there is only one running timer for this limiter
        if !success && !self.timer_active {
            // register the timer; don't care about its previous state
            // safe to unwrap: timer is definitely Some() since we have a bucket
            let _ = self.timer_fd
                .as_mut()
                .unwrap()
                .set_state(self.timer_future_state.clone(), SetTimeFlags::Default);
            self.timer_active = true;
        }
        success
    }

    /// Returns whether this rate limiter is blocked.
    /// The limiter 'blocks' when a consume() operation fails because there is not enough
    /// budget for it. The internal timer will 'unblock' it when it expires.
    pub fn is_blocked(&self) -> bool {
        self.timer_active
    }

    /// This function needs to be called every time there is an event on the
    /// FD provided by this object's AsRawFd trait implementation.
    pub fn event_handler(&mut self) {
        self.timer_active = false;
        match self.timer_fd.as_mut() {
            Some(timer_fd) => {
                let _ = timer_fd.read();
            }
            None => {
                warn!("Rate limiter event handler called without a present timer");
            }
        };
    }
}

impl AsRawFd for RateLimiter {
    /// Provides a FD which needs to be monitored for POLLIN events;
    /// this object's .event_handler() must be called on such events.
    ///
    /// Will return a negative value if rate limiter is disabled.
    fn as_raw_fd(&self) -> RawFd {
        match self.timer_fd.as_ref() {
            Some(timer_fd) => timer_fd.as_raw_fd(),
            None => -1,
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        // safe to unwrap since this will not attempt to create timer_fd
        RateLimiter::new(0, 0, 0, 0).unwrap()
    }
}
