extern crate time;
extern crate timerfd;

use self::timerfd::{ClockId, SetTimeFlags, TimerFd, TimerState};
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::Duration;

pub enum Error {
    SpuriousRateLimiterEvent,
}

// interval at which the refill timer will run when limiter is at capacity
const REFILL_TIMER_INTERVAL_MS: u64 = 100;

const NANOSEC_IN_ONE_MILLISEC: u64 = 1_000_000;

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

        // get the gcd between processed_capacity and NANOSEC_IN_ONE_MILLISEC
        let common_factor = gcd(processed_capacity, NANOSEC_IN_ONE_MILLISEC);
        // process/reduce the capacity factor even further
        processed_capacity /= common_factor;
        // processed_refill_time was ms; turn to nanoseconds and reduce by common_factor
        processed_refill_time *= NANOSEC_IN_ONE_MILLISEC / common_factor;

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

    // TODO (Issue #259): handle cases where a single request is larger than the full capacity
    // for such cases we need to support partial fulfilment of requests
    fn reduce(&mut self, tokens: u64) -> bool {
        let now = time::precise_time_ns();
        let time_delta = now - self.last_update;

        self.last_update = now;
        self.budget += (time_delta * self.processed_capacity) / self.processed_refill_time;

        if self.budget >= self.total_capacity {
            self.budget = self.total_capacity;
        }

        if tokens > self.budget {
            // TODO (Issue #259) remove this block when issue is resolved
            if tokens > self.total_capacity {
                error!(
                    "Trying to consume more tokens {} than the total capacity {}",
                    tokens, self.total_capacity
                );
                // best effort rate-limiting, this is a dirty workaround for Issue #259
                if self.budget == self.total_capacity {
                    self.budget = 0;
                    return true;
                }
            }
            // if not enough tokens consume() fails, return false
            return false;
        }

        // use up tokens
        self.budget -= tokens;
        // consume() succeeded
        true
    }

    /// Adds tokens to bucket
    fn replenish(&mut self, tokens: u64) {
        self.budget = super::std::cmp::min(self.budget + tokens, self.total_capacity);
    }

    /// Resets the token bucket: budget set to max capacity and last-updated set to now
    #[cfg(test)]
    fn reset(&mut self) {
        self.budget = self.total_capacity;
        self.last_update = time::precise_time_ns();
    }

    #[cfg(test)]
    pub fn get_capacity(&self) -> u64 {
        self.total_capacity
    }

    #[cfg(test)]
    pub fn get_current_budget(&self) -> u64 {
        self.budget
    }

    #[cfg(test)]
    pub fn get_last_update(&self) -> u64 {
        self.last_update
    }

    #[cfg(test)]
    pub fn get_processed_capacity(&self) -> u64 {
        self.processed_capacity
    }

    #[cfg(test)]
    pub fn get_processed_refill_time(&self) -> u64 {
        self.processed_refill_time
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
    ) -> io::Result<Self> {
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
            // create TimerFd using monotonic clock, as nonblocking FD and set close-on-exec
            Some(TimerFd::new_custom(ClockId::Monotonic, true, true)?)
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
            self.timer_fd
                .as_mut()
                .unwrap()
                .set_state(self.timer_future_state.clone(), SetTimeFlags::Default);
            self.timer_active = true;
        }
        success
    }

    /// Adds tokens to their respective bucket
    pub fn manual_replenish(&mut self, tokens: u64, token_type: TokenType) {
        // identify the required token bucket
        let token_bucket = match token_type {
            TokenType::Bytes => self.bytes_token_bucket.as_mut(),
            TokenType::Ops => self.ops_token_bucket.as_mut(),
        };
        // add tokens to the token bucket
        if let Some(bucket) = token_bucket {
            bucket.replenish(tokens);
        }
    }

    /// Returns whether this rate limiter is blocked.
    /// The limiter 'blocks' when a consume() operation fails because there is not enough
    /// budget for it. The internal timer will 'unblock' it when it expires.
    pub fn is_blocked(&self) -> bool {
        self.timer_active
    }

    /// This function needs to be called every time there is an event on the
    /// FD provided by this object's AsRawFd trait implementation.
    pub fn event_handler(&mut self) -> Result<(), Error> {
        match self.timer_fd.as_mut() {
            Some(timer_fd) => {
                // read the timer_fd and report error if there was no event
                match timer_fd.read() {
                    0 => {
                        error!("Rate limiter event handler called in the absence of a timer event");
                        Err(Error::SpuriousRateLimiterEvent)
                    }
                    _ => {
                        self.timer_active = false;
                        Ok(())
                    }
                }
            }
            None => {
                error!("Rate limiter event handler called without a present timer");
                Err(Error::SpuriousRateLimiterEvent)
            }
        }
    }

    #[cfg(test)]
    fn get_token_bucket(&self, token_type: TokenType) -> Option<&TokenBucket> {
        match token_type {
            TokenType::Bytes => self.bytes_token_bucket.as_ref(),
            TokenType::Ops => self.ops_token_bucket.as_ref(),
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_token_bucket_create() {
        let before = time::precise_time_ns();
        let tb = TokenBucket::new(1000, 1000);
        assert_eq!(tb.get_capacity(), 1000);
        assert_eq!(tb.get_current_budget(), 1000);
        assert!(tb.get_last_update() >= before);
        assert!(tb.get_last_update() <= time::precise_time_ns());
        assert_eq!(tb.get_processed_capacity(), 1);
        assert_eq!(tb.get_processed_refill_time(), 1_000_000);
    }

    #[test]
    fn test_token_bucket_preprocess() {
        let tb = TokenBucket::new(1000, 1000);
        assert_eq!(tb.get_processed_capacity(), 1);
        assert_eq!(tb.get_processed_refill_time(), NANOSEC_IN_ONE_MILLISEC);

        let thousand = 1000;
        let tb = TokenBucket::new(3 * 7 * 11 * 19 * thousand, 7 * 11 * 13 * 17);
        assert_eq!(tb.get_processed_capacity(), 3 * 19);
        assert_eq!(
            tb.get_processed_refill_time(),
            13 * 17 * (NANOSEC_IN_ONE_MILLISEC / thousand)
        );
    }

    #[test]
    fn test_token_bucket_reduce() {
        // token bucket with capacity 1000 and refill time of 1000 milliseconds
        // allowing rate of 1 token/ms
        let capacity = 1000;
        let refill_ms = 1000;
        let mut tb = TokenBucket::new(capacity, refill_ms as u64);

        assert!(tb.reduce(123));
        assert_eq!(tb.get_current_budget(), capacity - 123);

        thread::sleep(Duration::from_millis(123));
        assert!(tb.reduce(1));
        assert_eq!(tb.get_current_budget(), capacity - 1);
        assert!(tb.reduce(100));
        assert!(!tb.reduce(capacity));

        // token bucket with capacity 1000 and refill time of 1000 milliseconds
        let mut tb = TokenBucket::new(1000, 1000);
        // safely assuming the thread can run these 3 commands in less than 500ms
        assert!(tb.reduce(500));
        assert!(tb.reduce(500));
        assert!(!tb.reduce(500));
        thread::sleep(Duration::from_millis(500));
        assert!(tb.reduce(500));

        let before = time::precise_time_ns();
        tb.reset();
        assert_eq!(tb.get_capacity(), 1000);
        assert_eq!(tb.get_current_budget(), 1000);
        assert!(tb.get_last_update() >= before);
        assert!(tb.get_last_update() <= time::precise_time_ns());
    }

    #[test]
    fn test_rate_limiter_default() {
        let mut l = RateLimiter::default();

        // limiter should not be blocked
        assert!(!l.is_blocked());
        // limiter should be disabled so consume(whatever) should work
        assert!(l.consume(u64::max_value(), TokenType::Ops));
        assert!(l.consume(u64::max_value(), TokenType::Bytes));
        // calling the handler without there having been an event should error
        assert!(l.event_handler().is_err());
        // raw FD for this disabled rate-limiter should be -1
        assert_eq!(l.as_raw_fd(), -1);
    }

    #[test]
    fn test_rate_limiter_manual_replenish() {
        // rate limiter with limit of 1000 bytes/s and 1000 ops/s
        let mut l = RateLimiter::new(1000, 1000, 1000, 1000).unwrap();

        // consume 123 bytes
        assert!(l.consume(123, TokenType::Bytes));
        l.manual_replenish(23, TokenType::Bytes);
        {
            let bytes_tb = l.get_token_bucket(TokenType::Bytes).unwrap();
            assert_eq!(bytes_tb.get_current_budget(), 900);
        }
        // consume 123 ops
        assert!(l.consume(123, TokenType::Ops));
        l.manual_replenish(23, TokenType::Ops);
        {
            let bytes_tb = l.get_token_bucket(TokenType::Ops).unwrap();
            assert_eq!(bytes_tb.get_current_budget(), 900);
        }
    }

    #[test]
    fn test_rate_limiter_bandwidth() {
        // rate limiter with limit of 1000 bytes/s
        let mut l = RateLimiter::new(1000, 1000, 0, 0).unwrap();

        // limiter should not be blocked
        assert!(!l.is_blocked());
        // raw FD for this disabled should be valid
        assert!(l.as_raw_fd() > 0);

        // ops/s limiter should be disabled so consume(whatever) should work
        assert!(l.consume(u64::max_value(), TokenType::Ops));

        // do full 1000 bytes
        assert!(l.consume(1000, TokenType::Bytes));
        // try and fail on another 100
        assert!(!l.consume(100, TokenType::Bytes));
        // since consume failed, limiter should be blocked now
        assert!(l.is_blocked());
        // wait half the timer period
        thread::sleep(Duration::from_millis(REFILL_TIMER_INTERVAL_MS / 2));
        // limiter should still be blocked
        assert!(l.is_blocked());
        // wait the other half of the timer period
        thread::sleep(Duration::from_millis(REFILL_TIMER_INTERVAL_MS / 2));
        // the timer_fd should have an event on it by now
        assert!(l.event_handler().is_ok());
        // limiter should now be unblocked
        assert!(!l.is_blocked());
        // try and succeed on another 100 bytes this time
        assert!(l.consume(100, TokenType::Bytes));
    }

    #[test]
    fn test_rate_limiter_ops() {
        // rate limiter with limit of 1000 ops/s
        let mut l = RateLimiter::new(0, 0, 1000, 1000).unwrap();

        // limiter should not be blocked
        assert!(!l.is_blocked());
        // raw FD for this disabled should be valid
        assert!(l.as_raw_fd() > 0);

        // bytes/s limiter should be disabled so consume(whatever) should work
        assert!(l.consume(u64::max_value(), TokenType::Bytes));

        // do full 1000 ops
        assert!(l.consume(1000, TokenType::Ops));
        // try and fail on another 100
        assert!(!l.consume(100, TokenType::Ops));
        // since consume failed, limiter should be blocked now
        assert!(l.is_blocked());
        // wait half the timer period
        thread::sleep(Duration::from_millis(REFILL_TIMER_INTERVAL_MS / 2));
        // limiter should still be blocked
        assert!(l.is_blocked());
        // wait the other half of the timer period
        thread::sleep(Duration::from_millis(REFILL_TIMER_INTERVAL_MS / 2));
        // the timer_fd should have an event on it by now
        assert!(l.event_handler().is_ok());
        // limiter should now be unblocked
        assert!(!l.is_blocked());
        // try and succeed on another 100 ops this time
        assert!(l.consume(100, TokenType::Ops));
    }

    #[test]
    fn test_rate_limiter_full() {
        // rate limiter with limit of 1000 bytes/s and 1000 ops/s
        let mut l = RateLimiter::new(1000, 1000, 1000, 1000).unwrap();

        // limiter should not be blocked
        assert!(!l.is_blocked());
        // raw FD for this disabled should be valid
        assert!(l.as_raw_fd() > 0);

        // do full 1000 bytes
        assert!(l.consume(1000, TokenType::Ops));
        // do full 1000 bytes
        assert!(l.consume(1000, TokenType::Bytes));
        // try and fail on another 100 ops
        assert!(!l.consume(100, TokenType::Ops));
        // try and fail on another 100 bytes
        assert!(!l.consume(100, TokenType::Bytes));
        // since consume failed, limiter should be blocked now
        assert!(l.is_blocked());
        // wait half the timer period
        thread::sleep(Duration::from_millis(REFILL_TIMER_INTERVAL_MS / 2));
        // limiter should still be blocked
        assert!(l.is_blocked());
        // wait the other half of the timer period
        thread::sleep(Duration::from_millis(REFILL_TIMER_INTERVAL_MS / 2));
        // the timer_fd should have an event on it by now
        assert!(l.event_handler().is_ok());
        // limiter should now be unblocked
        assert!(!l.is_blocked());
        // try and succeed on another 100 ops this time
        assert!(l.consume(100, TokenType::Ops));
        // try and succeed on another 100 bytes this time
        assert!(l.consume(100, TokenType::Bytes));

        // TODO (Issue #259) enable this check when issue is resolved
        // fail with warning on consume() > total_capacity
        //assert!(!l.consume(u64::max_value(), TokenType::Bytes));
    }
}
