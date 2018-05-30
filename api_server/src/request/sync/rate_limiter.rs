use std::io;

use fc_util::ratelimiter::RateLimiter;

// This struct represents the strongly typed equivalent of the json body for TokenBucket
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct TokenBucket {
    pub size: u64,
    pub refill_time: u64,
}

impl Default for TokenBucket {
    fn default() -> Self {
        TokenBucket {
            size: 0,
            refill_time: 0,
        }
    }
}

// This struct represents the strongly typed equivalent of the json body for RateLimiter
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct RateLimiterDescription {
    pub bandwidth: TokenBucket,
    pub ops: TokenBucket,
}

// TryFrom trait is sadly marked unstable, so make our own
impl RateLimiterDescription {
    fn into_implementation(&self) -> io::Result<RateLimiter> {
        RateLimiter::new(
            self.bandwidth.size,
            self.bandwidth.refill_time,
            self.ops.size,
            self.ops.refill_time,
        )
    }
}

pub fn description_into_implementation(
    rate_limiter_description: Option<&RateLimiterDescription>,
) -> io::Result<Option<RateLimiter>> {
    match rate_limiter_description {
        Some(rld) => Ok(Some(rld.into_implementation()?)),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket_derives() {
        let tb = TokenBucket {
            size: 0,
            refill_time: 0,
        };
        let tbc = tb.clone();
        // test clone and partial eq
        assert_eq!(tb, tbc);
    }

    #[test]
    fn test_rate_limiter_default() {
        let l = RateLimiterDescription::default();
        assert_eq!(l.bandwidth.size, 0);
        assert_eq!(l.bandwidth.refill_time, 0);
        assert_eq!(l.ops.size, 0);
        assert_eq!(l.ops.refill_time, 0);
    }

    #[test]
    fn test_rate_limiter_into_impl() {
        RateLimiterDescription::default()
            .into_implementation()
            .unwrap();
    }
}
