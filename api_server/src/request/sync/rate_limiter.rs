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
pub struct RateLimiter {
    pub bandwidth: TokenBucket,
    pub ops: TokenBucket,
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
        let l = RateLimiter::default();
        assert_eq!(l.bandwidth.size, 0);
        assert_eq!(l.bandwidth.refill_time, 0);
        assert_eq!(l.ops.size, 0);
        assert_eq!(l.ops.refill_time, 0);
    }
}
