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
