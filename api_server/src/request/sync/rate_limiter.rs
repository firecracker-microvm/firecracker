use std::io;

use fc_util::ratelimiter::RateLimiter;

// This struct represents the strongly typed equivalent of the json body for TokenBucket
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenBucketDescription {
    pub size: u64,
    pub refill_time: u64,
}

impl Default for TokenBucketDescription {
    fn default() -> Self {
        TokenBucketDescription {
            size: 0,
            refill_time: 0,
        }
    }
}

// This struct represents the strongly typed equivalent of the json body for RateLimiter
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimiterDescription {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bandwidth: Option<TokenBucketDescription>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ops: Option<TokenBucketDescription>,
}

// TryFrom trait is sadly marked unstable, so make our own
impl RateLimiterDescription {
    fn into_implementation(&self) -> io::Result<RateLimiter> {
        let bw = match self.bandwidth.as_ref() {
            Some(bwtbd) => bwtbd.clone(),
            None => TokenBucketDescription::default(),
        };
        let ops = match self.ops.as_ref() {
            Some(opstbd) => opstbd.clone(),
            None => TokenBucketDescription::default(),
        };
        RateLimiter::new(bw.size, bw.refill_time, ops.size, ops.refill_time)
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
        let tb = TokenBucketDescription {
            size: 0,
            refill_time: 0,
        };
        let tbc = tb.clone();
        // test clone and partial eq
        assert_eq!(tb, tbc);
    }

    #[test]
    fn test_token_bucket_default() {
        let tb = TokenBucketDescription::default();
        assert_eq!(tb.size, 0);
        assert_eq!(tb.refill_time, 0);
    }

    #[test]
    fn test_rate_limiter_default() {
        let l = RateLimiterDescription::default();
        assert!(l.bandwidth.is_none());
        assert!(l.ops.is_none());
    }

    #[test]
    fn test_rate_limiter_into_impl() {
        RateLimiterDescription::default()
            .into_implementation()
            .unwrap();
    }
}
