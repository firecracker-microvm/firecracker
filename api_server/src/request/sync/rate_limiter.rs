use std::io;

use fc_util::ratelimiter::RateLimiter;

// This struct represents the strongly typed equivalent of the json body for TokenBucket.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenBucketDescription {
    pub size: u64,
    pub one_time_burst: Option<u64>,
    pub refill_time: u64,
}

impl Default for TokenBucketDescription {
    fn default() -> Self {
        TokenBucketDescription {
            size: 0,
            one_time_burst: None,
            refill_time: 0,
        }
    }
}

// This struct represents the strongly typed equivalent of the json body for RateLimiter.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimiterDescription {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bandwidth: Option<TokenBucketDescription>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ops: Option<TokenBucketDescription>,
}

// TryFrom trait is sadly marked unstable, so make our own.
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

        let bw_one_time_burst = bw.one_time_burst.unwrap_or(0);

        let ops_one_time_burst = ops.one_time_burst.unwrap_or(0);

        RateLimiter::new(
            bw.size,
            bw_one_time_burst,
            bw.refill_time,
            ops.size,
            ops_one_time_burst,
            ops.refill_time,
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
    use serde_json;

    #[test]
    fn test_token_bucket_derives() {
        let tb = TokenBucketDescription::default();
        let tbc = tb.clone();
        // Test `clone` and `partial eq`.
        assert_eq!(tb, tbc);
    }

    #[test]
    fn test_token_bucket_default() {
        let tb = TokenBucketDescription::default();
        assert_eq!(tb.size, 0);
        assert!(tb.one_time_burst.is_none());
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
        let res = description_into_implementation(Some(&RateLimiterDescription::default()));
        assert!(res.unwrap().is_some());
        let res = description_into_implementation(None);
        assert!(res.unwrap().is_none());
        RateLimiterDescription::default()
            .into_implementation()
            .unwrap();
    }

    #[test]
    fn test_rate_limiter_deserialization() {
        let jstr = r#"{
                "bandwidth": { "size": 0, "one_time_burst": 0,  "refill_time": 0 },
                "ops": { "size": 0, "one_time_burst": 0, "refill_time": 0 }
            }"#;

        let x: RateLimiterDescription =
            serde_json::from_str(jstr).expect("deserialization failed.");
        assert!(x.into_implementation().is_ok());
    }
}
