// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::result::Result;

use micro_http::{HttpHeaderError, RequestError};

/// Header rejected by MMDS.
/// Defined in lowercase since HTTP headers are case-insensitive.
pub const REJECTED_HEADER: &str = "x-forwarded-for";

/// `X-metadata-token` header might be used by HTTP clients to specify a token in order to
/// authenticate to the session. This is used for GET requests issued by the guest to MMDS only.
#[derive(Debug)]
pub struct XMetadataToken(pub Option<String>);

// Defined in lowercase since HTTP headers are case-insensitive.
const X_METADATA_TOKEN_HEADER: &str = "x-metadata-token";
const X_AWS_EC2_METADATA_TOKEN_HEADER: &str = "x-aws-ec2-metadata-token";

impl From<&HashMap<String, String>> for XMetadataToken {
    fn from(custom_headers: &HashMap<String, String>) -> Self {
        Self(
            custom_headers
                .iter()
                .find(|(k, _)| {
                    let k = k.to_lowercase();
                    k == X_METADATA_TOKEN_HEADER || k == X_AWS_EC2_METADATA_TOKEN_HEADER
                })
                .map(|(_, v)| v.to_string()),
        )
    }
}

/// `X-metadata-token-ttl-seconds` header might be used by HTTP clients to specify the expiry time
/// of a token. This is used for PUT requests issued by the guest to MMDS only.
#[derive(Debug)]
pub struct XMetadataTokenTtlSeconds(pub Option<u32>);

// Defined in lowercase since HTTP headers are case-insensitive.
const X_METADATA_TOKEN_TTL_SECONDS_HEADER: &str = "x-metadata-token-ttl-seconds";
const X_AWS_EC2_METADATA_TOKEN_SSL_SECONDS_HEADER: &str = "x-aws-ec2-metadata-token-ttl-seconds";

impl TryFrom<&HashMap<String, String>> for XMetadataTokenTtlSeconds {
    type Error = RequestError;

    fn try_from(custom_headers: &HashMap<String, String>) -> Result<Self, RequestError> {
        let seconds = custom_headers
            .iter()
            .find(|(k, _)| {
                let k = k.to_lowercase();
                k == X_METADATA_TOKEN_TTL_SECONDS_HEADER
                    || k == X_AWS_EC2_METADATA_TOKEN_SSL_SECONDS_HEADER
            })
            .map(|(k, v)| {
                v.parse::<u32>().map_err(|_| {
                    RequestError::HeaderError(HttpHeaderError::InvalidValue(
                        k.to_string(),
                        v.to_string(),
                    ))
                })
            })
            .transpose()?;

        Ok(Self(seconds))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_mixed_case(s: &str) -> String {
        s.chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_ascii_lowercase()
                } else {
                    c.to_ascii_uppercase()
                }
            })
            .collect()
    }

    #[test]
    fn test_x_metadata_token() {
        // No custom headers
        let custom_headers = HashMap::default();
        let x_metadata_token = XMetadataToken::from(&custom_headers);
        assert!(x_metadata_token.0.is_none());

        // Unrelated custom headers
        let custom_headers = HashMap::from([
            ("Some-Header".into(), "10".into()),
            ("Another-Header".into(), "value".into()),
        ]);
        let x_metadata_token = XMetadataToken::from(&custom_headers);
        assert!(x_metadata_token.0.is_none());

        for header in [X_METADATA_TOKEN_HEADER, X_AWS_EC2_METADATA_TOKEN_HEADER] {
            let token = "THIS_IS_TOKEN";

            // Valid header
            let custom_headers = HashMap::from([(header.into(), token.into())]);
            let x_metadata_token = XMetadataToken::from(&custom_headers);
            assert_eq!(&x_metadata_token.0.unwrap(), token);

            // Valid header in unrelated custom headers
            let custom_headers = HashMap::from([
                ("Some-Header".into(), "10".into()),
                ("Another-Header".into(), "value".into()),
                (header.into(), token.into()),
            ]);
            let x_metadata_token = XMetadataToken::from(&custom_headers);
            assert_eq!(&x_metadata_token.0.unwrap(), token);

            // Test case-insensitiveness
            let custom_headers = HashMap::from([(to_mixed_case(header), token.into())]);
            let x_metadata_token = XMetadataToken::from(&custom_headers);
            assert_eq!(&x_metadata_token.0.unwrap(), token);
        }
    }

    #[test]
    fn test_x_metadata_token_ttl_seconds() {
        // No custom headers
        let custom_headers = HashMap::default();
        let x_metadata_token_ttl_seconds =
            XMetadataTokenTtlSeconds::try_from(&custom_headers).unwrap();
        assert!(x_metadata_token_ttl_seconds.0.is_none());

        // Unrelated custom headers
        let custom_headers = HashMap::from([
            ("Some-Header".into(), "10".into()),
            ("Another-Header".into(), "value".into()),
        ]);
        let x_metadata_token_ttl_seconds =
            XMetadataTokenTtlSeconds::try_from(&custom_headers).unwrap();
        assert!(x_metadata_token_ttl_seconds.0.is_none());

        for header in [
            X_METADATA_TOKEN_TTL_SECONDS_HEADER,
            X_AWS_EC2_METADATA_TOKEN_SSL_SECONDS_HEADER,
        ] {
            let seconds = 60;

            // Valid header
            let custom_headers = HashMap::from([(header.into(), seconds.to_string())]);
            let x_metadata_token_ttl_seconds =
                XMetadataTokenTtlSeconds::try_from(&custom_headers).unwrap();
            assert_eq!(x_metadata_token_ttl_seconds.0.unwrap(), seconds);

            // Valid header in unrelated custom headers
            let custom_headers = HashMap::from([
                ("Some-Header".into(), "10".into()),
                ("Another-Header".into(), "value".into()),
                (header.into(), seconds.to_string()),
            ]);
            let x_metadata_token_ttl_seconds =
                XMetadataTokenTtlSeconds::try_from(&custom_headers).unwrap();
            assert_eq!(x_metadata_token_ttl_seconds.0.unwrap(), seconds);

            // Test case-insensitiveness
            let custom_headers = HashMap::from([(to_mixed_case(header), seconds.to_string())]);
            let x_metadata_token_ttl_seconds =
                XMetadataTokenTtlSeconds::try_from(&custom_headers).unwrap();
            assert_eq!(x_metadata_token_ttl_seconds.0.unwrap(), seconds);

            // Invalid value
            let mixed_case_header = to_mixed_case(header);
            let invalid_seconds = "-60";
            let custom_headers =
                HashMap::from([(mixed_case_header.clone(), invalid_seconds.to_string())]);
            assert_eq!(
                XMetadataTokenTtlSeconds::try_from(&custom_headers).unwrap_err(),
                RequestError::HeaderError(HttpHeaderError::InvalidValue(
                    mixed_case_header,
                    invalid_seconds.to_string()
                ))
            );
        }
    }
}
