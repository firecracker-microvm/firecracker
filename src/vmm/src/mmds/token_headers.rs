// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

// `X-Forwarded-For`
pub(crate) const X_FORWARDED_FOR_HEADER: &str = "x-forwarded-for";
// `X-metadata-token`
pub(crate) const X_METADATA_TOKEN_HEADER: &str = "x-metadata-token";
// `X-aws-ec2-metadata-token`
pub(crate) const X_AWS_EC2_METADATA_TOKEN_HEADER: &str = "x-aws-ec2-metadata-token";
// `X-metadata-token-ttl-seconds`
pub(crate) const X_METADATA_TOKEN_TTL_SECONDS_HEADER: &str = "x-metadata-token-ttl-seconds";
// `X-aws-ec2-metadata-token-ttl-seconds`
pub(crate) const X_AWS_EC2_METADATA_TOKEN_SSL_SECONDS_HEADER: &str =
    "x-aws-ec2-metadata-token-ttl-seconds";

pub(crate) fn get_header_value_pair<'a>(
    custom_headers: &'a HashMap<String, String>,
    headers: &'a [&'static str],
) -> Option<(&'a String, &'a String)> {
    custom_headers
        .iter()
        .find(|(k, _)| headers.iter().any(|header| k.eq_ignore_ascii_case(header)))
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
    fn test_get_header_value_pair() {
        let headers = [X_METADATA_TOKEN_HEADER, X_AWS_EC2_METADATA_TOKEN_HEADER];

        // No custom headers
        let custom_headers = HashMap::default();
        let token = get_header_value_pair(&custom_headers, &headers);
        assert!(token.is_none());

        // Unrelated custom headers
        let custom_headers = HashMap::from([
            ("Some-Header".into(), "10".into()),
            ("Another-Header".into(), "value".into()),
        ]);
        let token = get_header_value_pair(&custom_headers, &headers);
        assert!(token.is_none());

        for header in headers {
            // Valid header
            let expected = "THIS_IS_TOKEN";
            let custom_headers = HashMap::from([(header.into(), expected.into())]);
            let token = get_header_value_pair(&custom_headers, &headers).unwrap();
            assert_eq!(token, (&header.into(), &expected.into()));

            // Valid header in unrelated custom headers
            let custom_headers = HashMap::from([
                ("Some-Header".into(), "10".into()),
                ("Another-Header".into(), "value".into()),
                (header.into(), expected.into()),
            ]);
            let token = get_header_value_pair(&custom_headers, &headers).unwrap();
            assert_eq!(token, (&header.into(), &expected.into()));

            // Test case-insensitiveness
            let header = to_mixed_case(header);
            let custom_headers = HashMap::from([(header.clone(), expected.into())]);
            let token = get_header_value_pair(&custom_headers, &headers).unwrap();
            assert_eq!(token, (&header, &expected.into()));
        }
    }
}
