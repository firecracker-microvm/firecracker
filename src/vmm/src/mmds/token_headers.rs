// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

/// Header rejected by MMDS.
pub const REJECTED_HEADER: &str = "X-Forwarded-For";

// `X-metadata-token`
pub(crate) const X_METADATA_TOKEN_HEADER: &str = "x-metadata-token";
// `X-metadata-token-ttl-seconds`
pub(crate) const X_METADATA_TOKEN_TTL_SECONDS_HEADER: &str = "x-metadata-token-ttl-seconds";

pub(crate) fn get_header_value_pair<'a>(
    custom_headers: &'a HashMap<String, String>,
    header: &'static str,
) -> Option<(&'a String, &'a String)> {
    custom_headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(header))
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
        // No custom headers
        let custom_headers = HashMap::default();
        let token = get_header_value_pair(&custom_headers, X_METADATA_TOKEN_HEADER);
        assert!(token.is_none());

        // Unrelated custom headers
        let custom_headers = HashMap::from([
            ("Some-Header".into(), "10".into()),
            ("Another-Header".into(), "value".into()),
        ]);
        let token = get_header_value_pair(&custom_headers, X_METADATA_TOKEN_HEADER);
        assert!(token.is_none());

        // Valid header
        let expected = "THIS_IS_TOKEN";
        let custom_headers = HashMap::from([(X_METADATA_TOKEN_HEADER.into(), expected.into())]);
        let token = get_header_value_pair(&custom_headers, X_METADATA_TOKEN_HEADER).unwrap();
        assert_eq!(token, (&X_METADATA_TOKEN_HEADER.into(), &expected.into()));

        // Valid header in unrelated custom headers
        let custom_headers = HashMap::from([
            ("Some-Header".into(), "10".into()),
            ("Another-Header".into(), "value".into()),
            (X_METADATA_TOKEN_HEADER.into(), expected.into()),
        ]);
        let token = get_header_value_pair(&custom_headers, X_METADATA_TOKEN_HEADER).unwrap();
        assert_eq!(token, (&X_METADATA_TOKEN_HEADER.into(), &expected.into()));

        // Test case-insensitiveness
        let header = to_mixed_case(X_METADATA_TOKEN_HEADER);
        let custom_headers = HashMap::from([(header.clone(), expected.into())]);
        let token = get_header_value_pair(&custom_headers, X_METADATA_TOKEN_HEADER).unwrap();
        assert_eq!(token, (&header, &expected.into()));
    }
}
