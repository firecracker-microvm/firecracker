// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use micro_http::{HttpHeaderError, RequestError};
use std::collections::HashMap;
use std::result::Result;

/// Wrapper over supported HTTP Custom Header types.
#[derive(Debug, Eq, Hash, PartialEq)]
pub enum CustomHeader {
    /// Header `X-aws-ec2-metadata-token`
    XAwsMetadataToken,
    /// Header `X-aws-ec2-metadata-token-ttl-seconds`
    XAwsMetadataTokenTtlSeconds,
}

impl CustomHeader {
    /// Parses a byte slice into a `CustomHeader` structure.
    fn try_from(mut string: String) -> Result<Self, RequestError> {
        string.make_ascii_lowercase();
        match string.trim() {
            "x-aws-ec2-metadata-token" => Ok(Self::XAwsMetadataToken),
            "x-aws-ec2-metadata-token-ttl-seconds" => Ok(Self::XAwsMetadataTokenTtlSeconds),
            invalid_key => Err(RequestError::HeaderError(HttpHeaderError::UnsupportedName(
                invalid_key.to_string(),
            ))),
        }
    }
}

/// Wrapper over the list of custom headers associated with a Request.
#[derive(Debug, PartialEq)]
pub struct CustomHeaders {
    /// The `X-aws-ec2-metadata-token` header might be used by HTTP clients to specify a token in order
    /// to authenticate to the session. This is used for guest requests to MMDS only.
    x_aws_metadata_token: Option<String>,
    /// The `X-aws-ec2-metadata-token-ttl-seconds` header might be used by HTTP clients to specify
    /// the expiry time of a token. This is used for PUT requests issued by the guest to MMDS only.
    x_aws_metadata_token_ttl_seconds: Option<u32>,
}

impl Default for CustomHeaders {
    /// Custom headers are not present in the request by default.
    fn default() -> Self {
        Self {
            x_aws_metadata_token: None,
            x_aws_metadata_token_ttl_seconds: None,
        }
    }
}

impl CustomHeaders {
    /// Return `CustomHeaders` from headers map.
    pub fn try_from(map: &HashMap<String, String>) -> Result<CustomHeaders, RequestError> {
        let mut headers = Self::default();

        for (name, value) in map.iter() {
            if let Ok(head) = CustomHeader::try_from(name.to_string()) {
                match head {
                    CustomHeader::XAwsMetadataToken => match value.parse::<String>() {
                        Ok(token) => {
                            headers.x_aws_metadata_token = Some(token);
                        }
                        Err(_) => {
                            return Err(RequestError::HeaderError(HttpHeaderError::InvalidValue(
                                name.to_string(),
                                value.to_string(),
                            )));
                        }
                    },
                    CustomHeader::XAwsMetadataTokenTtlSeconds => match value.parse::<u32>() {
                        Ok(seconds) => {
                            headers.x_aws_metadata_token_ttl_seconds = Some(seconds);
                        }
                        Err(_) => {
                            return Err(RequestError::HeaderError(HttpHeaderError::InvalidValue(
                                name.to_string(),
                                value.to_string(),
                            )));
                        }
                    },
                }
            } else {
                // Skip unrecognized headers.
                continue;
            }
        }
        Ok(headers)
    }

    /// Returns the `XAwsMetadataToken` token.
    pub fn x_aws_metadata_token(&self) -> Option<&String> {
        self.x_aws_metadata_token.as_ref()
    }

    /// Returns the `XAwsMetadataTokenTtlSeconds` token.
    pub fn x_aws_metadata_token_ttl_seconds(&self) -> Option<u32> {
        self.x_aws_metadata_token_ttl_seconds
    }

    /// Sets the `XAwsMetadataToken` token.
    pub fn set_x_aws_metadata_token(&mut self, token: String) {
        self.x_aws_metadata_token = Some(token)
    }

    /// Sets the `XAwsMetadataTokenTtlSeconds` token.
    pub fn set_x_aws_metadata_token_ttl_seconds(&mut self, ttl: u32) {
        self.x_aws_metadata_token_ttl_seconds = Some(ttl);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        let headers = CustomHeaders::default();
        assert_eq!(headers.x_aws_metadata_token(), None);
        assert_eq!(headers.x_aws_metadata_token_ttl_seconds(), None);
    }

    #[test]
    fn test_try_from_headers() {
        // Empty custom header map.
        let map: HashMap<String, String> = HashMap::default();
        let headers = CustomHeaders::try_from(&map).unwrap();
        assert_eq!(headers, CustomHeaders::default());

        // Unrecognised custom headers.
        let mut map: HashMap<String, String> = HashMap::default();
        map.insert("Some-Header".to_string(), "10".to_string());
        map.insert("Another-Header".to_string(), "value".to_string());
        let headers = CustomHeaders::try_from(&map).unwrap();
        assert_eq!(headers, CustomHeaders::default());

        // Valid headers.
        let mut map: HashMap<String, String> = HashMap::default();
        map.insert("Some-Header".to_string(), "10".to_string());
        map.insert(
            "X-aws-ec2-metadata-token-ttl-seconds".to_string(),
            "60".to_string(),
        );
        map.insert("X-aws-ec2-metadata-token".to_string(), "foo".to_string());
        let headers = CustomHeaders::try_from(&map).unwrap();
        assert_eq!(headers.x_aws_metadata_token_ttl_seconds().unwrap(), 60);
        assert_eq!(*headers.x_aws_metadata_token().unwrap(), "foo".to_string());

        let mut map: HashMap<String, String> = HashMap::default();
        map.insert("X-aws-ec2-metadata-token".to_string(), "".to_string());
        let headers = CustomHeaders::try_from(&map).unwrap();
        assert_eq!(*headers.x_aws_metadata_token().unwrap(), "".to_string());

        // Invalid value.
        let mut map: HashMap<String, String> = HashMap::default();
        map.insert(
            "X-aws-ec2-metadata-token-ttl-seconds".to_string(),
            "-60".to_string(),
        );
        assert_eq!(
            CustomHeaders::try_from(&map).unwrap_err(),
            RequestError::HeaderError(HttpHeaderError::InvalidValue(
                "X-aws-ec2-metadata-token-ttl-seconds".to_string(),
                "-60".to_string()
            ))
        );
    }
}
