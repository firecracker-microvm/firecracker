// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use request::{Body, Error, ParsedRequest};

pub fn parse_get_mmds() -> Result<ParsedRequest, Error> {
    Ok(ParsedRequest::GetMMDS)
}

pub fn parse_put_mmds(body: &Body) -> Result<ParsedRequest, Error> {
    Ok(ParsedRequest::PutMMDS(
        serde_json::from_slice(body.raw()).map_err(Error::SerdeJson)?,
    ))
}

pub fn parse_patch_mmds(body: &Body) -> Result<ParsedRequest, Error> {
    Ok(ParsedRequest::PatchMMDS(
        serde_json::from_slice(body.raw()).map_err(Error::SerdeJson)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_get_mmds_request() {
        assert!(parse_get_mmds().is_ok());
    }

    #[test]
    fn test_parse_put_mmds_request() {
        let body = r#"{
                "foo": "bar"
              }"#;
        assert!(parse_put_mmds(&Body::new(body)).is_ok());

        let body = "invalid_body";
        assert!(parse_put_mmds(&Body::new(body)).is_err());
    }

    #[test]
    fn test_parse_patch_mmds_request() {
        let body = r#"{
                "foo": "bar"
              }"#;
        assert!(parse_put_mmds(&Body::new(body)).is_ok());

        let body = "invalid_body";
        assert!(parse_put_mmds(&Body::new(body)).is_err());
    }
}
