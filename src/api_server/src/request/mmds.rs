// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use micro_http::StatusCode;
use request::{Body, Error, ParsedRequest};
use vmm::rpc_interface::VmmAction::SetMmdsConfiguration;
use vmm::vmm_config::mmds::MmdsConfig;

pub fn parse_get_mmds() -> Result<ParsedRequest, Error> {
    Ok(ParsedRequest::GetMMDS)
}

pub fn parse_put_mmds(
    body: &Body,
    path_second_token: Option<&&str>,
) -> Result<ParsedRequest, Error> {
    match path_second_token {
        Some(config_path) => match *config_path {
            "config" => Ok(ParsedRequest::Sync(SetMmdsConfiguration(
                serde_json::from_slice::<MmdsConfig>(body.raw()).map_err(Error::SerdeJson)?,
            ))),
            _ => Err(Error::Generic(
                StatusCode::BadRequest,
                format!("Unrecognized PUT request path `{}`.", *config_path),
            )),
        },
        None => Ok(ParsedRequest::PutMMDS(
            serde_json::from_slice(body.raw()).map_err(Error::SerdeJson)?,
        )),
    }
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
        assert!(parse_put_mmds(&Body::new(body), None).is_ok());
        let invalid_body = "invalid_body";
        assert!(parse_put_mmds(&Body::new(invalid_body), None).is_err());

        let body = r#"{
                "ipv4_address": "169.254.170.2"
              }"#;
        let path = "config";
        assert!(parse_put_mmds(&Body::new(body), Some(&path)).is_ok());

        let body = r#"{
                "ipv4_address": ""
              }"#;
        assert!(parse_put_mmds(&Body::new(body), Some(&path)).is_err());

        // Equivalent to reset the mmds configuration.
        let empty_body = r#"{}"#;
        assert!(parse_put_mmds(&Body::new(empty_body), Some(&path)).is_ok());

        let invalid_config_body = r#"{
                "invalid_config": "invalid_value"
              }"#;
        assert!(parse_put_mmds(&Body::new(invalid_config_body), Some(&path)).is_err());
        assert!(parse_put_mmds(&Body::new(body), Some(&"invalid_path")).is_err());
        assert!(parse_put_mmds(&Body::new(invalid_body), Some(&path)).is_err());
    }

    #[test]
    fn test_parse_patch_mmds_request() {
        let body = r#"{
                "foo": "bar"
              }"#;
        assert!(parse_patch_mmds(&Body::new(body)).is_ok());
        assert!(parse_patch_mmds(&Body::new("invalid_body")).is_err());
    }
}
