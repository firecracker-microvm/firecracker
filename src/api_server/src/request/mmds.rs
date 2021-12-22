// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::parsed_request::{Error, ParsedRequest, RequestAction};
use crate::request::Body;
use logger::{IncMetric, METRICS};
use micro_http::StatusCode;
use vmm::rpc_interface::VmmAction::SetMmdsConfiguration;

pub(crate) fn parse_get_mmds() -> Result<ParsedRequest, Error> {
    METRICS.get_api_requests.mmds_count.inc();
    Ok(ParsedRequest::new(RequestAction::GetMMDS))
}

pub(crate) fn parse_put_mmds(
    body: &Body,
    path_second_token: Option<&&str>,
) -> Result<ParsedRequest, Error> {
    METRICS.put_api_requests.mmds_count.inc();
    match path_second_token {
        None => Ok(ParsedRequest::new(RequestAction::PutMMDS(
            serde_json::from_slice(body.raw()).map_err(|e| {
                METRICS.put_api_requests.mmds_fails.inc();
                Error::SerdeJson(e)
            })?,
        ))),
        Some(&"config") => Ok(ParsedRequest::new_sync(SetMmdsConfiguration(
            serde_json::from_slice(body.raw()).map_err(|e| {
                METRICS.put_api_requests.mmds_fails.inc();
                Error::SerdeJson(e)
            })?,
        ))),
        Some(&unrecognized) => {
            METRICS.put_api_requests.mmds_fails.inc();
            Err(Error::Generic(
                StatusCode::BadRequest,
                format!("Unrecognized PUT request path `{}`.", unrecognized),
            ))
        }
    }
}

pub(crate) fn parse_patch_mmds(body: &Body) -> Result<ParsedRequest, Error> {
    METRICS.patch_api_requests.mmds_count.inc();
    Ok(ParsedRequest::new(RequestAction::PatchMMDS(
        serde_json::from_slice(body.raw()).map_err(|e| {
            METRICS.patch_api_requests.mmds_fails.inc();
            Error::SerdeJson(e)
        })?,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_get_mmds_request() {
        assert!(parse_get_mmds().is_ok());
        assert!(METRICS.get_api_requests.mmds_count.count() > 0);
    }

    #[test]
    fn test_parse_put_mmds_request() {
        let body = r#"{
                "foo": "bar"
              }"#;
        assert!(parse_put_mmds(&Body::new(body), None).is_ok());

        let invalid_body = "invalid_body";
        assert!(parse_put_mmds(&Body::new(invalid_body), None).is_err());
        assert!(METRICS.put_api_requests.mmds_fails.count() > 0);

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
        assert!(METRICS.patch_api_requests.mmds_count.count() > 0);
        assert!(parse_patch_mmds(&Body::new("invalid_body")).is_err());
        assert!(METRICS.patch_api_requests.mmds_fails.count() > 0);
    }
}
