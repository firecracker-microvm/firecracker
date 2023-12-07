// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use micro_http::StatusCode;
use vmm::logger::{IncMetric, METRICS};
use vmm::mmds::data_store::MmdsVersion;
use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::mmds::MmdsConfig;

use crate::parsed_request::{Error, ParsedRequest};
use crate::request::Body;

pub(crate) fn parse_get_mmds() -> Result<ParsedRequest, Error> {
    METRICS.get_api_requests.mmds_count.inc();
    Ok(ParsedRequest::new_sync(VmmAction::GetMMDS))
}

fn parse_put_mmds_config(body: &Body) -> Result<ParsedRequest, Error> {
    let config: MmdsConfig = serde_json::from_slice(body.raw()).map_err(|err| {
        METRICS.put_api_requests.mmds_fails.inc();
        err
    })?;
    // Construct the `ParsedRequest` object.
    let version = config.version;
    let mut parsed_request = ParsedRequest::new_sync(VmmAction::SetMmdsConfiguration(config));

    // MmdsV1 is deprecated.
    if version == MmdsVersion::V1 {
        METRICS.deprecated_api.deprecated_http_api_calls.inc();
        parsed_request
            .parsing_info()
            .append_deprecation_message("PUT /mmds/config: V1 is deprecated. Use V2 instead.");
    }

    Ok(parsed_request)
}

pub(crate) fn parse_put_mmds(
    body: &Body,
    path_second_token: Option<&str>,
) -> Result<ParsedRequest, Error> {
    METRICS.put_api_requests.mmds_count.inc();
    match path_second_token {
        None => Ok(ParsedRequest::new_sync(VmmAction::PutMMDS(
            serde_json::from_slice(body.raw()).map_err(|err| {
                METRICS.put_api_requests.mmds_fails.inc();
                err
            })?,
        ))),
        Some("config") => parse_put_mmds_config(body),
        Some(unrecognized) => {
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
    Ok(ParsedRequest::new_sync(VmmAction::PatchMMDS(
        serde_json::from_slice(body.raw()).map_err(|err| {
            METRICS.patch_api_requests.mmds_fails.inc();
            err
        })?,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsed_request::tests::depr_action_from_req;

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

        // Test `config` path.
        let body = r#"{
            "version": "V2",
            "ipv4_address": "169.254.170.2",
            "network_interfaces": []
        }"#;
        let config_path = "config";
        assert!(parse_put_mmds(&Body::new(body), Some(config_path)).is_ok());

        let body = r#"{
            "network_interfaces": []
        }"#;
        assert!(parse_put_mmds(&Body::new(body), Some(config_path)).is_ok());

        let body = r#"{
            "version": "foo",
            "ipv4_address": "169.254.170.2",
            "network_interfaces": []
        }"#;
        assert!(parse_put_mmds(&Body::new(body), Some(config_path)).is_err());

        let body = r#"{
            "version": "V2"
        }"#;
        assert!(parse_put_mmds(&Body::new(body), Some(config_path)).is_err());

        let body = r#"{
            "ipv4_address": "",
            "network_interfaces": []
        }"#;
        assert!(parse_put_mmds(&Body::new(body), Some(config_path)).is_err());

        let invalid_config_body = r#"{
            "invalid_config": "invalid_value"
        }"#;
        assert!(parse_put_mmds(&Body::new(invalid_config_body), Some(config_path)).is_err());
        assert!(parse_put_mmds(&Body::new(body), Some("invalid_path")).is_err());
        assert!(parse_put_mmds(&Body::new(invalid_body), Some(config_path)).is_err());
    }

    #[test]
    fn test_deprecated_config() {
        let config_path = "config";

        let body = r#"{
            "ipv4_address": "169.254.170.2",
            "network_interfaces": []
        }"#;
        depr_action_from_req(
            parse_put_mmds(&Body::new(body), Some(config_path)).unwrap(),
            Some("PUT /mmds/config: V1 is deprecated. Use V2 instead.".to_string()),
        );

        let body = r#"{
            "version": "V1",
            "ipv4_address": "169.254.170.2",
            "network_interfaces": []
        }"#;
        depr_action_from_req(
            parse_put_mmds(&Body::new(body), Some(config_path)).unwrap(),
            Some("PUT /mmds/config: V1 is deprecated. Use V2 instead.".to_string()),
        );

        let body = r#"{
            "version": "V2",
            "ipv4_address": "169.254.170.2",
            "network_interfaces": []
        }"#;
        let (_, mut parsing_info) = parse_put_mmds(&Body::new(body), Some(config_path))
            .unwrap()
            .into_parts();
        assert!(parsing_info.take_deprecation_message().is_none());
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
