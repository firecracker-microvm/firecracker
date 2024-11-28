// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use micro_http::StatusCode;
use vmm::logger::{IncMetric, METRICS};
use vmm::mmds::data_store::MmdsVersion;
use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::mmds::MmdsConfig;

use super::super::parsed_request::{ParsedRequest, RequestError};
use super::Body;

pub(crate) fn parse_get_mmds() -> Result<ParsedRequest, RequestError> {
    METRICS.get_api_requests.mmds_count.inc();
    Ok(ParsedRequest::new_sync(VmmAction::GetMMDS))
}

fn parse_put_mmds_config(body: &Body) -> Result<ParsedRequest, RequestError> {
    let config: MmdsConfig = serde_json::from_slice(body.raw()).inspect_err(|_| {
        METRICS.put_api_requests.mmds_fails.inc();
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
) -> Result<ParsedRequest, RequestError> {
    METRICS.put_api_requests.mmds_count.inc();
    match path_second_token {
        None => Ok(ParsedRequest::new_sync(VmmAction::PutMMDS(
            serde_json::from_slice(body.raw()).inspect_err(|_| {
                METRICS.put_api_requests.mmds_fails.inc();
            })?,
        ))),
        Some("config") => parse_put_mmds_config(body),
        Some(unrecognized) => {
            METRICS.put_api_requests.mmds_fails.inc();
            Err(RequestError::Generic(
                StatusCode::BadRequest,
                format!("Unrecognized PUT request path `{}`.", unrecognized),
            ))
        }
    }
}

pub(crate) fn parse_patch_mmds(body: &Body) -> Result<ParsedRequest, RequestError> {
    METRICS.patch_api_requests.mmds_count.inc();
    Ok(ParsedRequest::new_sync(VmmAction::PatchMMDS(
        serde_json::from_slice(body.raw()).inspect_err(|_| {
            METRICS.patch_api_requests.mmds_fails.inc();
        })?,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_server::parsed_request::tests::depr_action_from_req;

    #[test]
    fn test_parse_get_mmds_request() {
        parse_get_mmds().unwrap();
        assert!(METRICS.get_api_requests.mmds_count.count() > 0);
    }

    #[test]
    fn test_parse_put_mmds_request() {
        let body = r#"{
            "foo": "bar"
        }"#;
        parse_put_mmds(&Body::new(body), None).unwrap();

        let invalid_body = "invalid_body";
        parse_put_mmds(&Body::new(invalid_body), None).unwrap_err();
        assert!(METRICS.put_api_requests.mmds_fails.count() > 0);

        // Test `config` path.
        let body = r#"{
            "version": "V2",
            "ipv4_address": "169.254.170.2",
            "network_interfaces": []
        }"#;
        let config_path = "config";
        parse_put_mmds(&Body::new(body), Some(config_path)).unwrap();

        let body = r#"{
            "network_interfaces": []
        }"#;
        parse_put_mmds(&Body::new(body), Some(config_path)).unwrap();

        let body = r#"{
            "version": "foo",
            "ipv4_address": "169.254.170.2",
            "network_interfaces": []
        }"#;
        parse_put_mmds(&Body::new(body), Some(config_path)).unwrap_err();

        let body = r#"{
            "version": "V2"
        }"#;
        parse_put_mmds(&Body::new(body), Some(config_path)).unwrap_err();

        let body = r#"{
            "ipv4_address": "",
            "network_interfaces": []
        }"#;
        parse_put_mmds(&Body::new(body), Some(config_path)).unwrap_err();

        let invalid_config_body = r#"{
            "invalid_config": "invalid_value"
        }"#;
        parse_put_mmds(&Body::new(invalid_config_body), Some(config_path)).unwrap_err();
        parse_put_mmds(&Body::new(body), Some("invalid_path")).unwrap_err();
        parse_put_mmds(&Body::new(invalid_body), Some(config_path)).unwrap_err();
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
        parse_patch_mmds(&Body::new(body)).unwrap();
        assert!(METRICS.patch_api_requests.mmds_count.count() > 0);
        parse_patch_mmds(&Body::new("invalid_body")).unwrap_err();
        assert!(METRICS.patch_api_requests.mmds_fails.count() > 0);
    }
}
