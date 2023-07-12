// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use hyper::StatusCode;
use logger::{IncMetric, METRICS};
use mmds::data_store::MmdsVersion;
use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::mmds::MmdsConfig;

use crate::parsed_request::{Error, ParsedRequest};

pub(crate) fn parse_get_mmds() -> Result<ParsedRequest, Error> {
    METRICS.get_api_requests.mmds_count.inc();
    Ok(ParsedRequest::new_sync(VmmAction::GetMMDS))
}

pub(crate) fn parse_put_mmds(
    body: serde_json::Value,
    path_second_token: Option<&str>,
) -> Result<ParsedRequest, Error> {
    METRICS.put_api_requests.mmds_count.inc();
    match path_second_token {
        None => Ok(ParsedRequest::new_sync(VmmAction::PutMMDS(
            serde_json::from_value(body).map_err(|err| {
                METRICS.put_api_requests.mmds_fails.inc();
                err
            })?,
        ))),
        Some("config") => {
            let config: MmdsConfig = serde_json::from_value(body).map_err(|err| {
                METRICS.put_api_requests.mmds_fails.inc();
                err
            })?;
            // Construct the `ParsedRequest` object.
            let version = config.version;
            let mut parsed_request =
                ParsedRequest::new_sync(VmmAction::SetMmdsConfiguration(config));

            // MmdsV1 is deprecated.
            if version == MmdsVersion::V1 {
                METRICS.deprecated_api.deprecated_http_api_calls.inc();
                parsed_request.parsing_info().append_deprecation_message(
                    "PUT /mmds/config: V1 is deprecated. Use V2 instead.",
                );
            }

            Ok(parsed_request)
        }
        Some(unrecognized) => {
            METRICS.put_api_requests.mmds_fails.inc();
            Err(Error::Generic(
                StatusCode::BAD_REQUEST,
                format!("Unrecognized PUT request path `{}`.", unrecognized),
            ))
        }
    }
}

pub(crate) fn parse_patch_mmds(body: serde_json::Value) -> Result<ParsedRequest, Error> {
    METRICS.patch_api_requests.mmds_count.inc();
    Ok(ParsedRequest::new_sync(VmmAction::PatchMMDS(
        serde_json::from_value(body).map_err(|err| {
            METRICS.patch_api_requests.mmds_fails.inc();
            err
        })?,
    )))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_parse_get_mmds_request() {
        assert!(parse_get_mmds().is_ok());
        assert!(METRICS.get_api_requests.mmds_count.count() > 0);
    }

    #[test]
    fn test_parse_put_mmds_request() {
        let body = json!({
          "foo": "bar"
        });
        assert!(parse_put_mmds(body, None).is_ok());

        assert!(parse_put_mmds(serde_json::Value::Null, None).is_err());
        assert!(METRICS.put_api_requests.mmds_fails.count() > 0);

        // Test `config` path.
        let body = json!({
          "version": "V2",
          "ipv4_address": "169.254.170.2",
          "network_interfaces": []
        });
        let config_path = "config";
        assert!(parse_put_mmds(body, Some(config_path)).is_ok());

        let body = json!({
          "network_interfaces": []
        });
        assert!(parse_put_mmds(body, Some(config_path)).is_ok());

        let body = json!({
          "version": "foo",
          "ipv4_address": "169.254.170.2",
          "network_interfaces": []
        });
        assert!(parse_put_mmds(body, Some(config_path)).is_err());

        let body = json!({
          "version": "V2"
        });
        assert!(parse_put_mmds(body, Some(config_path)).is_err());

        let body = json!({
          "ipv4_address": "",
          "network_interfaces": []
        });
        assert!(parse_put_mmds(body.clone(), Some(config_path)).is_err());

        let invalid_config_body = json!({
          "invalid_config": "invalid_value"
        });
        assert!(parse_put_mmds(invalid_config_body.clone(), Some(config_path)).is_err());
        assert!(parse_put_mmds(body, Some("invalid_path")).is_err());
        assert!(parse_put_mmds(invalid_config_body, Some(config_path)).is_err());
    }

    #[test]
    fn test_deprecated_config() {
        let config_path = "config";

        let body = json!({
            "version": "V2",
            "ipv4_address": "169.254.170.2",
            "network_interfaces": []
        });
        let (_, _parsing_info) = parse_put_mmds(body, Some(config_path))
            .unwrap()
            .into_parts();
    }

    #[test]
    fn test_parse_patch_mmds_request() {
        let body = json!({
          "foo": "bar"
        });
        assert!(parse_patch_mmds(body).is_ok());
        assert!(METRICS.patch_api_requests.mmds_count.count() > 0);
        assert!(parse_patch_mmds(serde_json::Value::Null).is_err());
        assert!(METRICS.patch_api_requests.mmds_fails.count() > 0);
    }
}
