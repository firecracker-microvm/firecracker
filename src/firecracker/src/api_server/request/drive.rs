// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::logger::{IncMetric, METRICS};
use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::drive::{BlockDeviceConfig, BlockDeviceUpdateConfig};

use super::super::parsed_request::{ParsedRequest, RequestError, checked_id};
use super::{Body, StatusCode};

pub(crate) fn parse_put_drive(
    body: &Body,
    id_from_path: Option<&str>,
) -> Result<ParsedRequest, RequestError> {
    METRICS.put_api_requests.drive_count.inc();
    let id = if let Some(id) = id_from_path {
        checked_id(id)?
    } else {
        METRICS.put_api_requests.drive_fails.inc();
        return Err(RequestError::EmptyID);
    };

    let device_cfg = serde_json::from_slice::<BlockDeviceConfig>(body.raw()).inspect_err(|_| {
        METRICS.put_api_requests.drive_fails.inc();
    })?;

    if id != device_cfg.drive_id {
        METRICS.put_api_requests.drive_fails.inc();
        Err(RequestError::Generic(
            StatusCode::BadRequest,
            "The id from the path does not match the id from the body!".to_string(),
        ))
    } else {
        Ok(ParsedRequest::new_sync(VmmAction::InsertBlockDevice(
            device_cfg,
        )))
    }
}

pub(crate) fn parse_patch_drive(
    body: &Body,
    id_from_path: Option<&str>,
) -> Result<ParsedRequest, RequestError> {
    METRICS.patch_api_requests.drive_count.inc();
    let id = if let Some(id) = id_from_path {
        checked_id(id)?
    } else {
        METRICS.patch_api_requests.drive_fails.inc();
        return Err(RequestError::EmptyID);
    };

    let block_device_update_cfg: BlockDeviceUpdateConfig =
        serde_json::from_slice::<BlockDeviceUpdateConfig>(body.raw()).inspect_err(|_| {
            METRICS.patch_api_requests.drive_fails.inc();
        })?;

    if id != block_device_update_cfg.drive_id {
        METRICS.patch_api_requests.drive_fails.inc();
        return Err(RequestError::Generic(
            StatusCode::BadRequest,
            String::from("The id from the path does not match the id from the body!"),
        ));
    }

    Ok(ParsedRequest::new_sync(VmmAction::UpdateBlockDevice(
        block_device_update_cfg,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_server::parsed_request::tests::vmm_action_from_request;

    #[test]
    fn test_parse_patch_drive_request() {
        parse_patch_drive(&Body::new("invalid_payload"), None).unwrap_err();
        parse_patch_drive(&Body::new("invalid_payload"), Some("id")).unwrap_err();

        // PATCH with invalid fields.
        let body = r#"{
            "drive_id": "bar",
            "is_read_only": false
        }"#;
        parse_patch_drive(&Body::new(body), Some("2")).unwrap_err();

        // PATCH with invalid types on fields. Adding a drive_id as number instead of string.
        let body = r#"{
            "drive_id": 1000,
            "path_on_host": "dummy"
        }"#;
        let res = parse_patch_drive(&Body::new(body), Some("1000"));
        res.unwrap_err();

        // PATCH with invalid types on fields. Adding a path_on_host as bool instead of string.
        let body = r#"{
            "drive_id": 1000,
            "path_on_host": true
        }"#;
        let res = parse_patch_drive(&Body::new(body), Some("1000"));
        res.unwrap_err();

        // PATCH with only drive_id field.
        let body = r#"{
            "drive_id": "1000"
        }"#;
        let res = parse_patch_drive(&Body::new(body), Some("1000"));
        res.unwrap();

        // PATCH with missing drive_id field.
        let body = r#"{
            "path_on_host": true
        }"#;
        let res = parse_patch_drive(&Body::new(body), Some("1000"));
        res.unwrap_err();

        // PATCH that tries to update something else other than path_on_host.
        let body = r#"{
            "drive_id": "dummy_id",
            "path_on_host": "dummy_host",
            "is_read_only": false
        }"#;
        let res = parse_patch_drive(&Body::new(body), Some("1234"));
        res.unwrap_err();

        // PATCH with payload that is not a json.
        let body = r#"{
            "fields": "dummy_field"
        }"#;
        parse_patch_drive(&Body::new(body), Some("1234")).unwrap_err();

        let body = r#"{
            "drive_id": "foo",
            "path_on_host": "dummy"
        }"#;
        let expected_config = BlockDeviceUpdateConfig {
            drive_id: "foo".to_string(),
            path_on_host: Some("dummy".to_string()),
            rate_limiter: None,
        };
        assert_eq!(
            vmm_action_from_request(parse_patch_drive(&Body::new(body), Some("foo")).unwrap()),
            VmmAction::UpdateBlockDevice(expected_config)
        );

        let body = r#"{
            "drive_id": "foo",
            "path_on_host": "dummy"
        }"#;
        // Must fail since the drive id differs from id_from_path (foo vs bar).
        parse_patch_drive(&Body::new(body), Some("bar")).unwrap_err();

        let body = r#"{
            "drive_id": "foo",
            "rate_limiter": {
                "bandwidth": {
                    "size": 5000,
                    "refill_time": 100
                },
                "ops": {
                    "size": 500,
                    "refill_time": 100
                }
            }
        }"#;
        // Validate that updating just the ratelimiter works.
        parse_patch_drive(&Body::new(body), Some("foo")).unwrap();

        let body = r#"{
            "drive_id": "foo",
            "path_on_host": "/there",
            "rate_limiter": {
                "bandwidth": {
                    "size": 5000,
                    "refill_time": 100
                },
                "ops": {
                    "size": 500,
                    "refill_time": 100
                }
            }
        }"#;
        // Validate that updating both path and rate limiter succeds.
        parse_patch_drive(&Body::new(body), Some("foo")).unwrap();

        let body = r#"{
            "drive_id": "foo",
            "path_on_host": "/there",
            "rate_limiter": {
                "ops": {
                    "size": 100
                }
            }
        }"#;
        // Validate that parse_patch_drive fails for invalid rate limiter cfg.
        parse_patch_drive(&Body::new(body), Some("foo")).unwrap_err();
    }

    #[test]
    fn test_parse_put_drive_request() {
        parse_put_drive(&Body::new("invalid_payload"), None).unwrap_err();
        parse_put_drive(&Body::new("invalid_payload"), Some("id")).unwrap_err();

        // PUT with invalid fields.
        let body = r#"{
            "drive_id": "bar",
            "is_read_only": false
        }"#;
        parse_put_drive(&Body::new(body), Some("2")).unwrap_err();

        // PUT with missing all optional fields.
        let body = r#"{
            "drive_id": "1000",
            "path_on_host": "dummy",
            "is_root_device": true,
            "is_read_only": true
        }"#;
        parse_put_drive(&Body::new(body), Some("1000")).unwrap();

        // PUT with invalid types on fields. Adding a drive_id as number instead of string.
        parse_put_drive(&Body::new(body), Some("foo")).unwrap_err();

        // PUT with the complete configuration.
        let body = r#"{
            "drive_id": "1000",
            "path_on_host": "dummy",
            "is_root_device": true,
            "partuuid": "string",
            "is_read_only": true,
            "cache_type": "Unsafe",
            "io_engine": "Sync",
            "rate_limiter": {
                "bandwidth": {
                    "size": 0,
                    "one_time_burst": 0,
                    "refill_time": 0
                },
                "ops": {
                    "size": 0,
                    "one_time_burst": 0,
                    "refill_time": 0
                }
            }
        }"#;
        parse_put_drive(&Body::new(body), Some("1000")).unwrap();
    }
}
