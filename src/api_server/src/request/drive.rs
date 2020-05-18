// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0<Paste>

use serde_json::{Map, Value};

use super::super::VmmAction;
use logger::{Metric, METRICS};
use request::{checked_id, Body, Error, ParsedRequest, StatusCode};
use vmm::vmm_config::drive::BlockDeviceConfig;

struct PatchDrivePayload {
    // Leaving `fields` pub because ownership on it needs to be yielded to the
    // Request enum object. A getter couldn't move `fields` out of the borrowed
    // PatchDrivePayload object.
    pub fields: Value,
}

impl PatchDrivePayload {
    /// Checks that `field_key` exists and that the value has the type Value::String.
    fn check_field_is_string(map: &Map<String, Value>, field_key: &str) -> Result<(), String> {
        match map.get(field_key) {
            None => {
                return Err(format!(
                    "Required key {} not present in the json.",
                    field_key
                ));
            }
            Some(id) => {
                // Check that field is a string.
                if id.as_str().is_none() {
                    return Err(format!("Invalid type for key {}.", field_key));
                }
            }
        }
        Ok(())
    }

    /// Validates that only path_on_host and drive_id are present in the payload.
    fn validate(&self) -> Result<(), Error> {
        match self.fields.as_object() {
            Some(fields_map) => {
                // Check that field `drive_id` exists and its type is String.
                PatchDrivePayload::check_field_is_string(fields_map, "drive_id")
                    .map_err(|e| Error::Generic(StatusCode::BadRequest, e))?;
                // Check that field `path_on_host` exists and its type is String.
                PatchDrivePayload::check_field_is_string(fields_map, "path_on_host")
                    .map_err(|e| Error::Generic(StatusCode::BadRequest, e))?;

                // Check that there are no other fields in the object.
                if fields_map.len() > 2 {
                    return Err(Error::Generic(
                        StatusCode::BadRequest,
                        "Invalid PATCH payload. Only updates on path_on_host are allowed."
                            .to_string(),
                    ));
                }
                Ok(())
            }
            _ => Err(Error::Generic(
                StatusCode::BadRequest,
                "Invalid json.".to_string(),
            )),
        }
    }

    /// Returns the field specified by `field_key` as a string. This is unsafe if validate
    /// is not called prior to calling this method.
    fn get_string_field_unchecked(&self, field_key: &str) -> String {
        self.fields
            .get(field_key)
            .expect("No field key")
            .as_str()
            .expect("Field value not a string")
            .to_string()
    }
}

pub fn parse_put_drive(body: &Body, id_from_path: Option<&&str>) -> Result<ParsedRequest, Error> {
    METRICS.put_api_requests.drive_count.inc();
    let id = if let Some(id) = id_from_path {
        checked_id(id)?
    } else {
        METRICS.put_api_requests.drive_fails.inc();
        return Err(Error::EmptyID);
    };

    let device_cfg = serde_json::from_slice::<BlockDeviceConfig>(body.raw()).map_err(|e| {
        METRICS.put_api_requests.drive_fails.inc();
        Error::SerdeJson(e)
    })?;

    if id != device_cfg.drive_id {
        METRICS.put_api_requests.drive_fails.inc();
        Err(Error::Generic(
            StatusCode::BadRequest,
            "The id from the path does not match the id from the body!".to_string(),
        ))
    } else {
        Ok(ParsedRequest::Sync(VmmAction::InsertBlockDevice(
            device_cfg,
        )))
    }
}

pub fn parse_patch_drive(body: &Body, id_from_path: Option<&&str>) -> Result<ParsedRequest, Error> {
    METRICS.patch_api_requests.drive_count.inc();
    let id = if let Some(id) = id_from_path {
        checked_id(id)?
    } else {
        METRICS.patch_api_requests.drive_fails.inc();
        return Err(Error::EmptyID);
    };

    let patch_drive_payload = PatchDrivePayload {
        fields: serde_json::from_slice(body.raw()).map_err(|e| {
            METRICS.patch_api_requests.drive_fails.inc();
            Error::SerdeJson(e)
        })?,
    };

    patch_drive_payload.validate()?;
    let drive_id: String = patch_drive_payload.get_string_field_unchecked("drive_id");
    let path_on_host: String = patch_drive_payload.get_string_field_unchecked("path_on_host");

    if id != drive_id.as_str() {
        METRICS.patch_api_requests.drive_fails.inc();
        return Err(Error::Generic(
            StatusCode::BadRequest,
            String::from("The id from the path does not match the id from the body!"),
        ));
    }

    Ok(ParsedRequest::Sync(VmmAction::UpdateBlockDevicePath(
        drive_id,
        path_on_host,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_patch_drive_request() {
        assert!(parse_patch_drive(&Body::new("invalid_payload"), None).is_err());
        assert!(parse_patch_drive(&Body::new("invalid_payload"), Some(&"id")).is_err());

        // PATCH with invalid fields.
        let body = r#"{
                "drive_id": "bar",
                "is_read_only": false
              }"#;
        assert!(parse_patch_drive(&Body::new(body), Some(&"2")).is_err());

        // PATCH with invalid types on fields. Adding a drive_id as number instead of string.
        let body = r#"{
                "drive_id": 1000,
                "path_on_host": "dummy"
              }"#;
        let res = parse_patch_drive(&Body::new(body), Some(&"1000"));
        assert!(res.is_err());

        // PATCH with invalid types on fields. Adding a path_on_host as bool instead of string.
        let body = r#"{
                "drive_id": 1000,
                "path_on_host": true
              }"#;
        let res = parse_patch_drive(&Body::new(body), Some(&"1000"));
        assert!(res.is_err());

        // PATCH with missing path_on_host field.
        let body = r#"{
                "drive_id": "dummy_id"
              }"#;
        let res = parse_patch_drive(&Body::new(body), Some(&"dummy_id"));
        assert!(res.is_err());

        // PATCH with missing drive_id field.
        let body = r#"{
                "path_on_host": true
              }"#;
        let res = parse_patch_drive(&Body::new(body), Some(&"1000"));
        assert!(res.is_err());

        // PATCH that tries to update something else other than path_on_host.
        let body = r#"{
                "drive_id": "dummy_id",
                "path_on_host": "dummy_host",
                "is_read_only": false
              }"#;
        let res = parse_patch_drive(&Body::new(body), Some(&"1234"));
        assert!(res.is_err());

        // PATCH with payload that is not a json.
        let body = r#"{
                "fields": "dummy_field"
              }"#;
        assert!(parse_patch_drive(&Body::new(body), Some(&"1234")).is_err());

        let body = r#"{
                "drive_id": "foo",
                "path_on_host": "dummy"
              }"#;
        #[allow(clippy::match_wild_err_arm)]
        match parse_patch_drive(&Body::new(body), Some(&"foo")) {
            Ok(ParsedRequest::Sync(VmmAction::UpdateBlockDevicePath(a, b))) => {
                assert_eq!(a, "foo".to_string());
                assert_eq!(b, "dummy".to_string());
            }
            Err(_e) => panic!("Test failed."),
            _ => panic!("Test failed: Invalid parameters"),
        };

        let body = r#"{
                "drive_id": "foo",
                "path_on_host": "dummy"
              }"#;
        assert!(parse_patch_drive(&Body::new(body), Some(&"bar")).is_err());
    }

    #[test]
    fn test_parse_put_drive_request() {
        assert!(parse_put_drive(&Body::new("invalid_payload"), None).is_err());
        assert!(parse_put_drive(&Body::new("invalid_payload"), Some(&"id")).is_err());

        // PATCH with invalid fields.
        let body = r#"{
                "drive_id": "bar",
                "is_read_only": false
              }"#;
        assert!(parse_put_drive(&Body::new(body), Some(&"2")).is_err());

        // PATCH with invalid types on fields. Adding a drive_id as number instead of string.
        let body = r#"{
                "drive_id": "1000",
                "path_on_host": "dummy",
                "is_root_device": true,
                "partuuid": "string",
                "is_read_only": true,
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
        assert!(parse_put_drive(&Body::new(body), Some(&"1000")).is_ok());

        assert!(parse_put_drive(&Body::new(body), Some(&"foo")).is_err());
    }

    #[test]
    fn test_validate() {
        let pdp = PatchDrivePayload {
            fields: Value::Null,
        };
        assert!(pdp.validate().is_err());
    }
}
