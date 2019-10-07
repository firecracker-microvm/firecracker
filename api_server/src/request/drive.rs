// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0<Paste>

use serde_json::{Map, Value};

use super::super::VmmAction;
use logger::{Metric, METRICS};
use request::{Body, checked_id, Error, ParsedRequest, StatusCode};
use vmm::vmm_config::drive::BlockDeviceConfig;

#[derive(Clone)]
pub struct PatchDrivePayload {
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
                // Check that field `drive_id` exists and its type is String.
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
            .unwrap()
            .as_str()
            .unwrap()
            .to_string()
    }
}

pub fn parse_put_drive(
    maybe_body: Option<&Body>,
    id_from_path: Option<&&str>,
) -> Result<ParsedRequest, Error> {
    METRICS.put_api_requests.drive_count.inc();
    let id = match id_from_path {
        Some(&id) => checked_id(id)?,
        None => {
            return Err(Error::EmptyID);
        }
    };

    if let Some(body) = maybe_body {
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
    } else {
        Err(Error::Generic(
            StatusCode::BadRequest,
            "Empty PUT request.".to_string(),
        ))
    }
}

pub fn parse_patch_drive(
    maybe_body: Option<&Body>,
    id_from_path: Option<&&str>,
) -> Result<ParsedRequest, Error> {
    METRICS.patch_api_requests.drive_count.inc();
    let id = match id_from_path {
        Some(&id) => checked_id(id)?,
        None => {
            return Err(Error::EmptyID);
        }
    };

    if let Some(body) = maybe_body {
        METRICS.patch_api_requests.drive_count.inc();
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
    } else {
        Err(Error::Generic(
            StatusCode::BadRequest,
            "Empty PATCH request.".to_string(),
        ))
    }
}
