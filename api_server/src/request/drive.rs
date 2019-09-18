// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0<Paste>

use std::result;

use serde_json::{Map, Value};

use vmm::VmmAction;

use request::ParsedRequest;

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
    fn validate(&self) -> result::Result<(), String> {
        match self.fields.as_object() {
            Some(fields_map) => {
                // Check that field `drive_id` exists and its type is String.
                PatchDrivePayload::check_field_is_string(fields_map, "drive_id")?;
                // Check that field `drive_id` exists and its type is String.
                PatchDrivePayload::check_field_is_string(fields_map, "path_on_host")?;

                // Check that there are no other fields in the object.
                if fields_map.len() > 2 {
                    return Err(
                        "Invalid PATCH payload. Only updates on path_on_host are allowed."
                            .to_string(),
                    );
                }
                Ok(())
            }
            _ => Err("Invalid json.".to_string()),
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

    pub fn into_parsed_request(self, id_from_path: String) -> Result<ParsedRequest, String> {
        self.validate()?;
        let drive_id: String = self.get_string_field_unchecked("drive_id");
        let path_on_host: String = self.get_string_field_unchecked("path_on_host");

        if id_from_path != drive_id {
            return Err(String::from(
                "The id from the path does not match the id from the body!",
            ));
        }

        Ok(ParsedRequest::Sync(VmmAction::UpdateBlockDevicePath(
            drive_id,
            path_on_host,
        )))
    }
}

/*impl BlockDeviceConfig {
    pub fn into_parsed_request(
        self,
        id_from_path: String,
    ) -> result::Result<ParsedRequest, String> {
        let id_from_path = id_from_path.unwrap_or_default();
        if id_from_path != self.drive_id {
            return Err(String::from(
                "The id from the path does not match the id from the body!",
            ));
        }
        Ok(ParsedRequest::Sync(VmmAction::InsertBlockDevice(self)))
    }
}*/
