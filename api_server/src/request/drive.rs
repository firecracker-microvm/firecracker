use std::result;

use futures::sync::oneshot;
use hyper::Method;
use serde_json::{Map, Value};

use vmm::vmm_config::drive::BlockDeviceConfig;
use vmm::VmmAction;

use request::{IntoParsedRequest, ParsedRequest};

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
}

impl IntoParsedRequest for PatchDrivePayload {
    fn into_parsed_request(
        self,
        id_from_path: Option<String>,
        method: Method,
    ) -> result::Result<ParsedRequest, String> {
        match method {
            Method::Patch => {
                self.validate()?;
                let drive_id: String = self.get_string_field_unchecked("drive_id");
                let path_on_host: String = self.get_string_field_unchecked("path_on_host");

                let id_from_path = id_from_path.unwrap_or(String::new());
                if id_from_path != drive_id {
                    return Err(String::from(
                        "The id from the path does not match the id from the body!",
                    ));
                }

                let (sender, receiver) = oneshot::channel();
                Ok(ParsedRequest::Sync(
                    VmmAction::UpdateBlockDevicePath(drive_id, path_on_host, sender),
                    receiver,
                ))
            }
            _ => Err(format!("Invalid method {}!", method)),
        }
    }
}

impl IntoParsedRequest for BlockDeviceConfig {
    fn into_parsed_request(
        self,
        id_from_path: Option<String>,
        method: Method,
    ) -> result::Result<ParsedRequest, String> {
        let id_from_path = id_from_path.unwrap_or(String::new());
        if id_from_path != self.drive_id {
            return Err(String::from(
                "The id from the path does not match the id from the body!",
            ));
        }
        let (sender, receiver) = oneshot::channel();
        match method {
            Method::Put => Ok(ParsedRequest::Sync(
                VmmAction::InsertBlockDevice(self, sender),
                receiver,
            )),
            _ => Err(String::from("Invalid method.")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::Number;
    use std::path::PathBuf;

    #[test]
    fn test_patch_into_parsed_request() {
        // PATCH with invalid fields.
        let mut payload_map = Map::<String, Value>::new();
        payload_map.insert(String::from("drive_id"), Value::String(String::from("bar")));
        payload_map.insert(String::from("is_read_only"), Value::Bool(false));
        let patch_payload = PatchDrivePayload {
            fields: Value::Object(payload_map),
        };
        let expected_err = Err("Required key path_on_host not present in the json.".to_string());
        assert!(patch_payload.into_parsed_request(None, Method::Patch) == expected_err);

        // PATCH with invalid types on fields. Adding a drive_id as number instead of string.
        let mut payload_map = Map::<String, Value>::new();
        payload_map.insert(String::from("drive_id"), Value::Number(Number::from(1000)));
        payload_map.insert(
            String::from("path_on_host"),
            Value::String(String::from("dummy")),
        );
        let patch_payload = PatchDrivePayload {
            fields: Value::Object(payload_map),
        };
        let expected_err = Err("Invalid type for key drive_id.".to_string());
        assert!(patch_payload.into_parsed_request(None, Method::Patch) == expected_err);

        // PATCH with invalid types on fields. Adding a path_on_host as bool instead of string.
        let mut payload_map = Map::<String, Value>::new();
        payload_map.insert(
            String::from("drive_id"),
            Value::String(String::from("dummy_id")),
        );
        payload_map.insert(String::from("path_on_host"), Value::Bool(true));
        let patch_payload = PatchDrivePayload {
            fields: Value::Object(payload_map),
        };
        assert!(
            patch_payload
                .into_parsed_request(None, Method::Patch)
                .is_err()
        );

        // PATCH with missing path_on_host field.
        let mut payload_map = Map::<String, Value>::new();
        payload_map.insert(
            String::from("drive_id"),
            Value::String(String::from("dummy_id")),
        );
        let patch_payload = PatchDrivePayload {
            fields: Value::Object(payload_map),
        };
        let expected_err = Err("Required key path_on_host not present in the json.".to_string());
        assert!(patch_payload.into_parsed_request(None, Method::Patch) == expected_err);

        // PATCH with missing drive_id field.
        let mut payload_map = Map::<String, Value>::new();
        payload_map.insert(String::from("path_on_host"), Value::Bool(true));
        let patch_payload = PatchDrivePayload {
            fields: Value::Object(payload_map),
        };
        let expected_err = Err("Required key drive_id not present in the json.".to_string());
        assert!(patch_payload.into_parsed_request(None, Method::Patch) == expected_err);

        // PATCH that tries to update something else other than path_on_host.
        let mut payload_map = Map::new();
        payload_map.insert(
            String::from("drive_id"),
            Value::String(String::from("1234")),
        );
        payload_map.insert(
            String::from("path_on_host"),
            Value::String(String::from("dummy")),
        );
        payload_map.insert(String::from("is_read_only"), Value::Bool(false));

        let patch_payload = PatchDrivePayload {
            fields: Value::Object(payload_map),
        };
        let expected_err =
            Err("Invalid PATCH payload. Only updates on path_on_host are allowed.".to_string());
        assert!(patch_payload.into_parsed_request(None, Method::Patch) == expected_err);

        // PATCH with payload that is not a json.
        let patch_payload = PatchDrivePayload {
            fields: Value::String(String::from("dummy_payload")),
        };
        assert!(
            patch_payload.into_parsed_request(None, Method::Patch)
                == Err("Invalid json.".to_string())
        );

        let mut payload_map = Map::<String, Value>::new();
        payload_map.insert(String::from("drive_id"), Value::String(String::from("foo")));
        payload_map.insert(
            String::from("path_on_host"),
            Value::String(String::from("dummy")),
        );
        let pdp = PatchDrivePayload {
            fields: Value::Object(payload_map),
        };
        let (sender, receiver) = oneshot::channel();

        assert!(
            pdp.clone()
                .into_parsed_request(Some("foo".to_string()), Method::Patch)
                .eq(&Ok(ParsedRequest::Sync(
                    VmmAction::UpdateBlockDevicePath(
                        "foo".to_string(),
                        "dummy".to_string(),
                        sender
                    ),
                    receiver
                )))
        );

        assert!(
            pdp.into_parsed_request(None, Method::Put) == Err(String::from("Invalid method PUT!"))
        );
    }

    #[test]
    fn test_into_parsed_request() {
        let desc = BlockDeviceConfig {
            drive_id: String::from("foo"),
            path_on_host: PathBuf::from(String::from("/foo/bar")),
            is_root_device: true,
            is_read_only: true,
            partuuid: None,
            rate_limiter: None,
        };

        assert!(
            &desc
                .clone()
                .into_parsed_request(Some(String::from("foo")), Method::Options)
                == &Err(String::from("Invalid method."))
        );
        let (sender, receiver) = oneshot::channel();
        assert!(
            &desc
                .clone()
                .into_parsed_request(Some(String::from("foo")), Method::Put)
                .eq(&Ok(ParsedRequest::Sync(
                    VmmAction::InsertBlockDevice(desc, sender),
                    receiver
                )))
        );
    }
}
