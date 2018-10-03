use std::result;

use futures::sync::oneshot;
use hyper::{Method, Response, StatusCode};
use serde_json::Value;

use data_model::vm::{BlockDeviceConfig, DriveError};

use super::{GenerateResponse, SyncRequest};
use http_service::{empty_response, json_fault_message, json_response};
use request::{IntoParsedRequest, ParsedRequest};

#[derive(PartialEq)]
pub enum PatchDriveOutcome {
    Updated,
}

#[derive(Clone)]
pub struct PatchDrivePayload {
    // Leaving `fields` pub because ownership on it needs to be yielded to the
    // Request enum object. A getter couldn't move `fields` out of the borrowed
    // PatchDrivePayload object.
    pub fields: Value,
}

/// Validates that only path_on_host and drive_id are present in the payload.
fn validate_payload(fields: &Value) -> result::Result<(), String> {
    match fields {
        Value::Object(fields_map) => {
            for key in fields_map.keys() {
                if key != "drive_id" && key != "path_on_host" {
                    return Err(format!(
                        "Cannot update {:?} with PATCH. Only updates on path_on_host are allowed.",
                        key
                    ));
                }
            }
            Ok(())
        }
        _ => Err("Invalid json.".to_string()),
    }
}

impl IntoParsedRequest for PatchDrivePayload {
    fn into_parsed_request(self, method: Method) -> result::Result<ParsedRequest, String> {
        match method {
            Method::Patch => {
                validate_payload(&self.fields)?;
                let (sender, receiver) = oneshot::channel();
                Ok(ParsedRequest::Sync(
                    SyncRequest::PatchDrive(self.fields, sender),
                    receiver,
                ))
            }
            _ => Err(format!("Invalid method {}!", method)),
        }
    }
}

impl GenerateResponse for PatchDriveOutcome {
    fn generate_response(&self) -> Response {
        use self::PatchDriveOutcome::*;
        match *self {
            Updated => empty_response(StatusCode::NoContent),
        }
    }
}

impl IntoParsedRequest for BlockDeviceConfig {
    fn into_parsed_request(self, method: Method) -> result::Result<ParsedRequest, String> {
        let (sender, receiver) = oneshot::channel();
        match method {
            Method::Put => Ok(ParsedRequest::Sync(
                SyncRequest::PutDrive(self, sender),
                receiver,
            )),
            _ => Ok(ParsedRequest::Dummy),
        }
    }
}

impl GenerateResponse for DriveError {
    fn generate_response(&self) -> Response {
        use self::DriveError::*;
        match *self {
            InvalidBlockDeviceID => json_response(
                StatusCode::BadRequest,
                json_fault_message("Invalid block device ID!"),
            ),
            InvalidBlockDevicePath => json_response(
                StatusCode::BadRequest,
                json_fault_message("Invalid block device path!"),
            ),
            BlockDevicePathAlreadyExists => json_response(
                StatusCode::BadRequest,
                json_fault_message("The block device path was already added to a different drive!"),
            ),
            BlockDeviceUpdateFailed => json_response(
                StatusCode::InternalServerError,
                json_fault_message("The update operation failed!"),
            ),
            BlockDeviceUpdateNotAllowed => json_response(
                StatusCode::Forbidden,
                json_fault_message("The block device update operation is not allowed!"),
            ),
            NotImplemented => json_response(
                StatusCode::InternalServerError,
                json_fault_message("The operation is not implemented!"),
            ),
            OperationNotAllowedPreBoot => json_response(
                StatusCode::BadRequest,
                json_fault_message("Operation not allowed pre-boot!"),
            ),
            RootBlockDeviceAlreadyAdded => json_response(
                StatusCode::BadRequest,
                json_fault_message("A root block device already exists!"),
            ),
            SerdeJson => json_response(
                StatusCode::BadRequest,
                json_fault_message("Invalid request body!"),
            ),
            UpdateNotAllowedPostBoot => json_response(
                StatusCode::BadRequest,
                json_fault_message("The update operation is not allowed after boot."),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::Map;
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
        assert!(patch_payload.into_parsed_request(Method::Patch).is_err());

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
                .into_parsed_request(Method::Patch)
                .eq(&Ok(ParsedRequest::Sync(
                    SyncRequest::PatchDrive(pdp.fields.clone(), sender),
                    receiver
                )))
        );

        assert!(pdp.into_parsed_request(Method::Put).is_err());
    }

    #[test]
    fn test_generate_response_drive_error() {
        assert_eq!(
            DriveError::InvalidBlockDeviceID
                .generate_response()
                .status(),
            StatusCode::BadRequest
        );
        assert_eq!(
            DriveError::InvalidBlockDevicePath
                .generate_response()
                .status(),
            StatusCode::BadRequest
        );
        assert_eq!(
            DriveError::BlockDevicePathAlreadyExists
                .generate_response()
                .status(),
            StatusCode::BadRequest
        );
        assert_eq!(
            DriveError::BlockDeviceUpdateFailed
                .generate_response()
                .status(),
            StatusCode::InternalServerError
        );
        assert_eq!(
            DriveError::BlockDeviceUpdateNotAllowed
                .generate_response()
                .status(),
            StatusCode::Forbidden
        );
        assert_eq!(
            DriveError::NotImplemented.generate_response().status(),
            StatusCode::InternalServerError
        );
        assert_eq!(
            DriveError::RootBlockDeviceAlreadyAdded
                .generate_response()
                .status(),
            StatusCode::BadRequest
        );
        assert_eq!(
            DriveError::SerdeJson.generate_response().status(),
            StatusCode::BadRequest
        );
        assert_eq!(
            DriveError::UpdateNotAllowedPostBoot
                .generate_response()
                .status(),
            StatusCode::BadRequest
        );
    }

    #[test]
    fn test_generate_response_patch_drive_outcome() {
        assert_eq!(
            PatchDriveOutcome::Updated.generate_response().status(),
            StatusCode::NoContent
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
                .into_parsed_request(Method::Options)
                .eq(&Ok(ParsedRequest::Dummy))
        );
        let (sender, receiver) = oneshot::channel();
        assert!(
            &desc
                .clone()
                .into_parsed_request(Method::Put)
                .eq(&Ok(ParsedRequest::Sync(
                    SyncRequest::PutDrive(desc, sender),
                    receiver
                )))
        );
    }
}
