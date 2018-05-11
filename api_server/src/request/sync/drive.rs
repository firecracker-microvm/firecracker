use std::result;

use futures::sync::oneshot;
use hyper::{Response, StatusCode};

use super::{DeviceState, GenerateResponse, SyncRequest};
use http_service::{empty_response, json_fault_message, json_response};
use request::ParsedRequest;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[allow(non_camel_case_types)]
pub enum DrivePermissions {
    ro,
    rw,
}

// This struct represents the strongly typed equivalent of the json body from drive
// related requests.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DriveDescription {
    pub drive_id: String,
    pub path_on_host: String,
    pub state: DeviceState,
    pub is_root_device: bool,
    pub permissions: DrivePermissions,
}

impl DriveDescription {
    pub fn is_read_only(&self) -> bool {
        self.permissions == DrivePermissions::ro
    }
}

#[derive(Debug)]
pub enum DriveError {
    RootBlockDeviceAlreadyAdded,
    InvalidBlockDevicePath,
    BlockDevicePathAlreadyExists,
    BlockDeviceUpdateFailed,
    BlockDeviceUpdateNotAllowed,
    NotImplemented,
}

impl GenerateResponse for DriveError {
    fn generate_response(&self) -> Response {
        use self::DriveError::*;
        match *self {
            RootBlockDeviceAlreadyAdded => json_response(
                StatusCode::BadRequest,
                json_fault_message("A root block device already exists!"),
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
                json_fault_message("The update operation is not allowed!"),
            ),
            NotImplemented => json_response(
                StatusCode::InternalServerError,
                json_fault_message("The operation is not implemented!"),
            ),
        }
    }
}

pub enum PutDriveOutcome {
    Created,
    Updated,
    Error(DriveError),
}

impl GenerateResponse for PutDriveOutcome {
    fn generate_response(&self) -> Response {
        use self::PutDriveOutcome::*;
        match *self {
            Created => empty_response(StatusCode::Created),
            Updated => empty_response(StatusCode::NoContent),
            Error(ref e) => e.generate_response(),
        }
    }
}

impl DriveDescription {
    pub fn into_parsed_request(self, id_from_path: &str) -> result::Result<ParsedRequest, String> {
        if id_from_path != self.drive_id {
            return Err(String::from(
                "The id from the path does not match the id from the body!",
            ));
        }

        let (sender, receiver) = oneshot::channel();
        Ok(ParsedRequest::Sync(
            SyncRequest::PutDrive(self, sender),
            receiver,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_read_only() {
        assert!(
            DriveDescription {
                drive_id: String::from("foo"),
                path_on_host: String::from("/foo/bar"),
                state: DeviceState::Attached,
                is_root_device: true,
                permissions: DrivePermissions::ro,
            }.is_read_only()
        );
    }

    #[test]
    fn test_generate_response_drive_error() {
        assert_eq!(
            DriveError::RootBlockDeviceAlreadyAdded
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
    }

    #[test]
    fn test_generate_response_put_drive_outcome() {
        assert_eq!(
            PutDriveOutcome::Created.generate_response().status(),
            StatusCode::Created
        );
        assert_eq!(
            PutDriveOutcome::Updated.generate_response().status(),
            StatusCode::NoContent
        );
        assert_eq!(
            PutDriveOutcome::Error(DriveError::NotImplemented)
                .generate_response()
                .status(),
            StatusCode::InternalServerError
        );
    }

    #[test]
    fn test_into_parsed_request() {
        let desc = DriveDescription {
            drive_id: String::from("foo"),
            path_on_host: String::from("/foo/bar"),
            state: DeviceState::Attached,
            is_root_device: true,
            permissions: DrivePermissions::ro,
        };

        assert!(&desc.clone().into_parsed_request("bar").is_err());
        let (sender, receiver) = oneshot::channel();
        assert!(&desc.clone()
            .into_parsed_request("foo")
            .eq(&Ok(ParsedRequest::Sync(
                SyncRequest::PutDrive(desc, sender),
                receiver
            ))));
    }
}
