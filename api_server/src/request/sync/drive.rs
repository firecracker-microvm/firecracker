use std::result;

use futures::sync::oneshot;
use hyper::{Response, StatusCode};

use request::ParsedRequest;
use http_service::{empty_response, json_fault_message, json_response};
use super::{DeviceState, GenerateResponse, SyncRequest};

// This struct represents the strongly typed equivalent of the json body from drive
// related requests.
#[derive(Debug, Deserialize, Serialize)]
pub struct DriveDescription {
    pub drive_id: String,
    pub path_on_host: String,
    pub state: DeviceState,
    pub is_root_device: bool,
}

#[derive(Debug)]
pub enum DriveError {
    RootBlockDeviceAlreadyAdded,
    InvalidBlockDevicePath,
    BlockDevicePathAlreadyExists,
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
                json_fault_message("The block device path was already added to a different drive!")
            ),
            NotImplemented => json_response(
                StatusCode::InternalServerError,
                json_fault_message("The update operation is not implemented!")
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
        use self::DriveError::*;
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
            return Err(String::from("The id from the path does not match the id from the path!"));
        }

        let (sender, receiver) = oneshot::channel();
        Ok(ParsedRequest::Sync(
            SyncRequest::PutDrive(self, sender),
            receiver,
        ))
    }
}
