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
    pub fn into_parsed_request(self, _id_from_path: &str) -> result::Result<ParsedRequest, String> {
        // todo: any validation?
        let (sender, receiver) = oneshot::channel();
        Ok(ParsedRequest::Sync(
            SyncRequest::PutDrive(self, sender),
            receiver,
        ))
    }
}
