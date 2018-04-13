use std::result;

use futures::sync::oneshot;
use hyper::{Response, StatusCode};

use http_service::{empty_response, json_fault_message, json_response};
use request::{ParsedRequest, SyncRequest};
use request::sync::GenerateResponse;

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub enum BootSourceType {
    LocalImage,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct LocalImage {
    pub kernel_image_path: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct BootSourceBody {
    boot_source_id: String,
    source_type: BootSourceType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_image: Option<LocalImage>,
    // drive_boot to be added later
    // network_boot to be added later
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_args: Option<String>,
}

#[derive(Debug)]
pub enum PutBootSourceConfigError {
    InvalidKernelPath,
    InvalidKernelCommandLine,
}

impl GenerateResponse for PutBootSourceConfigError {
    fn generate_response(&self) -> Response {
        use self::PutBootSourceConfigError::*;
        match *self {
            InvalidKernelPath => json_response(
                StatusCode::BadRequest,
                json_fault_message("The kernel path is invalid!"),
            ),
            InvalidKernelCommandLine => json_response(
                StatusCode::BadRequest,
                json_fault_message("The kernel command line is invalid!"),
            ),
        }
    }
}

pub enum PutBootSourceOutcome {
    Created,
    Updated,
    Error(PutBootSourceConfigError),
}

impl GenerateResponse for PutBootSourceOutcome {
    fn generate_response(&self) -> Response {
        use self::PutBootSourceOutcome::*;
        match *self {
            Created => empty_response(StatusCode::Created),
            Updated => empty_response(StatusCode::NoContent),
            Error(ref e) => e.generate_response(),
        }
    }
}

impl BootSourceBody {
    pub fn into_parsed_request(self) -> result::Result<ParsedRequest, String> {
        let (sender, receiver) = oneshot::channel();
        Ok(ParsedRequest::Sync(
            SyncRequest::PutBootSource(self, sender),
            receiver,
        ))
    }
}
