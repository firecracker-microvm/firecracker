use std::result;

use futures::sync::oneshot;
use hyper::{Response, StatusCode};

use http_service::{empty_response, json_fault_message, json_response};
use request::{ParsedRequest, SyncRequest};
use request::sync::GenerateResponse;

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub enum BootSourceType {
    LocalImage,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct LocalImage {
    pub kernel_image_path: String,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_response_put_boot_source_config_error() {
        assert_eq!(
            PutBootSourceConfigError::InvalidKernelPath
                .generate_response()
                .status(),
            StatusCode::BadRequest
        );
        assert_eq!(
            PutBootSourceConfigError::InvalidKernelCommandLine
                .generate_response()
                .status(),
            StatusCode::BadRequest
        );
    }

    #[test]
    fn test_generate_response_put_boot_source_outcome() {
        assert_eq!(
            PutBootSourceOutcome::Created.generate_response().status(),
            StatusCode::Created
        );
        assert_eq!(
            PutBootSourceOutcome::Updated.generate_response().status(),
            StatusCode::NoContent
        );
        assert_eq!(
            PutBootSourceOutcome::Error(PutBootSourceConfigError::InvalidKernelPath)
                .generate_response()
                .status(),
            StatusCode::BadRequest
        );
    }

    #[test]
    fn test_into_parsed_request() {
        let body = BootSourceBody {
            boot_source_id: String::from("/foo/bar"),
            source_type: BootSourceType::LocalImage,
            local_image: Some(LocalImage {
                kernel_image_path: String::from("/foo/bar"),
            }),
            boot_args: Some(String::from("foobar")),
        };
        let same_body = BootSourceBody {
            boot_source_id: String::from("/foo/bar"),
            source_type: BootSourceType::LocalImage,
            local_image: Some(LocalImage {
                kernel_image_path: String::from("/foo/bar"),
            }),
            boot_args: Some(String::from("foobar")),
        };
        let (sender, receiver) = oneshot::channel();
        assert!(body.into_parsed_request().eq(&Ok(ParsedRequest::Sync(
            SyncRequest::PutBootSource(same_body, sender),
            receiver
        ))))
    }
}
