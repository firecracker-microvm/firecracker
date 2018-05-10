use std::result;

use futures::sync::oneshot;
use hyper::{Method, Response, StatusCode};

use data_model::vm::boot_source::{BootSource, BootSourceError, PutBootSourceOutcome};
use http_service::{empty_response, json_fault_message, json_response};
use request::sync::GenerateResponse;
use request::{IntoParsedRequest, ParsedRequest, SyncRequest};

impl GenerateResponse for BootSourceError {
    fn generate_response(&self) -> Response {
        match *self {
            BootSourceError::InvalidKernelPath => json_response(
                StatusCode::BadRequest,
                json_fault_message("The kernel path is invalid!"),
            ),
            BootSourceError::InvalidKernelCommandLine => json_response(
                StatusCode::BadRequest,
                json_fault_message("The kernel command line is invalid!"),
            ),
        }
    }
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

impl IntoParsedRequest for BootSource {
    fn into_parsed_request(self, _method: Method) -> result::Result<ParsedRequest, String> {
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
    use serde_json;

    #[test]
    fn test_generate_response_put_boot_source_config_error() {
        assert_eq!(
            BootSourceError::InvalidKernelPath
                .generate_response()
                .status(),
            StatusCode::BadRequest
        );
        assert_eq!(
            BootSourceError::InvalidKernelCommandLine
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
            PutBootSourceOutcome::Error(BootSourceError::InvalidKernelPath)
                .generate_response()
                .status(),
            StatusCode::BadRequest
        );
    }

    #[test]
    fn test_into_parsed_request() {
        let body = r#"{
            "boot_source_id": "/foo/bar",
            "source_type": "LocalImage",
            "local_image": { "kernel_image_path": "/foo/bar"}
        }"#;
        let result1: Result<BootSource, serde_json::Error> = serde_json::from_str(body);
        assert!(result1.is_ok());

        let body = r#"{
            "boot_source_id": "/foo/bar",
            "source_type": "LocalImage",
            "local_image": { "kernel_image_path": "/foo/bar"}
        }"#;
        let result2: Result<BootSource, serde_json::Error> = serde_json::from_str(body);
        assert!(result2.is_ok());

        let (sender, receiver) = oneshot::channel();
        assert!(
            result1
                .unwrap()
                .into_parsed_request(Method::Put)
                .eq(&Ok(ParsedRequest::Sync(
                    SyncRequest::PutBootSource(result2.unwrap(), sender),
                    receiver
                )))
        )
    }
}
