use futures::sync::oneshot;
use hyper::{Method, Response, StatusCode};
use std::result;

use data_model::device_config::{DriveConfig, DriveError, PutDriveOutcome};
use http_service::{empty_response, json_fault_message, json_response};
use request::sync::GenerateResponse;
use request::{IntoParsedRequest, ParsedRequest, SyncRequest};

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

impl IntoParsedRequest for DriveConfig {
    fn into_parsed_request(
        self,
        _method: Method,
        id_from_path: Option<&str>,
    ) -> result::Result<ParsedRequest, String> {
        if id_from_path.is_some() && id_from_path.unwrap() != self.get_id() {
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
    extern crate serde_json;

    use super::*;

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
        let json = "{
                \"drive_id\": \"foo\",
                \"path_on_host\": \"/foo/bar\",
                \"state\": \"Attached\",
                \"is_root_device\": true,
                \"permissions\": \"ro\"
              }";
        let result: result::Result<DriveConfig, serde_json::Error> = serde_json::from_str(json);
        assert!(result.is_ok());
        let desc = result.unwrap();

        let (sender, receiver) = oneshot::channel();
        assert!(&desc.clone()
            .into_parsed_request(Method::Put, Some("foo"))
            .eq(&Ok(ParsedRequest::Sync(
                SyncRequest::PutDrive(desc, sender),
                receiver
            ))));
    }
}
