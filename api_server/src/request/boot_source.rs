use std::result;

use futures::sync::oneshot;
use hyper::{Method, Response, StatusCode};

use http_service::{json_fault_message, json_response};
use request::{GenerateResponse, IntoParsedRequest, ParsedRequest, VmmAction};

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootSourceConfig {
    pub kernel_image_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_args: Option<String>,
}

#[derive(Debug)]
pub enum BootSourceConfigError {
    InvalidKernelPath,
    InvalidKernelCommandLine,
    UpdateNotAllowedPostBoot,
}

impl GenerateResponse for BootSourceConfigError {
    fn generate_response(&self) -> Response {
        use self::BootSourceConfigError::*;
        match *self {
            InvalidKernelPath => json_response(
                StatusCode::BadRequest,
                json_fault_message(
                    "The kernel file cannot \
                     be opened due to invalid kernel path or invalid permissions.",
                ),
            ),
            InvalidKernelCommandLine => json_response(
                StatusCode::BadRequest,
                json_fault_message("The kernel command line is invalid!"),
            ),
            UpdateNotAllowedPostBoot => json_response(
                StatusCode::BadRequest,
                json_fault_message("The update operation is not allowed after boot."),
            ),
        }
    }
}

impl IntoParsedRequest for BootSourceConfig {
    fn into_parsed_request(
        self,
        _: Option<String>,
        _: Method,
    ) -> result::Result<ParsedRequest, String> {
        let (sender, receiver) = oneshot::channel();
        Ok(ParsedRequest::Sync(
            VmmAction::ConfigureBootSource(self, sender),
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
            BootSourceConfigError::InvalidKernelPath
                .generate_response()
                .status(),
            StatusCode::BadRequest
        );
        assert_eq!(
            BootSourceConfigError::InvalidKernelCommandLine
                .generate_response()
                .status(),
            StatusCode::BadRequest
        );
    }

    #[test]
    fn test_into_parsed_request() {
        let body = BootSourceConfig {
            kernel_image_path: String::from("/foo/bar"),
            boot_args: Some(String::from("foobar")),
        };
        let same_body = BootSourceConfig {
            kernel_image_path: String::from("/foo/bar"),
            boot_args: Some(String::from("foobar")),
        };
        let (sender, receiver) = oneshot::channel();
        assert!(
            body.into_parsed_request(None, Method::Put)
                .eq(&Ok(ParsedRequest::Sync(
                    VmmAction::ConfigureBootSource(same_body, sender),
                    receiver
                )))
        )
    }
}
