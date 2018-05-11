use std::result;

use futures::sync::oneshot;
use hyper::{Response, StatusCode};

use http_service::{empty_response, json_fault_message, json_response};
use request::sync::GenerateResponse;
use request::{ParsedRequest, SyncRequest};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum APILoggerLevel {
    Error,
    Warning,
    Info,
    Debug,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct APILoggerDescription {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<APILoggerLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub show_level: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub show_log_origin: Option<bool>,
}

#[derive(Debug)]
pub enum APILoggerError {
    InitializationFailure(String),
}

impl GenerateResponse for APILoggerError {
    fn generate_response(&self) -> Response {
        use self::APILoggerError::*;
        match *self {
            InitializationFailure(ref e) => json_response(
                StatusCode::BadRequest,
                json_fault_message(format!{"Cannot initialize logging system! {}", e}),
            ),
        }
    }
}

pub enum PutLoggerOutcome {
    Initialized,
    Error(APILoggerError),
}

impl GenerateResponse for PutLoggerOutcome {
    fn generate_response(&self) -> Response {
        use self::PutLoggerOutcome::*;
        match *self {
            Initialized => empty_response(StatusCode::Created),
            Error(ref e) => e.generate_response(),
        }
    }
}

impl APILoggerDescription {
    pub fn into_parsed_request(self) -> result::Result<ParsedRequest, String> {
        let (sender, receiver) = oneshot::channel();
        Ok(ParsedRequest::Sync(
            SyncRequest::PutLogger(self, sender),
            receiver,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_response_logger_error() {
        assert_eq!(
            APILoggerError::InitializationFailure("Could not initialize log system".to_string())
                .generate_response()
                .status(),
            StatusCode::BadRequest
        );
        assert!(
            format!(
                "{:?}",
                APILoggerError::InitializationFailure(
                    "Could not initialize log system".to_string()
                )
            ).contains("InitializationFailure")
        );
    }

    #[test]
    fn test_generate_response_put_logger_outcome() {
        assert_eq!(
            PutLoggerOutcome::Initialized.generate_response().status(),
            StatusCode::Created
        );
        assert_eq!(
            PutLoggerOutcome::Error(APILoggerError::InitializationFailure(
                "Could not initialize log system".to_string()
            )).generate_response()
                .status(),
            StatusCode::BadRequest
        );
    }

    #[test]
    fn test_into_parsed_request() {
        let desc = APILoggerDescription {
            path: String::from(""),
            level: None,
            show_level: None,
            show_log_origin: None,
        };
        format!("{:?}", desc);
        assert!(&desc.clone().into_parsed_request().is_ok());
        let (sender, receiver) = oneshot::channel();
        assert!(&desc.clone()
            .into_parsed_request()
            .eq(&Ok(ParsedRequest::Sync(
                SyncRequest::PutLogger(desc, sender),
                receiver
            ))));
    }
}
