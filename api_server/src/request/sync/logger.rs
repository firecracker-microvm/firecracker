use std::result;

use futures::sync::oneshot;
use hyper::{Response, StatusCode};

use http_service::{empty_response, json_fault_message, json_response};
use request::{ParsedRequest, SyncRequest};
use request::sync::GenerateResponse;

#[derive(Debug, Deserialize, Serialize)]
pub enum APILoggerLevel {
    Error,
    Warning,
    Info,
    Debug,
}

#[derive(Debug, Deserialize, Serialize)]
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
