use std::result;

use futures::sync::oneshot;
use hyper::{Method, Response, StatusCode};

use data_model::vm::{LoggerDescription, LoggerError, PutLoggerOutcome};
use http_service::{empty_response, json_fault_message, json_response};
use request::sync::GenerateResponse;
use request::{IntoParsedRequest, ParsedRequest, SyncRequest};

impl GenerateResponse for LoggerError {
    fn generate_response(&self) -> Response {
        use self::LoggerError::*;
        match *self {
            InitializationFailure(ref e) => json_response(
                StatusCode::BadRequest,
                json_fault_message(format!{"Cannot initialize logging system! {}", e}),
            ),
        }
    }
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

impl IntoParsedRequest for LoggerDescription {
    fn into_parsed_request(
        self,
        _method: Method,
        _id_from_path: Option<&str>,
    ) -> result::Result<ParsedRequest, String> {
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
            LoggerError::InitializationFailure("Could not initialize log system".to_string())
                .generate_response()
                .status(),
            StatusCode::BadRequest
        );
        assert!(
            format!(
                "{:?}",
                LoggerError::InitializationFailure("Could not initialize log system".to_string())
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
            PutLoggerOutcome::Error(LoggerError::InitializationFailure(
                "Could not initialize log system".to_string()
            )).generate_response()
                .status(),
            StatusCode::BadRequest
        );
    }

    #[test]
    fn test_into_parsed_request() {
        let desc = LoggerDescription {
            path: String::from(""),
            level: None,
            show_level: None,
            show_log_origin: None,
        };
        format!("{:?}", desc);
        assert!(&desc.clone().into_parsed_request(Method::Put, None).is_ok());
        let (sender, receiver) = oneshot::channel();
        assert!(&desc.clone()
            .into_parsed_request(Method::Put, None)
            .eq(&Ok(ParsedRequest::Sync(
                SyncRequest::PutLogger(desc, sender),
                receiver
            ))));
    }
}
