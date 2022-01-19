// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::ser::Serialize;
use serde_json::Value;

use super::VmmData;
use crate::request::actions::parse_put_actions;
use crate::request::balloon::{parse_get_balloon, parse_patch_balloon, parse_put_balloon};
use crate::request::boot_source::parse_put_boot_source;
use crate::request::drive::{parse_patch_drive, parse_put_drive};
use crate::request::instance_info::parse_get_instance_info;
use crate::request::logger::parse_put_logger;
use crate::request::machine_configuration::{
    parse_get_machine_config, parse_patch_machine_config, parse_put_machine_config,
};
use crate::request::metrics::parse_put_metrics;
use crate::request::mmds::{parse_get_mmds, parse_patch_mmds, parse_put_mmds};
use crate::request::net::{parse_patch_net, parse_put_net};
use crate::request::snapshot::parse_patch_vm_state;
use crate::request::snapshot::parse_put_snapshot;
use crate::request::version::parse_get_version;
use crate::request::vsock::parse_put_vsock;
use crate::ApiServer;
use micro_http::{Body, Method, Request, Response, StatusCode, Version};

use logger::{error, info};
use vmm::rpc_interface::{VmmAction, VmmActionError};

pub(crate) enum RequestAction {
    GetMMDS,
    PatchMMDS(Value),
    PutMMDS(Value),
    Sync(Box<VmmAction>),
    ShutdownInternal, // !!! not an API, used by shutdown to thread::join the API thread
}

#[derive(Default)]
#[cfg_attr(test, derive(PartialEq))]
pub(crate) struct ParsingInfo {
    deprecation_message: Option<String>,
}

impl ParsingInfo {
    pub fn append_deprecation_message(&mut self, message: &str) {
        match self.deprecation_message.as_mut() {
            None => self.deprecation_message = Some(message.to_owned()),
            Some(s) => (*s).push_str(message),
        }
    }

    pub fn take_deprecation_message(&mut self) -> Option<String> {
        self.deprecation_message.take()
    }
}

pub(crate) struct ParsedRequest {
    action: RequestAction,
    parsing_info: ParsingInfo,
}

impl ParsedRequest {
    pub(crate) fn new(action: RequestAction) -> Self {
        Self {
            action,
            parsing_info: Default::default(),
        }
    }

    pub(crate) fn into_parts(self) -> (RequestAction, ParsingInfo) {
        (self.action, self.parsing_info)
    }

    pub(crate) fn parsing_info(&mut self) -> &mut ParsingInfo {
        &mut self.parsing_info
    }

    pub(crate) fn try_from_request(request: &Request) -> Result<ParsedRequest, Error> {
        let request_uri = request.uri().get_abs_path().to_string();
        log_received_api_request(describe(
            request.method(),
            request_uri.as_str(),
            request.body.as_ref(),
        ));

        // Split request uri by '/' by doing:
        // 1. Trim starting '/' characters
        // 2. Splitting by '/'
        let path_tokens: Vec<&str> = request_uri
            .trim_start_matches('/')
            .split_terminator('/')
            .collect();
        let path = if path_tokens.is_empty() {
            ""
        } else {
            path_tokens[0]
        };

        match (request.method(), path, request.body.as_ref()) {
            (Method::Get, "", None) => parse_get_instance_info(),
            (Method::Get, "balloon", None) => parse_get_balloon(path_tokens.get(1)),
            (Method::Get, "version", None) => parse_get_version(),
            (Method::Get, "vm", None) if path_tokens.get(1) == Some(&"config") => {
                Ok(ParsedRequest::new_sync(VmmAction::GetFullVmConfig))
            }
            (Method::Get, "machine-config", None) => parse_get_machine_config(),
            (Method::Get, "mmds", None) => parse_get_mmds(),
            (Method::Get, _, Some(_)) => method_to_error(Method::Get),
            (Method::Put, "actions", Some(body)) => parse_put_actions(body),
            (Method::Put, "balloon", Some(body)) => parse_put_balloon(body),
            (Method::Put, "boot-source", Some(body)) => parse_put_boot_source(body),
            (Method::Put, "drives", Some(body)) => parse_put_drive(body, path_tokens.get(1)),
            (Method::Put, "logger", Some(body)) => parse_put_logger(body),
            (Method::Put, "machine-config", Some(body)) => parse_put_machine_config(body),
            (Method::Put, "metrics", Some(body)) => parse_put_metrics(body),
            (Method::Put, "mmds", Some(body)) => parse_put_mmds(body, path_tokens.get(1)),
            (Method::Put, "network-interfaces", Some(body)) => {
                parse_put_net(body, path_tokens.get(1))
            }
            (Method::Put, "shutdown-internal", None) => {
                Ok(ParsedRequest::new(RequestAction::ShutdownInternal))
            }
            (Method::Put, "snapshot", Some(body)) => parse_put_snapshot(body, path_tokens.get(1)),
            (Method::Put, "vsock", Some(body)) => parse_put_vsock(body),
            (Method::Put, _, None) => method_to_error(Method::Put),
            (Method::Patch, "balloon", Some(body)) => parse_patch_balloon(body, path_tokens.get(1)),
            (Method::Patch, "drives", Some(body)) => parse_patch_drive(body, path_tokens.get(1)),
            (Method::Patch, "machine-config", Some(body)) => parse_patch_machine_config(body),
            (Method::Patch, "mmds", Some(body)) => parse_patch_mmds(body),
            (Method::Patch, "network-interfaces", Some(body)) => {
                parse_patch_net(body, path_tokens.get(1))
            }
            (Method::Patch, "vm", Some(body)) => parse_patch_vm_state(body),
            (Method::Patch, _, None) => method_to_error(Method::Patch),
            (method, unknown_uri, _) => {
                Err(Error::InvalidPathMethod(unknown_uri.to_string(), method))
            }
        }
    }

    pub(crate) fn success_response_with_data<T>(body_data: &T) -> Response
    where
        T: ?Sized + Serialize,
    {
        info!("The request was executed successfully. Status code: 200 OK.");
        let mut response = Response::new(Version::Http11, StatusCode::OK);
        response.set_body(Body::new(serde_json::to_string(body_data).unwrap()));
        response
    }

    pub(crate) fn convert_to_response(
        request_outcome: &std::result::Result<VmmData, VmmActionError>,
    ) -> Response {
        match request_outcome {
            Ok(vmm_data) => match vmm_data {
                VmmData::Empty => {
                    info!("The request was executed successfully. Status code: 204 No Content.");
                    Response::new(Version::Http11, StatusCode::NoContent)
                }
                VmmData::MachineConfiguration(vm_config) => {
                    Self::success_response_with_data(vm_config)
                }
                VmmData::BalloonConfig(balloon_config) => {
                    Self::success_response_with_data(balloon_config)
                }
                VmmData::BalloonStats(stats) => Self::success_response_with_data(stats),
                VmmData::InstanceInformation(info) => Self::success_response_with_data(info),
                VmmData::VmmVersion(version) => Self::success_response_with_data(
                    &serde_json::json!({ "firecracker_version": version.as_str() }),
                ),
                VmmData::FullVmConfig(config) => Self::success_response_with_data(config),
            },
            Err(vmm_action_error) => {
                error!(
                    "Received Error. Status code: 400 Bad Request. Message: {}",
                    vmm_action_error
                );
                let mut response = Response::new(Version::Http11, StatusCode::BadRequest);
                response.set_body(Body::new(ApiServer::json_fault_message(
                    vmm_action_error.to_string(),
                )));
                response
            }
        }
    }

    /// Helper function to avoid boiler-plate code.
    pub(crate) fn new_sync(vmm_action: VmmAction) -> ParsedRequest {
        ParsedRequest::new(RequestAction::Sync(Box::new(vmm_action)))
    }
}

/// Helper function for writing the received API requests to the log.
///
/// The `info` macro is used for logging.
#[inline]
fn log_received_api_request(api_description: String) {
    info!("The API server received a {}.", api_description);
}

/// Helper function for metric-logging purposes on API requests.
///
/// # Arguments
///
/// * `method` - one of `GET`, `PATCH`, `PUT`
/// * `path` - path of the API request
/// * `body` - body of the API request
fn describe(method: Method, path: &str, body: Option<&Body>) -> String {
    match (path, body) {
        ("/mmds", Some(_)) | (_, None) => format!("{:?} request on {:?}", method, path),
        (_, Some(value)) => format!(
            "{:?} request on {:?} with body {:?}",
            method,
            path,
            std::str::from_utf8(value.body.as_slice())
                .unwrap_or("inconvertible to UTF-8")
                .to_string()
        ),
    }
}

/// Generates a `GenericError` for each request method.
pub(crate) fn method_to_error(method: Method) -> Result<ParsedRequest, Error> {
    match method {
        Method::Get => Err(Error::Generic(
            StatusCode::BadRequest,
            "GET request cannot have a body.".to_string(),
        )),
        Method::Put => Err(Error::Generic(
            StatusCode::BadRequest,
            "Empty PUT request.".to_string(),
        )),
        Method::Patch => Err(Error::Generic(
            StatusCode::BadRequest,
            "Empty PATCH request.".to_string(),
        )),
    }
}

#[derive(Debug)]
pub(crate) enum Error {
    // A generic error, with a given status code and message to be turned into a fault message.
    Generic(StatusCode, String),
    // The resource ID is empty.
    EmptyID,
    // The resource ID must only contain alphanumeric characters and '_'.
    InvalidID,
    // The HTTP method & request path combination is not valid.
    InvalidPathMethod(String, Method),
    // An error occurred when deserializing the json body of a request.
    SerdeJson(serde_json::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Generic(_, ref desc) => write!(f, "{}", desc),
            Error::EmptyID => write!(f, "The ID cannot be empty."),
            Error::InvalidID => write!(
                f,
                "API Resource IDs can only contain alphanumeric characters and underscores."
            ),
            Error::InvalidPathMethod(ref path, ref method) => write!(
                f,
                "Invalid request method and/or path: {} {}.",
                std::str::from_utf8(method.raw()).expect("Cannot convert from UTF-8"),
                path
            ),
            Error::SerdeJson(ref e) => write!(
                f,
                "An error occurred when deserializing the json body of a request: {}.",
                e
            ),
        }
    }
}

// It's convenient to turn errors into HTTP responses directly.
impl From<Error> for Response {
    fn from(e: Error) -> Self {
        let msg = ApiServer::json_fault_message(format!("{}", e));
        match e {
            Error::Generic(status, _) => ApiServer::json_response(status, msg),
            Error::EmptyID
            | Error::InvalidID
            | Error::InvalidPathMethod(_, _)
            | Error::SerdeJson(_) => ApiServer::json_response(StatusCode::BadRequest, msg),
        }
    }
}

// This function is supposed to do id validation for requests.
pub(crate) fn checked_id(id: &str) -> Result<&str, Error> {
    // todo: are there any checks we want to do on id's?
    // not allow them to be empty strings maybe?
    // check: ensure string is not empty
    if id.is_empty() {
        return Err(Error::EmptyID);
    }
    // check: ensure string is alphanumeric
    if !id.chars().all(|c| c == '_' || c.is_alphanumeric()) {
        return Err(Error::InvalidID);
    }
    Ok(id)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::io::{Cursor, Write};
    use std::os::unix::net::UnixStream;
    use std::str::FromStr;

    use micro_http::HttpConnection;
    use vmm::builder::StartMicrovmError;
    use vmm::resources::VmmConfig;
    use vmm::rpc_interface::VmmActionError;
    use vmm::vmm_config::balloon::{BalloonDeviceConfig, BalloonStats};
    use vmm::vmm_config::instance_info::InstanceInfo;
    use vmm::vmm_config::machine_config::VmConfig;

    impl PartialEq for ParsedRequest {
        fn eq(&self, other: &ParsedRequest) -> bool {
            if self.parsing_info.deprecation_message != other.parsing_info.deprecation_message {
                return false;
            }

            match (&self.action, &other.action) {
                (RequestAction::Sync(ref sync_req), RequestAction::Sync(ref other_sync_req)) => {
                    sync_req == other_sync_req
                }
                (RequestAction::GetMMDS, RequestAction::GetMMDS) => true,
                (RequestAction::PutMMDS(ref val), RequestAction::PutMMDS(ref other_val)) => {
                    val == other_val
                }
                (RequestAction::PatchMMDS(ref val), RequestAction::PatchMMDS(ref other_val)) => {
                    val == other_val
                }

                _ => false,
            }
        }
    }

    pub(crate) fn vmm_action_from_request(req: ParsedRequest) -> VmmAction {
        match req.action {
            RequestAction::Sync(vmm_action) => *vmm_action,
            _ => panic!("Invalid request"),
        }
    }

    pub(crate) fn depr_action_from_req(req: ParsedRequest, msg: Option<String>) -> VmmAction {
        let (action_req, mut parsing_info) = req.into_parts();
        match action_req {
            RequestAction::Sync(vmm_action) => {
                let req_msg = parsing_info.take_deprecation_message();
                assert!(req_msg.is_some());
                assert_eq!(req_msg, msg);
                *vmm_action
            }
            _ => panic!("Invalid request"),
        }
    }

    fn http_response(body: &str, status_code: i32) -> String {
        let header = format!(
            "HTTP/1.1 {} \r\n\
             Server: Firecracker API\r\n\
             Connection: keep-alive\r\n",
            status_code
        );
        if status_code == 204 {
            // No Content
            return format!("{}{}", header, "\r\n");
        } else {
            let content = format!(
                "Content-Type: application/json\r\n\
                Content-Length: {}\r\n\r\n{}",
                body.len(),
                body,
            );

            format!("{}{}", header, content)
        }
    }

    fn http_request(request_type: &str, endpoint: &str, body: Option<&str>) -> String {
        let req_no_body = format!(
            "{} {} HTTP/1.1\r\n\
            Content-Type: application/json\r\n",
            request_type, endpoint
        );
        if body.is_some() {
            return format!(
                "{}\
                Content-Length: {}\r\n\r\n\
                {}",
                req_no_body,
                body.unwrap().len(),
                body.unwrap()
            );
        }
        return format!("{}\r\n", req_no_body,);
    }

    #[test]
    fn test_missing_slash() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(http_request("GET", "none", Some("body")).as_bytes())
            .unwrap();
        assert!(connection.try_read().is_ok());

        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_err());
    }

    #[test]
    fn test_checked_id() {
        assert!(checked_id("dummy").is_ok());
        assert!(checked_id("dummy_1").is_ok());

        assert_eq!(
            format!("{}", checked_id("").unwrap_err()),
            "The ID cannot be empty."
        );
        assert_eq!(
            format!("{}", checked_id("dummy!!").unwrap_err()),
            "API Resource IDs can only contain alphanumeric characters and underscores."
        );
    }

    #[test]
    fn test_invalid_get() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(http_request("GET", "/mmds", Some("body")).as_bytes())
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        if let Err(Error::Generic(StatusCode::BadRequest, err_msg)) =
            ParsedRequest::try_from_request(&req)
        {
            assert_eq!(err_msg, "GET request cannot have a body.");
        } else {
            panic!("GET request with body failed the tests.")
        }
    }

    #[test]
    fn test_invalid_put() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(http_request("PUT", "/mmds", None).as_bytes())
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        if let Err(Error::Generic(StatusCode::BadRequest, err_msg)) =
            ParsedRequest::try_from_request(&req)
        {
            assert_eq!(err_msg, "Empty PUT request.");
        } else {
            panic!("Empty PUT request failed the tests.");
        };
    }

    #[test]
    fn test_invalid_patch() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(http_request("PATCH", "/mmds", None).as_bytes())
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        if let Err(Error::Generic(StatusCode::BadRequest, err_msg)) =
            ParsedRequest::try_from_request(&req)
        {
            assert_eq!(err_msg, "Empty PATCH request.");
        } else {
            panic!("Empty PATCH request failed the tests.");
        };
    }

    #[test]
    fn test_error_into_response() {
        // Generic error.
        let mut buf = Cursor::new(vec![0]);
        let response: Response =
            Error::Generic(StatusCode::BadRequest, "message".to_string()).into();
        assert!(response.write_all(&mut buf).is_ok());
        let body = ApiServer::json_fault_message("message");
        let expected_response = http_response(&body, 400);
        assert_eq!(buf.into_inner(), expected_response.as_bytes());

        // Empty ID error.
        let mut buf = Cursor::new(vec![0]);
        let response: Response = Error::EmptyID.into();
        assert!(response.write_all(&mut buf).is_ok());
        let body = ApiServer::json_fault_message("The ID cannot be empty.");
        let expected_response = http_response(&body, 400);
        assert_eq!(buf.into_inner(), expected_response.as_bytes());

        // Invalid ID error.
        let mut buf = Cursor::new(vec![0]);
        let response: Response = Error::InvalidID.into();
        assert!(response.write_all(&mut buf).is_ok());
        let body = ApiServer::json_fault_message(
            "API Resource IDs can only contain alphanumeric characters and underscores.",
        );
        let expected_response = http_response(&body, 400);
        assert_eq!(buf.into_inner(), expected_response.as_bytes());

        // Invalid path or method error.
        let mut buf = Cursor::new(vec![0]);
        let response: Response = Error::InvalidPathMethod("path".to_string(), Method::Get).into();
        assert!(response.write_all(&mut buf).is_ok());
        let body = ApiServer::json_fault_message(format!(
            "Invalid request method and/or path: {} {}.",
            std::str::from_utf8(Method::Get.raw()).unwrap(),
            "path"
        ));
        let expected_response = http_response(&body, 400);
        assert_eq!(buf.into_inner(), expected_response.as_bytes());

        // Serde error.
        let mut buf = Cursor::new(vec![0]);
        let serde_error = serde_json::Value::from_str("").unwrap_err();
        let response: Response = Error::SerdeJson(serde_error).into();
        assert!(response.write_all(&mut buf).is_ok());
        let body = ApiServer::json_fault_message(
            "An error occurred when deserializing the json body of a request: \
             EOF while parsing a value at line 1 column 0.",
        );
        let expected_response = http_response(&body, 400);
        assert_eq!(buf.into_inner(), expected_response.as_bytes());
    }

    #[test]
    fn test_describe() {
        assert_eq!(
            describe(Method::Get, "path", None),
            "Get request on \"path\""
        );
        assert_eq!(
            describe(Method::Put, "/mmds", None),
            "Put request on \"/mmds\""
        );
        assert_eq!(
            describe(Method::Put, "path", Some(&Body::new("body"))),
            "Put request on \"path\" with body \"body\""
        );
    }

    #[test]
    fn test_convert_to_response() {
        let verify_ok_response_with = |vmm_data: VmmData| {
            let data = Ok(vmm_data);
            let mut buf = Cursor::new(vec![0]);
            let expected_response = match data.as_ref().unwrap() {
                VmmData::BalloonConfig(cfg) => {
                    http_response(&serde_json::to_string(cfg).unwrap(), 200)
                }
                VmmData::BalloonStats(stats) => {
                    http_response(&serde_json::to_string(stats).unwrap(), 200)
                }
                VmmData::Empty => http_response("", 204),
                VmmData::FullVmConfig(cfg) => {
                    http_response(&serde_json::to_string(cfg).unwrap(), 200)
                }
                VmmData::MachineConfiguration(cfg) => {
                    http_response(&serde_json::to_string(cfg).unwrap(), 200)
                }
                VmmData::InstanceInformation(info) => {
                    http_response(&serde_json::to_string(info).unwrap(), 200)
                }
                VmmData::VmmVersion(version) => http_response(
                    &serde_json::json!({ "firecracker_version": version.as_str() }).to_string(),
                    200,
                ),
            };
            let response = ParsedRequest::convert_to_response(&data);
            assert!(response.write_all(&mut buf).is_ok());
            assert_eq!(buf.into_inner(), expected_response.as_bytes());
        };

        verify_ok_response_with(VmmData::BalloonConfig(BalloonDeviceConfig::default()));
        verify_ok_response_with(VmmData::BalloonStats(BalloonStats {
            swap_in: Some(1),
            swap_out: Some(1),
            ..Default::default()
        }));
        verify_ok_response_with(VmmData::Empty);
        verify_ok_response_with(VmmData::FullVmConfig(VmmConfig::default()));
        verify_ok_response_with(VmmData::MachineConfiguration(VmConfig::default()));
        verify_ok_response_with(VmmData::InstanceInformation(InstanceInfo::default()));
        verify_ok_response_with(VmmData::VmmVersion(String::default()));

        // Error.
        let error = VmmActionError::StartMicrovm(StartMicrovmError::MissingKernelConfig);
        let mut buf = Cursor::new(vec![0]);
        let json = ApiServer::json_fault_message(error.to_string());
        let response = ParsedRequest::convert_to_response(&Err(error));
        response.write_all(&mut buf).unwrap();

        let expected_response = http_response(&json, 400);
        assert_eq!(buf.into_inner(), expected_response.as_bytes());
    }

    #[test]
    fn test_try_from_get_info() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(http_request("GET", "/", None).as_bytes())
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_get_balloon() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(http_request("GET", "/balloon", None).as_bytes())
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_get_balloon_stats() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(http_request("GET", "/balloon/statistics", None).as_bytes())
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_get_machine_config() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(http_request("GET", "/machine-config", None).as_bytes())
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_get_mmds() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(http_request("GET", "/mmds", None).as_bytes())
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_get_version() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(http_request("GET", "/version", None).as_bytes())
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_put_actions() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        let body = "{ \
            \"action_type\": \"FlushMetrics\" \
            }";
        sender
            .write_all(http_request("PUT", "/actions", Some(&body)).as_bytes())
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_put_balloon() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        let body = "{ \
            \"amount_mib\": 0, \
            \"deflate_on_oom\": false, \
            \"stats_polling_interval_s\": 0 \
            }";
        sender
            .write_all(http_request("PUT", "/balloon", Some(&body)).as_bytes())
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_put_boot() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        let body = "{ \
            \"kernel_image_path\": \"string\", \
            \"boot_args\": \"string\" \
            }";
        sender
            .write_all(http_request("PUT", "/boot-source", Some(&body)).as_bytes())
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_put_drives() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        let body = "{ \
            \"drive_id\": \"string\", \
            \"path_on_host\": \"string\", \
            \"is_root_device\": true, \
            \"partuuid\": \"string\", \
            \"is_read_only\": true, \
            \"cache_type\": \"Unsafe\", \
            \"io_engine\": \"Sync\", \
            \"rate_limiter\": { \
                \"bandwidth\": { \
                    \"size\": 0, \
                    \"one_time_burst\": 0, \
                    \"refill_time\": 0 \
                }, \
                \"ops\": { \
                    \"size\": 0, \
                    \"one_time_burst\": 0, \
                    \"refill_time\": 0 \
                } \
            } \
        }";
        sender
            .write_all(http_request("PUT", "/drives/string", Some(&body)).as_bytes())
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_put_logger() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        let body = "{ \
            \"log_path\": \"string\", \
            \"level\": \"Warning\", \
            \"show_level\": false, \
            \"show_log_origin\": false \
        }";
        sender
            .write_all(http_request("PUT", "/logger", Some(&body)).as_bytes())
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_put_machine_config() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        let body = "{ \
            \"vcpu_count\": 0, \
            \"mem_size_mib\": 0, \
            \"ht_enabled\": true \
        }";
        sender
            .write_all(http_request("PUT", "/machine-config", Some(&body)).as_bytes())
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_put_metrics() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        let body = "{ \
            \"metrics_path\": \"string\" \
        }";
        sender
            .write_all(http_request("PUT", "/metrics", Some(&body)).as_bytes())
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_put_mmds() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);

        // `/mmds`
        sender
            .write_all(http_request("PUT", "/mmds", Some(&"{}")).as_bytes())
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());

        let body = "{\"foo\":\"bar\"}";
        sender
            .write_all(http_request("PUT", "/mmds", Some(&body)).as_bytes())
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());

        // `/mmds/config`
        let body = "{ \
            \"ipv4_address\": \"169.254.170.2\", \
            \"network_interfaces\": [\"iface0\"] \
        }";
        sender
            .write_all(http_request("PUT", "/mmds/config", Some(&body)).as_bytes())
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_put_netif() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        let body = "{ \
            \"iface_id\": \"string\", \
            \"guest_mac\": \"12:34:56:78:9a:BC\", \
            \"host_dev_name\": \"string\", \
            \"rx_rate_limiter\": { \
                \"bandwidth\": { \
                    \"size\": 0, \
                    \"one_time_burst\": 0, \
                    \"refill_time\": 0 \
                }, \
                \"ops\": { \
                    \"size\": 0, \
                    \"one_time_burst\": 0, \
                    \"refill_time\": 0 \
                } \
            }, \
            \"tx_rate_limiter\": { \
                \"bandwidth\": { \
                    \"size\": 0, \
                    \"one_time_burst\": 0, \
                    \"refill_time\": 0 \
                }, \
                \"ops\": { \
                    \"size\": 0, \
                    \"one_time_burst\": 0, \
                    \"refill_time\": 0 \
                } \
            } \
        }";
        sender
            .write_all(http_request("PUT", "/network-interfaces/string", Some(&body)).as_bytes())
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_put_snapshot() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        let body = "{ \
            \"snapshot_path\": \"foo\", \
            \"mem_file_path\": \"bar\", \
            \"version\": \"0.23.0\" \
        }";
        sender
            .write_all(http_request("PUT", "/snapshot/create", Some(&body)).as_bytes())
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
        let body = "{ \
            \"snapshot_path\": \"foo\", \
            \"mem_file_path\": \"bar\", \
            \"enable_diff_snapshots\": true \
        }";
        sender
            .write_all(http_request("PUT", "/snapshot/load", Some(&body)).as_bytes())
            .unwrap();

        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_put_shutdown() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(http_request("PUT", "/shutdown-internal", None).as_bytes())
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        match ParsedRequest::try_from_request(&req).unwrap().into_parts() {
            (RequestAction::ShutdownInternal, _) => (),
            _ => panic!("wrong parsed request"),
        };
    }

    #[test]
    fn test_try_from_patch_vm() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        let body = "{ \
            \"state\": \"Paused\" \
        }";
        sender
            .write_all(http_request("PATCH", "/vm", Some(&body)).as_bytes())
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_put_vsock() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        let body = "{ \
            \"vsock_id\": \"string\", \
            \"guest_cid\": 0, \
            \"uds_path\": \"string\" \
        }";
        sender
            .write_all(http_request("PUT", "/vsock", Some(&body)).as_bytes())
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_patch_balloon() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        let body = "{ \"amount_mib\": 1 }";
        sender
            .write_all(http_request("PATCH", "/balloon", Some(&body)).as_bytes())
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
        let body = "{ \
            \"stats_polling_interval_s\": 1 \
        }";
        sender
            .write_all(http_request("PATCH", "/balloon/statistics", Some(&body)).as_bytes())
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_patch_drives() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        let body = "{ \
            \"drive_id\": \"string\", \
            \"path_on_host\": \"string\" \
        }";
        sender
            .write_all(http_request("PATCH", "/drives/string", Some(&body)).as_bytes())
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_patch_machine_config() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        let body = "{ \
            \"vcpu_count\": 0, \
            \"mem_size_mib\": 0, \
            \"ht_enabled\": true \
        }";
        sender
            .write_all(http_request("PATCH", "/machine-config", Some(&body)).as_bytes())
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
        let body = "{ \
            \"vcpu_count\": 0, \
            \"mem_size_mib\": 0, \
            \"ht_enabled\": true, \
            \"cpu_template\": \"C3\" \
        }";
        sender
            .write_all(http_request("PATCH", "/machine-config", Some(&body)).as_bytes())
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        #[cfg(target_arch = "x86_64")]
        assert!(ParsedRequest::try_from_request(&req).is_ok());
        #[cfg(target_arch = "aarch64")]
        assert!(ParsedRequest::try_from_request(&req).is_err());
    }

    #[test]
    fn test_try_from_patch_mmds() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(http_request("PATCH", "/mmds", Some(&"{}")).as_bytes())
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_patch_netif() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        let body = "{ \
            \"iface_id\": \"string\" \
        }";
        sender
            .write_all(http_request("PATCH", "/network-interfaces/string", Some(&body)).as_bytes())
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }
}
