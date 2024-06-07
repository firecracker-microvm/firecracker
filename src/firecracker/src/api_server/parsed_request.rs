// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;

use micro_http::{Body, Method, Request, Response, StatusCode, Version};
use serde::ser::Serialize;
use serde_json::Value;
use vmm::logger::{error, info, log_enabled, Level};
use vmm::rpc_interface::{VmmAction, VmmActionError, VmmData};

use super::request::actions::parse_put_actions;
use super::request::balloon::{parse_get_balloon, parse_patch_balloon, parse_put_balloon};
use super::request::boot_source::parse_put_boot_source;
use super::request::cpu_configuration::parse_put_cpu_config;
use super::request::drive::{parse_patch_drive, parse_put_drive};
use super::request::entropy::parse_put_entropy;
#[cfg(target_arch = "x86_64")]
use super::request::hotplug::parse_put_hotplug;
use super::request::instance_info::parse_get_instance_info;
use super::request::logger::parse_put_logger;
use super::request::machine_configuration::{
    parse_get_machine_config, parse_patch_machine_config, parse_put_machine_config,
};
use super::request::metrics::parse_put_metrics;
use super::request::mmds::{parse_get_mmds, parse_patch_mmds, parse_put_mmds};
use super::request::net::{parse_patch_net, parse_put_net};
use super::request::snapshot::{parse_patch_vm_state, parse_put_snapshot};
use super::request::version::parse_get_version;
use super::request::vsock::parse_put_vsock;
use super::ApiServer;

#[derive(Debug)]
pub(crate) enum RequestAction {
    Sync(Box<VmmAction>),
}

#[derive(Debug, Default, PartialEq)]
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

#[derive(Debug)]
pub(crate) struct ParsedRequest {
    action: RequestAction,
    parsing_info: ParsingInfo,
}

impl TryFrom<&Request> for ParsedRequest {
    type Error = RequestError;
    fn try_from(request: &Request) -> Result<Self, Self::Error> {
        let request_uri = request.uri().get_abs_path().to_string();
        let description = describe(
            request.method(),
            request_uri.as_str(),
            request.body.as_ref(),
        );
        info!("The API server received a {description}.");

        // Split request uri by '/' by doing:
        // 1. Trim starting '/' characters
        // 2. Splitting by '/'
        let mut path_tokens = request_uri.trim_start_matches('/').split_terminator('/');
        let path = path_tokens.next().unwrap_or("");

        match (request.method(), path, request.body.as_ref()) {
            (Method::Get, "", None) => parse_get_instance_info(),
            (Method::Get, "balloon", None) => parse_get_balloon(path_tokens.next()),
            (Method::Get, "version", None) => parse_get_version(),
            (Method::Get, "vm", None) if path_tokens.next() == Some("config") => {
                Ok(ParsedRequest::new_sync(VmmAction::GetFullVmConfig))
            }
            (Method::Get, "machine-config", None) => parse_get_machine_config(),
            (Method::Get, "mmds", None) => parse_get_mmds(),
            (Method::Get, _, Some(_)) => method_to_error(Method::Get),
            (Method::Put, "actions", Some(body)) => parse_put_actions(body),
            (Method::Put, "balloon", Some(body)) => parse_put_balloon(body),
            (Method::Put, "boot-source", Some(body)) => parse_put_boot_source(body),
            (Method::Put, "cpu-config", Some(body)) => parse_put_cpu_config(body),
            (Method::Put, "drives", Some(body)) => parse_put_drive(body, path_tokens.next()),
            #[cfg(target_arch = "x86_64")]
            (Method::Put, "hotplug", Some(body)) => parse_put_hotplug(body),
            (Method::Put, "logger", Some(body)) => parse_put_logger(body),
            (Method::Put, "machine-config", Some(body)) => parse_put_machine_config(body),
            (Method::Put, "metrics", Some(body)) => parse_put_metrics(body),
            (Method::Put, "mmds", Some(body)) => parse_put_mmds(body, path_tokens.next()),
            (Method::Put, "network-interfaces", Some(body)) => {
                parse_put_net(body, path_tokens.next())
            }
            (Method::Put, "snapshot", Some(body)) => parse_put_snapshot(body, path_tokens.next()),
            (Method::Put, "vsock", Some(body)) => parse_put_vsock(body),
            (Method::Put, "entropy", Some(body)) => parse_put_entropy(body),
            (Method::Put, _, None) => method_to_error(Method::Put),
            (Method::Patch, "balloon", Some(body)) => parse_patch_balloon(body, path_tokens.next()),
            (Method::Patch, "drives", Some(body)) => parse_patch_drive(body, path_tokens.next()),
            (Method::Patch, "machine-config", Some(body)) => parse_patch_machine_config(body),
            (Method::Patch, "mmds", Some(body)) => parse_patch_mmds(body),
            (Method::Patch, "network-interfaces", Some(body)) => {
                parse_patch_net(body, path_tokens.next())
            }
            (Method::Patch, "vm", Some(body)) => parse_patch_vm_state(body),
            (Method::Patch, _, None) => method_to_error(Method::Patch),
            (method, unknown_uri, _) => Err(RequestError::InvalidPathMethod(
                unknown_uri.to_string(),
                method,
            )),
        }
    }
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

    pub(crate) fn success_response_with_data<T>(body_data: &T) -> Response
    where
        T: ?Sized + Serialize + Debug,
    {
        info!("The request was executed successfully. Status code: 200 OK.");
        let mut response = Response::new(Version::Http11, StatusCode::OK);
        response.set_body(Body::new(serde_json::to_string(body_data).unwrap()));
        response
    }

    pub(crate) fn success_response_with_mmds_value(body_data: &Value) -> Response {
        info!("The request was executed successfully. Status code: 200 OK.");
        let mut response = Response::new(Version::Http11, StatusCode::OK);
        let body_str = match body_data {
            Value::Null => "{}".to_string(),
            _ => serde_json::to_string(body_data).unwrap(),
        };
        response.set_body(Body::new(body_str));
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
                VmmData::MmdsValue(value) => Self::success_response_with_mmds_value(value),
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
                let mut response = match vmm_action_error {
                    VmmActionError::MmdsLimitExceeded(_err) => {
                        error!(
                            "Received Error. Status code: 413 Payload too large. Message: {}",
                            vmm_action_error
                        );
                        Response::new(Version::Http11, StatusCode::PayloadTooLarge)
                    }
                    _ => {
                        error!(
                            "Received Error. Status code: 400 Bad Request. Message: {}",
                            vmm_action_error
                        );
                        Response::new(Version::Http11, StatusCode::BadRequest)
                    }
                };
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
        ("/cpu-config", Some(payload_value)) => {
            // If the log level is at Debug or higher, include the CPU template in
            // the log line.
            if log_enabled!(Level::Debug) {
                describe_with_body(method, path, payload_value)
            } else {
                format!(
                    "{:?} request on {:?}. To view the CPU template received by the API, \
                     configure log-level to DEBUG",
                    method, path
                )
            }
        }
        (_, Some(payload_value)) => describe_with_body(method, path, payload_value),
    }
}

fn describe_with_body(method: Method, path: &str, payload_value: &Body) -> String {
    format!(
        "{:?} request on {:?} with body {:?}",
        method,
        path,
        std::str::from_utf8(payload_value.body.as_slice())
            .unwrap_or("inconvertible to UTF-8")
            .to_string()
    )
}

/// Generates a `GenericError` for each request method.
pub(crate) fn method_to_error(method: Method) -> Result<ParsedRequest, RequestError> {
    match method {
        Method::Get => Err(RequestError::Generic(
            StatusCode::BadRequest,
            "GET request cannot have a body.".to_string(),
        )),
        Method::Put => Err(RequestError::Generic(
            StatusCode::BadRequest,
            "Empty PUT request.".to_string(),
        )),
        Method::Patch => Err(RequestError::Generic(
            StatusCode::BadRequest,
            "Empty PATCH request.".to_string(),
        )),
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RequestError {
    // The resource ID is empty.
    #[error("The ID cannot be empty.")]
    EmptyID,
    // A generic error, with a given status code and message to be turned into a fault message.
    #[error("{1}")]
    Generic(StatusCode, String),
    // The resource ID must only contain alphanumeric characters and '_'.
    #[error("API Resource IDs can only contain alphanumeric characters and underscores.")]
    InvalidID,
    // The HTTP method & request path combination is not valid.
    #[error("Invalid request method and/or path: {} {0}.", std::str::from_utf8(.1.raw()).expect("Cannot convert from UTF-8"))]
    InvalidPathMethod(String, Method),
    // An error occurred when deserializing the json body of a request.
    #[error("An error occurred when deserializing the json body of a request: {0}.")]
    SerdeJson(#[from] serde_json::Error),
}

// It's convenient to turn errors into HTTP responses directly.
impl From<RequestError> for Response {
    fn from(err: RequestError) -> Self {
        let msg = ApiServer::json_fault_message(format!("{}", err));
        match err {
            RequestError::Generic(status, _) => ApiServer::json_response(status, msg),
            RequestError::EmptyID
            | RequestError::InvalidID
            | RequestError::InvalidPathMethod(_, _)
            | RequestError::SerdeJson(_) => ApiServer::json_response(StatusCode::BadRequest, msg),
        }
    }
}

// This function is supposed to do id validation for requests.
pub(crate) fn checked_id(id: &str) -> Result<&str, RequestError> {
    // todo: are there any checks we want to do on id's?
    // not allow them to be empty strings maybe?
    // check: ensure string is not empty
    if id.is_empty() {
        return Err(RequestError::EmptyID);
    }
    // check: ensure string is alphanumeric
    if !id.chars().all(|c| c == '_' || c.is_alphanumeric()) {
        return Err(RequestError::InvalidID);
    }
    Ok(id)
}

#[cfg(test)]
pub mod tests {
    use std::io::{Cursor, Write};
    use std::os::unix::net::UnixStream;
    use std::str::FromStr;

    use micro_http::HttpConnection;
    use vmm::builder::StartMicrovmError;
    use vmm::cpu_config::templates::test_utils::build_test_template;
    use vmm::resources::VmmConfig;
    use vmm::rpc_interface::VmmActionError;
    use vmm::vmm_config::balloon::{BalloonDeviceConfig, BalloonStats};
    use vmm::vmm_config::instance_info::InstanceInfo;
    use vmm::vmm_config::machine_config::MachineConfig;

    use super::*;

    impl PartialEq for ParsedRequest {
        fn eq(&self, other: &ParsedRequest) -> bool {
            if self.parsing_info.deprecation_message != other.parsing_info.deprecation_message {
                return false;
            }

            match (&self.action, &other.action) {
                (RequestAction::Sync(ref sync_req), RequestAction::Sync(ref other_sync_req)) => {
                    sync_req == other_sync_req
                }
            }
        }
    }

    pub(crate) fn vmm_action_from_request(req: ParsedRequest) -> VmmAction {
        match req.action {
            RequestAction::Sync(vmm_action) => *vmm_action,
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
        }
    }

    fn http_response(body: &str, status_code: i32) -> String {
        let header = format!(
            "HTTP/1.1 {} \r\nServer: Firecracker API\r\nConnection: keep-alive\r\n",
            status_code
        );
        if status_code == 204 {
            // No Content
            format!("{}{}", header, "\r\n")
        } else {
            let content = format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body,
            );

            format!("{}{}", header, content)
        }
    }

    fn http_request(request_type: &str, endpoint: &str, body: Option<&str>) -> String {
        let req_no_body = format!(
            "{} {} HTTP/1.1\r\nContent-Type: application/json\r\n",
            request_type, endpoint
        );
        if body.is_some() {
            return format!(
                "{}Content-Length: {}\r\n\r\n{}",
                req_no_body,
                body.unwrap().len(),
                body.unwrap()
            );
        }
        format!("{}\r\n", req_no_body,)
    }

    #[test]
    fn test_missing_slash() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(http_request("GET", "none", Some("body")).as_bytes())
            .unwrap();
        connection.try_read().unwrap();

        let req = connection.pop_parsed_request().unwrap();
        ParsedRequest::try_from(&req).unwrap_err();
    }

    #[test]
    fn test_checked_id() {
        checked_id("dummy").unwrap();
        checked_id("dummy_1").unwrap();

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
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        let parsed_request = ParsedRequest::try_from(&req);
        assert!(matches!(
            &parsed_request,
            Err(RequestError::Generic(StatusCode::BadRequest, s)) if s == "GET request cannot have a body.",
        ));
    }

    #[test]
    fn test_invalid_put() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(http_request("PUT", "/mmds", None).as_bytes())
            .unwrap();
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        let parsed_request = ParsedRequest::try_from(&req);
        assert!(matches!(
            &parsed_request,
            Err(RequestError::Generic(StatusCode::BadRequest, s)) if s == "Empty PUT request.",
        ));
    }

    #[test]
    fn test_invalid_patch() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(http_request("PATCH", "/mmds", None).as_bytes())
            .unwrap();
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        let parsed_request = ParsedRequest::try_from(&req);
        assert!(matches!(
            &parsed_request,
            Err(RequestError::Generic(StatusCode::BadRequest, s)) if s == "Empty PATCH request.",
        ));
    }

    #[test]
    fn test_error_into_response() {
        // Generic error.
        let mut buf = Cursor::new(vec![0]);
        let response: Response =
            RequestError::Generic(StatusCode::BadRequest, "message".to_string()).into();
        response.write_all(&mut buf).unwrap();
        let body = ApiServer::json_fault_message("message");
        let expected_response = http_response(&body, 400);
        assert_eq!(buf.into_inner(), expected_response.as_bytes());

        // Empty ID error.
        let mut buf = Cursor::new(vec![0]);
        let response: Response = RequestError::EmptyID.into();
        response.write_all(&mut buf).unwrap();
        let body = ApiServer::json_fault_message("The ID cannot be empty.");
        let expected_response = http_response(&body, 400);
        assert_eq!(buf.into_inner(), expected_response.as_bytes());

        // Invalid ID error.
        let mut buf = Cursor::new(vec![0]);
        let response: Response = RequestError::InvalidID.into();
        response.write_all(&mut buf).unwrap();
        let body = ApiServer::json_fault_message(
            "API Resource IDs can only contain alphanumeric characters and underscores.",
        );
        let expected_response = http_response(&body, 400);
        assert_eq!(buf.into_inner(), expected_response.as_bytes());

        // Invalid path or method error.
        let mut buf = Cursor::new(vec![0]);
        let response: Response =
            RequestError::InvalidPathMethod("path".to_string(), Method::Get).into();
        response.write_all(&mut buf).unwrap();
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
        let response: Response = RequestError::SerdeJson(serde_error).into();
        response.write_all(&mut buf).unwrap();
        let body = ApiServer::json_fault_message(
            "An error occurred when deserializing the json body of a request: EOF while parsing a \
             value at line 1 column 0.",
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
                VmmData::MmdsValue(value) => {
                    http_response(&serde_json::to_string(value).unwrap(), 200)
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
            response.write_all(&mut buf).unwrap();
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
        verify_ok_response_with(VmmData::MachineConfiguration(MachineConfig::default()));
        verify_ok_response_with(VmmData::MmdsValue(serde_json::from_str("{}").unwrap()));
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
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        ParsedRequest::try_from(&req).unwrap();
    }

    #[test]
    fn test_try_from_get_balloon() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(http_request("GET", "/balloon", None).as_bytes())
            .unwrap();
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        ParsedRequest::try_from(&req).unwrap();
    }

    #[test]
    fn test_try_from_get_balloon_stats() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(http_request("GET", "/balloon/statistics", None).as_bytes())
            .unwrap();
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        ParsedRequest::try_from(&req).unwrap();
    }

    #[test]
    fn test_try_from_get_machine_config() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(http_request("GET", "/machine-config", None).as_bytes())
            .unwrap();
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        ParsedRequest::try_from(&req).unwrap();
    }

    #[test]
    fn test_try_from_get_mmds() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(http_request("GET", "/mmds", None).as_bytes())
            .unwrap();
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        ParsedRequest::try_from(&req).unwrap();
    }

    #[test]
    fn test_try_from_get_version() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(http_request("GET", "/version", None).as_bytes())
            .unwrap();
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        ParsedRequest::try_from(&req).unwrap();
    }

    #[test]
    fn test_try_from_put_actions() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        let body = "{ \"action_type\": \"FlushMetrics\" }";
        sender
            .write_all(http_request("PUT", "/actions", Some(body)).as_bytes())
            .unwrap();
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        ParsedRequest::try_from(&req).unwrap();
    }

    #[test]
    fn test_try_from_put_balloon() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        let body =
            "{ \"amount_mib\": 0, \"deflate_on_oom\": false, \"stats_polling_interval_s\": 0 }";
        sender
            .write_all(http_request("PUT", "/balloon", Some(body)).as_bytes())
            .unwrap();
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        ParsedRequest::try_from(&req).unwrap();
    }

    #[test]
    fn test_try_from_put_entropy() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        let body = "{ \"rate_limiter\": { \"bandwidth\" : { \"size\": 0, \"one_time_burst\": 0, \
                    \"refill_time\": 0 }, \"ops\": { \"size\": 0, \"one_time_burst\": 0, \
                    \"refill_time\": 0 } } }";
        sender
            .write_all(http_request("PUT", "/entropy", Some(body)).as_bytes())
            .unwrap();
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        ParsedRequest::try_from(&req).unwrap();
    }

    #[test]
    fn test_try_from_put_boot() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        let body = "{ \"kernel_image_path\": \"string\", \"boot_args\": \"string\" }";
        sender
            .write_all(http_request("PUT", "/boot-source", Some(body)).as_bytes())
            .unwrap();
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        ParsedRequest::try_from(&req).unwrap();
    }

    #[test]
    fn test_try_from_put_drives() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        let body = "{ \"drive_id\": \"string\", \"path_on_host\": \"string\", \"is_root_device\": \
                    true, \"partuuid\": \"string\", \"is_read_only\": true, \"cache_type\": \
                    \"Unsafe\", \"io_engine\": \"Sync\", \"rate_limiter\": { \"bandwidth\": { \
                    \"size\": 0, \"one_time_burst\": 0, \"refill_time\": 0 }, \"ops\": { \
                    \"size\": 0, \"one_time_burst\": 0, \"refill_time\": 0 } } }";
        sender
            .write_all(http_request("PUT", "/drives/string", Some(body)).as_bytes())
            .unwrap();
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        ParsedRequest::try_from(&req).unwrap();
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_try_from_put_hotplug_vcpu() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        let body = r#"{
            "Vcpu": { "add": 1 }
        }"#;
        sender
            .write_all(http_request("PUT", "/hotplug", Some(body)).as_bytes())
            .unwrap();
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        ParsedRequest::try_from(&req).unwrap();
    }

    #[test]
    fn test_try_from_put_logger() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        let body = "{ \"log_path\": \"string\", \"level\": \"Warning\", \"show_level\": false, \
                    \"show_log_origin\": false }";
        sender
            .write_all(http_request("PUT", "/logger", Some(body)).as_bytes())
            .unwrap();
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        ParsedRequest::try_from(&req).unwrap();
    }

    #[test]
    fn test_try_from_put_machine_config() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        let body = "{ \"vcpu_count\": 1, \"mem_size_mib\": 1 }";
        sender
            .write_all(http_request("PUT", "/machine-config", Some(body)).as_bytes())
            .unwrap();
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        ParsedRequest::try_from(&req).unwrap();
    }

    #[test]
    fn test_try_from_put_metrics() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        let body = "{ \"metrics_path\": \"string\" }";
        sender
            .write_all(http_request("PUT", "/metrics", Some(body)).as_bytes())
            .unwrap();
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        ParsedRequest::try_from(&req).unwrap();
    }

    #[test]
    fn test_try_from_put_mmds() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);

        // `/mmds`
        sender
            .write_all(http_request("PUT", "/mmds", Some("{}")).as_bytes())
            .unwrap();
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        ParsedRequest::try_from(&req).unwrap();

        let body = "{\"foo\":\"bar\"}";
        sender
            .write_all(http_request("PUT", "/mmds", Some(body)).as_bytes())
            .unwrap();
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        ParsedRequest::try_from(&req).unwrap();

        // `/mmds/config`
        let body = "{ \"ipv4_address\": \"169.254.170.2\", \"network_interfaces\": [\"iface0\"] }";
        sender
            .write_all(http_request("PUT", "/mmds/config", Some(body)).as_bytes())
            .unwrap();
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        ParsedRequest::try_from(&req).unwrap();
    }

    #[test]
    fn test_try_from_put_netif() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        let body = "{ \"iface_id\": \"string\", \"guest_mac\": \"12:34:56:78:9a:BC\", \
                    \"host_dev_name\": \"string\", \"rx_rate_limiter\": { \"bandwidth\": { \
                    \"size\": 0, \"one_time_burst\": 0, \"refill_time\": 0 }, \"ops\": { \
                    \"size\": 0, \"one_time_burst\": 0, \"refill_time\": 0 } }, \
                    \"tx_rate_limiter\": { \"bandwidth\": { \"size\": 0, \"one_time_burst\": 0, \
                    \"refill_time\": 0 }, \"ops\": { \"size\": 0, \"one_time_burst\": 0, \
                    \"refill_time\": 0 } } }";
        sender
            .write_all(http_request("PUT", "/network-interfaces/string", Some(body)).as_bytes())
            .unwrap();
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        ParsedRequest::try_from(&req).unwrap();
    }

    #[test]
    fn test_try_from_put_snapshot() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        let body = "{ \"snapshot_path\": \"foo\", \"mem_file_path\": \"bar\" }";
        sender
            .write_all(http_request("PUT", "/snapshot/create", Some(body)).as_bytes())
            .unwrap();
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        ParsedRequest::try_from(&req).unwrap();

        let body = "{ \"snapshot_path\": \"foo\", \"mem_backend\": { \"backend_type\": \"File\", \
                    \"backend_path\": \"bar\" }, \"enable_diff_snapshots\": true }";
        sender
            .write_all(http_request("PUT", "/snapshot/load", Some(body)).as_bytes())
            .unwrap();

        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        ParsedRequest::try_from(&req).unwrap();

        let body =
            "{ \"snapshot_path\": \"foo\", \"mem_file_path\": \"bar\", \"resume_vm\": true }";
        sender
            .write_all(http_request("PUT", "/snapshot/load", Some(body)).as_bytes())
            .unwrap();

        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        ParsedRequest::try_from(&req).unwrap();
    }

    #[test]
    fn test_try_from_patch_vm() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        let body = "{ \"state\": \"Paused\" }";
        sender
            .write_all(http_request("PATCH", "/vm", Some(body)).as_bytes())
            .unwrap();
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        ParsedRequest::try_from(&req).unwrap();
    }

    #[test]
    fn test_try_from_put_vsock() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        let body = "{ \"vsock_id\": \"string\", \"guest_cid\": 0, \"uds_path\": \"string\" }";
        sender
            .write_all(http_request("PUT", "/vsock", Some(body)).as_bytes())
            .unwrap();
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        ParsedRequest::try_from(&req).unwrap();
    }

    #[test]
    fn test_try_from_patch_balloon() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        let body = "{ \"amount_mib\": 1 }";
        sender
            .write_all(http_request("PATCH", "/balloon", Some(body)).as_bytes())
            .unwrap();
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        ParsedRequest::try_from(&req).unwrap();
        let body = "{ \"stats_polling_interval_s\": 1 }";
        sender
            .write_all(http_request("PATCH", "/balloon/statistics", Some(body)).as_bytes())
            .unwrap();
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        ParsedRequest::try_from(&req).unwrap();
    }

    #[test]
    fn test_try_from_patch_drives() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        let body = "{ \"drive_id\": \"string\", \"path_on_host\": \"string\" }";
        sender
            .write_all(http_request("PATCH", "/drives/string", Some(body)).as_bytes())
            .unwrap();
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        ParsedRequest::try_from(&req).unwrap();
    }

    #[test]
    fn test_try_from_patch_machine_config() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        let body = "{ \"vcpu_count\": 1, \"mem_size_mib\": 1 }";
        sender
            .write_all(http_request("PATCH", "/machine-config", Some(body)).as_bytes())
            .unwrap();
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        ParsedRequest::try_from(&req).unwrap();
        let body =
            "{ \"vcpu_count\": 1, \"mem_size_mib\": 1, \"smt\": false, \"cpu_template\": \"C3\" }";
        sender
            .write_all(http_request("PATCH", "/machine-config", Some(body)).as_bytes())
            .unwrap();
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        #[cfg(target_arch = "x86_64")]
        ParsedRequest::try_from(&req).unwrap();
        #[cfg(target_arch = "aarch64")]
        ParsedRequest::try_from(&req).unwrap_err();
    }

    #[test]
    fn test_try_from_put_cpu_config() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);

        let cpu_template = build_test_template();
        let cpu_config_json_result = serde_json::to_string(&cpu_template);
        assert!(
            cpu_config_json_result.is_ok(),
            "Unable to serialize custom CPU template"
        );
        let cpu_config_json = cpu_config_json_result.unwrap();
        let result =
            sender.write_all(http_request("PUT", "/cpu-config", Some(&cpu_config_json)).as_bytes());
        result.unwrap();
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        let request_result = ParsedRequest::try_from(&req);
        assert!(request_result.is_ok(), "{}", request_result.err().unwrap());
    }

    #[test]
    fn test_try_from_patch_mmds() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(http_request("PATCH", "/mmds", Some("{}")).as_bytes())
            .unwrap();
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        ParsedRequest::try_from(&req).unwrap();
    }

    #[test]
    fn test_try_from_patch_netif() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        let body = "{ \"iface_id\": \"string\" }";
        sender
            .write_all(http_request("PATCH", "/network-interfaces/string", Some(body)).as_bytes())
            .unwrap();
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        ParsedRequest::try_from(&req).unwrap();
    }
}
