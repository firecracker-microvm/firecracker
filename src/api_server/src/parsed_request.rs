// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

use super::VmmData;
use micro_http::{Body, Method, Request, Response, StatusCode, Version};
use request::actions::parse_put_actions;
use request::boot_source::parse_put_boot_source;
use request::drive::{parse_patch_drive, parse_put_drive};
use request::instance_info::parse_get_instance_info;
use request::logger::parse_put_logger;
use request::machine_configuration::{
    parse_get_machine_config, parse_patch_machine_config, parse_put_machine_config,
};
use request::metrics::parse_put_metrics;
use request::mmds::{parse_get_mmds, parse_patch_mmds, parse_put_mmds};
use request::net::{parse_patch_net, parse_put_net};
use request::snapshot::parse_patch_vm_state;
#[cfg(target_arch = "x86_64")]
use request::snapshot::parse_put_snapshot;
use request::vsock::parse_put_vsock;
use ApiServer;

use vmm::rpc_interface::{VmmAction, VmmActionError};

pub enum ParsedRequest {
    GetInstanceInfo,
    GetMMDS,
    PatchMMDS(Value),
    PutMMDS(Value),
    Sync(Box<VmmAction>),
}

impl ParsedRequest {
    pub fn try_from_request(request: &Request) -> Result<ParsedRequest, Error> {
        let request_uri = request.uri().get_abs_path().to_string();
        log_received_api_request(describe(
            request.method(),
            request_uri.as_str(),
            request.body.as_ref(),
        ));
        let path_tokens: Vec<&str> = request_uri[1..].split_terminator('/').collect();
        let path = if path_tokens.is_empty() {
            ""
        } else {
            path_tokens[0]
        };

        match (request.method(), path, request.body.as_ref()) {
            (Method::Get, "", None) => parse_get_instance_info(),
            (Method::Get, "machine-config", None) => parse_get_machine_config(),
            (Method::Get, "mmds", None) => parse_get_mmds(),
            (Method::Get, _, Some(_)) => method_to_error(Method::Get),
            (Method::Put, "actions", Some(body)) => parse_put_actions(body),
            (Method::Put, "boot-source", Some(body)) => parse_put_boot_source(body),
            (Method::Put, "drives", Some(body)) => parse_put_drive(body, path_tokens.get(1)),
            (Method::Put, "logger", Some(body)) => parse_put_logger(body),
            (Method::Put, "machine-config", Some(body)) => parse_put_machine_config(body),
            (Method::Put, "metrics", Some(body)) => parse_put_metrics(body),
            (Method::Put, "mmds", Some(body)) => parse_put_mmds(body, path_tokens.get(1)),
            (Method::Put, "network-interfaces", Some(body)) => {
                parse_put_net(body, path_tokens.get(1))
            }
            #[cfg(target_arch = "x86_64")]
            (Method::Put, "snapshot", Some(body)) => parse_put_snapshot(body, path_tokens.get(1)),
            (Method::Put, "vsock", Some(body)) => parse_put_vsock(body),
            (Method::Put, _, None) => method_to_error(Method::Put),
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

    pub fn convert_to_response(
        request_outcome: &std::result::Result<VmmData, VmmActionError>,
    ) -> Response {
        match request_outcome {
            Ok(vmm_data) => match vmm_data {
                VmmData::Empty => {
                    info!("The request was executed successfully. Status code: 204 No Content.");
                    Response::new(Version::Http11, StatusCode::NoContent)
                }
                VmmData::MachineConfiguration(vm_config) => {
                    info!("The request was executed successfully. Status code: 200 OK.");
                    let mut response = Response::new(Version::Http11, StatusCode::OK);
                    response.set_body(Body::new(vm_config.to_string()));
                    response
                }
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
    pub fn new_sync(vmm_action: VmmAction) -> ParsedRequest {
        ParsedRequest::Sync(Box::new(vmm_action))
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
pub fn method_to_error(method: Method) -> Result<ParsedRequest, Error> {
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
pub enum Error {
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
impl Into<Response> for Error {
    fn into(self) -> Response {
        let msg = ApiServer::json_fault_message(format!("{}", self));
        match self {
            Error::Generic(status, _) => ApiServer::json_response(status, msg),
            Error::EmptyID
            | Error::InvalidID
            | Error::InvalidPathMethod(_, _)
            | Error::SerdeJson(_) => ApiServer::json_response(StatusCode::BadRequest, msg),
        }
    }
}

// This function is supposed to do id validation for requests.
pub fn checked_id(id: &str) -> Result<&str, Error> {
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
    use vmm::rpc_interface::VmmActionError;
    use vmm::vmm_config::machine_config::VmConfig;

    impl PartialEq for ParsedRequest {
        fn eq(&self, other: &ParsedRequest) -> bool {
            match (self, other) {
                (&ParsedRequest::Sync(ref sync_req), &ParsedRequest::Sync(ref other_sync_req)) => {
                    sync_req == other_sync_req
                }
                (&ParsedRequest::GetInstanceInfo, &ParsedRequest::GetInstanceInfo) => true,
                (&ParsedRequest::GetMMDS, &ParsedRequest::GetMMDS) => true,
                (&ParsedRequest::PutMMDS(ref val), &ParsedRequest::PutMMDS(ref other_val)) => {
                    val == other_val
                }
                (&ParsedRequest::PatchMMDS(ref val), &ParsedRequest::PatchMMDS(ref other_val)) => {
                    val == other_val
                }
                _ => false,
            }
        }
    }

    pub(crate) fn vmm_action_from_request(req: ParsedRequest) -> VmmAction {
        match req {
            ParsedRequest::Sync(vmm_action) => *vmm_action,
            _ => panic!("Invalid request"),
        }
    }

    #[test]
    fn test_checked_id() {
        assert!(checked_id("dummy").is_ok());
        assert!(checked_id("dummy_1").is_ok());
        match checked_id("") {
            Err(Error::EmptyID) => {}
            _ => panic!("Test failed."),
        }
        match checked_id("dummy!!") {
            Err(Error::InvalidID) => {}
            _ => panic!("Test failed."),
        }
    }

    #[test]
    fn test_invalid_get() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(
                b"GET /mmds HTTP/1.1\r\n\
                Content-Type: text/plain\r\n\
                Content-Length: 4\r\n\r\nbody",
            )
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        match ParsedRequest::try_from_request(&req) {
            Err(Error::Generic(StatusCode::BadRequest, err_msg)) => {
                if err_msg != "GET request cannot have a body." {
                    panic!("GET request with body.");
                }
            }
            _ => panic!("GET request with body."),
        };
    }

    #[test]
    fn test_invalid_put() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(
                b"PUT /mmds HTTP/1.1\r\n\
                Content-Type: application/json\r\n\r\n",
            )
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        match ParsedRequest::try_from_request(&req) {
            Err(Error::Generic(StatusCode::BadRequest, err_msg)) => {
                if err_msg != "Empty PUT request." {
                    panic!("Empty PUT request.");
                }
            }
            _ => panic!("Empty PUT request."),
        };
    }

    #[test]
    fn test_invalid_patch() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(
                b"PATCH /mmds HTTP/1.1\r\n\
                Content-Type: application/json\r\n\r\n",
            )
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        match ParsedRequest::try_from_request(&req) {
            Err(Error::Generic(StatusCode::BadRequest, err_msg)) => {
                if err_msg != "Empty PATCH request." {
                    panic!("Empty PATCH request.");
                }
            }
            _ => panic!("Empty PATCH request."),
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
        let expected_response = format!(
            "HTTP/1.1 400 \r\n\
             Server: Firecracker API\r\n\
             Connection: keep-alive\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\r\n\
             {}",
            body.len(),
            body
        );
        assert_eq!(buf.into_inner(), expected_response.as_bytes());

        // Empty ID error.
        let mut buf = Cursor::new(vec![0]);
        let response: Response = Error::EmptyID.into();
        assert!(response.write_all(&mut buf).is_ok());
        let body = ApiServer::json_fault_message("The ID cannot be empty.");
        let expected_response = format!(
            "HTTP/1.1 400 \r\n\
             Server: Firecracker API\r\n\
             Connection: keep-alive\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\r\n\
             {}",
            body.len(),
            body,
        );
        assert_eq!(buf.into_inner(), expected_response.as_bytes());

        // Invalid ID error.
        let mut buf = Cursor::new(vec![0]);
        let response: Response = Error::InvalidID.into();
        assert!(response.write_all(&mut buf).is_ok());
        let body = ApiServer::json_fault_message(
            "API Resource IDs can only contain alphanumeric characters and underscores.",
        );
        let expected_response = format!(
            "HTTP/1.1 400 \r\n\
             Server: Firecracker API\r\n\
             Connection: keep-alive\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\r\n\
             {}",
            body.len(),
            body,
        );
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
        let expected_response = format!(
            "HTTP/1.1 400 \r\n\
             Server: Firecracker API\r\n\
             Connection: keep-alive\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\r\n\
             {}",
            body.len(),
            body,
        );
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
        let expected_response = format!(
            "HTTP/1.1 400 \r\n\
             Server: Firecracker API\r\n\
             Connection: keep-alive\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\r\n\
             {}",
            body.len(),
            body,
        );
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
        // Empty Vmm data.
        let mut buf = Cursor::new(vec![0]);
        let response = ParsedRequest::convert_to_response(&Ok(VmmData::Empty));
        assert!(response.write_all(&mut buf).is_ok());
        let expected_response = "HTTP/1.1 204 \r\n\
                                 Server: Firecracker API\r\n\
                                 Connection: keep-alive\r\n\r\n"
            .to_string();
        assert_eq!(buf.into_inner(), expected_response.as_bytes());

        // With Vmm data.
        let mut buf = Cursor::new(vec![0]);
        let response = ParsedRequest::convert_to_response(&Ok(VmmData::MachineConfiguration(
            VmConfig::default(),
        )));
        assert!(response.write_all(&mut buf).is_ok());
        let expected_response = format!(
            "HTTP/1.1 200 \r\n\
             Server: Firecracker API\r\n\
             Connection: keep-alive\r\n\
             Content-Type: application/json\r\n\
             Content-Length: 122\r\n\r\n{}",
            VmConfig::default().to_string()
        );
        assert_eq!(buf.into_inner(), expected_response.as_bytes());

        // Error.
        let error = VmmActionError::StartMicrovm(StartMicrovmError::MissingKernelConfig);
        let mut buf = Cursor::new(vec![0]);
        let json = ApiServer::json_fault_message(error.to_string());
        let response = ParsedRequest::convert_to_response(&Err(error));
        response.write_all(&mut buf).unwrap();

        let expected_response = format!(
            "HTTP/1.1 400 \r\n\
             Server: Firecracker API\r\n\
             Connection: keep-alive\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\r\n{}",
            json.len(),
            json,
        );
        assert_eq!(buf.into_inner(), expected_response.as_bytes());
    }

    #[test]
    fn test_try_from_get_info() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_get_machine_config() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(b"GET /machine-config HTTP/1.1\r\n\r\n")
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_get_mmds() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender.write_all(b"GET /mmds HTTP/1.1\r\n\r\n").unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_put_actions() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(
                b"PUT /actions HTTP/1.1\r\n\
                Content-Type: application/json\r\n\
                Content-Length: 33\r\n\r\n{ \
                \"action_type\": \"FlushMetrics\" \
                }",
            )
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_put_boot() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(
                b"PUT /boot-source HTTP/1.1\r\n\
                Content-Type: application/json\r\n\
                Content-Length: 56\r\n\r\n{ \
                \"kernel_image_path\": \"string\", \
                \"boot_args\": \"string\" \
                }",
            )
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_put_drives() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(
                b"PUT /drives/string HTTP/1.1\r\n\
                Content-Type: application/json\r\n\
                Content-Length: 266\r\n\r\n{ \
                \"drive_id\": \"string\", \
                \"path_on_host\": \"string\", \
                \"is_root_device\": true, \
                \"partuuid\": \"string\", \
                \"is_read_only\": true, \
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
            }",
            )
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_put_logger() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);

        let req_as_bytes = b"PUT /logger HTTP/1.1\r\n\
                Content-Type: application/json\r\n\
                Content-Length: 91\r\n\r\n{ \
                \"log_path\": \"string\", \
                \"level\": \"Warning\", \
                \"show_level\": false, \
                \"show_log_origin\": false \
            }";

        sender.write_all(req_as_bytes).unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_put_machine_config() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(
                b"PUT /machine-config HTTP/1.1\r\n\
                Content-Type: application/json\r\n\
                Content-Length: 80\r\n\r\n{ \
                \"vcpu_count\": 0, \
                \"mem_size_mib\": 0, \
                \"ht_enabled\": true, \
                \"cpu_template\": \"C3\" \
            }",
            )
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_put_metrics() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);

        let req_as_bytes = b"PUT /metrics HTTP/1.1\r\n\
                Content-Type: application/json\r\n\
                Content-Length: 28\r\n\r\n{ \
                \"metrics_path\": \"string\" \
            }";

        sender.write_all(req_as_bytes).unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_put_mmds() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(
                b"PUT /mmds HTTP/1.1\r\n\
                Content-Type: application/json\r\n\
                Content-Length: 2\r\n\r\n{}",
            )
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());

        sender
            .write_all(
                b"PUT /mmds/config HTTP/1.1\r\n\
                Content-Type: application/json\r\n\
                Content-Length: 32\r\n\r\n{\"ipv4_address\":\"169.254.170.2\"}",
            )
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_put_netif() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(
                b"PUT /network-interfaces/string HTTP/1.1\r\n\
                Content-Type: application/json\r\n\
                Content-Length: 416\r\n\r\n{ \
                \"iface_id\": \"string\", \
                \"guest_mac\": \"12:34:56:78:9a:BC\", \
                \"host_dev_name\": \"string\", \
                \"allow_mmds_requests\": true, \
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
            }",
            )
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_try_from_put_snapshot() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);

        sender
            .write_all(
                b"PUT /snapshot/create HTTP/1.1\r\n\
                Content-Type: application/json\r\n\
                Content-Length: 71\r\n\r\n{ \
                \"snapshot_path\": \"foo\", \
                \"mem_file_path\": \"bar\", \
                \"version\": \"0.23.0\" \
            }",
            )
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());

        sender
            .write_all(
                b"PUT /snapshot/load HTTP/1.1\r\n\
                Content-Type: application/json\r\n\
                Content-Length: 81\r\n\r\n{ \
                \"snapshot_path\": \"foo\", \
                \"mem_file_path\": \"bar\", \
                \"enable_diff_snapshots\": true \
            }",
            )
            .unwrap();

        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_patch_vm() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);

        sender
            .write_all(
                b"PATCH /vm HTTP/1.1\r\n\
                Content-Type: application/json\r\n\
                Content-Length: 21\r\n\r\n{ \
                \"state\": \"Paused\" \
            }",
            )
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_put_vsock() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(
                b"PUT /vsock HTTP/1.1\r\n\
                Content-Type: application/json\r\n\
                Content-Length: 62\r\n\r\n{ \
                \"vsock_id\": \"string\", \
                \"guest_cid\": 0, \
                \"uds_path\": \"string\" \
            }",
            )
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_patch_drives() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(
                b"PATCH /drives/string HTTP/1.1\r\n\
                Content-Type: application/json\r\n\
                Content-Length: 50\r\n\r\n{ \
                \"drive_id\": \"string\", \
                \"path_on_host\": \"string\" \
            }",
            )
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_patch_machine_config() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(
                b"PATCH /machine-config HTTP/1.1\r\n\
                Content-Type: application/json\r\n\
                Content-Length: 80\r\n\r\n{ \
                \"vcpu_count\": 0, \
                \"mem_size_mib\": 0, \
                \"ht_enabled\": true, \
                \"cpu_template\": \"C3\" \
            }",
            )
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_patch_mmds() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(
                b"PATCH /mmds HTTP/1.1\r\n\
                Content-Type: application/json\r\n\
                Content-Length: 2\r\n\r\n{}",
            )
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }

    #[test]
    fn test_try_from_patch_netif() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(
                b"PATCH /network-interfaces/string HTTP/1.1\r\n\
                Content-Type: application/json\r\n\
                Content-Length: 24\r\n\r\n{ \
                \"iface_id\": \"string\" \
            }",
            )
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        assert!(ParsedRequest::try_from_request(&req).is_ok());
    }
}
