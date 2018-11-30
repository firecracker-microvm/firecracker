// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::result;
use std::str;
use std::sync::{Arc, Mutex, RwLock};

use futures::future::{self, Either};
use futures::{Future, Stream, IntoFuture};

use std::sync::mpsc::Sender;
use hyper::header::{HeaderMap, HeaderValue};
use hyper::{self, Body, Chunk, Method, Request, Response, StatusCode};
use hyper::service::Service;
use serde_json;

use logger::{Metric, METRICS};
use mmds::data_store::Mmds;
use request::actions::ActionBody;
use request::drive::PatchDrivePayload;
use request::{GenerateHyperResponse, IntoParsedRequest, ParsedRequest};
use sys_util::EventFd;
use vmm::vmm_config::boot_source::BootSourceConfig;
use vmm::vmm_config::drive::BlockDeviceConfig;
use vmm::vmm_config::instance_info::InstanceInfo;
use vmm::vmm_config::logger::LoggerConfig;
use vmm::vmm_config::machine_config::VmConfig;
use vmm::vmm_config::net::NetworkInterfaceConfig;
#[cfg(feature = "vsock")]
use vmm::vmm_config::vsock::VsockDeviceConfig;
use vmm::VmmAction;

use std::error::Error as StdError;
use std::fmt;

#[derive(Debug)]
pub enum ServiceError {
    Hyper(hyper::error::Error),
    CanceledFuture(futures::Canceled),
    Generic,
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ServiceError::Hyper(inner) => write!(f, "Got an service error: {}", inner),
            ServiceError::CanceledFuture(inner) => write!(f, "Got an service error: {}", inner),
            ServiceError::Generic => write!(f, "Got an service error."),
        }
    }
}

impl StdError for ServiceError {
    fn description(&self) -> &str {
        "HTTP Service Error"
    }

    fn cause(&self) -> Option<&StdError> {
        match self {
            ServiceError::Hyper(inner) => Some(inner),
            ServiceError::CanceledFuture(inner) => Some(inner),
            ServiceError::Generic => None,
        }
    }
}

fn build_response_base<B: Into<Body>>(
    status: StatusCode,
    maybe_headers: Option<HeaderMap<HeaderValue>>,
    maybe_body: Option<B>,
) -> Response<Body> {
    let mut response: Response<Body> = Response::default();
    *response.status_mut() = status;

    if let Some(headers) = maybe_headers {
        *response.headers_mut() = headers;
    }
    if let Some(body) = maybe_body {
        *response.body_mut() = body.into();
    }
    response
}

// An HTTP response with just a status code.
pub fn empty_response(status: StatusCode) -> Response<Body> {
    build_response_base::<String>(status, None, None)
}

// An HTTP response which also includes a body.
pub fn json_response<T: Into<hyper::Body>>(status: StatusCode, body: T) -> Response<Body> {
    let mut headers = HeaderMap::new();
    headers.insert(
        hyper::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    build_response_base(status, Some(headers), Some(body))
}

// Builds a string that looks like (where $ stands for substitution):
//  {
//    "$k": "$v"
//  }
// Mainly used for building fault message response json bodies.
fn basic_json_body<K: AsRef<str>, V: AsRef<str>>(k: K, v: V) -> String {
    format!("{{\n  \"{}\": \"{}\"\n}}", k.as_ref(), v.as_ref())
}

pub fn json_fault_message<T: AsRef<str>>(msg: T) -> String {
    basic_json_body("fault_message", msg)
}

enum Error<'a> {
    // A generic error, with a given status code and message to be turned into a fault message.
    Generic(StatusCode, String),
    // The resource ID is invalid.
    EmptyID,
    // The HTTP method & request path combination is not valid.
    InvalidPathMethod(&'a str, Method),
    // An error occurred when deserializing the json body of a request.
    SerdeJson(serde_json::Error),
}

// It's convenient to turn errors into HTTP responses directly.
impl<'a> Into<Response<Body>> for Error<'a> {
    fn into(self) -> Response<Body> {
        match self {
            Error::Generic(status, msg) => json_response(status, json_fault_message(msg)),
            Error::EmptyID => json_response(
                StatusCode::BAD_REQUEST,
                json_fault_message("The ID cannot be empty."),
            ),
            Error::InvalidPathMethod(path, method) => json_response(
                StatusCode::BAD_REQUEST,
                json_fault_message(format!(
                    "Invalid request method and/or path: {} {}",
                    method, path
                )),
            ),
            Error::SerdeJson(e) => {
                json_response(StatusCode::BAD_REQUEST, json_fault_message(e.to_string()))
            }
        }
    }
}

type Result<'a, T> = result::Result<T, Error<'a>>;

// Turns a GET/PUT /actions HTTP request into a ParsedRequest
fn parse_actions_req<'a>(path: &'a str, method: Method, body: &Chunk) -> Result<'a, ParsedRequest> {
    let path_tokens: Vec<&str> = path[1..].split_terminator('/').collect();

    match path_tokens.len() {
        1 if method == Method::PUT => {
            METRICS.put_api_requests.actions_count.inc();
            Ok(serde_json::from_slice::<ActionBody>(body.as_ref())
                .map_err(|e| {
                    METRICS.put_api_requests.actions_fails.inc();
                    Error::SerdeJson(e)
                })?.into_parsed_request(None, method)
                .map_err(|msg| {
                    METRICS.put_api_requests.actions_fails.inc();
                    Error::Generic(StatusCode::BAD_REQUEST, msg)
                })?)
        }
        _ => Err(Error::InvalidPathMethod(path, method)),
    }
}

// This function is supposed to do id validation for requests.
fn checked_id(id: &str) -> Result<&str> {
    // todo: are there any checks we want to do on id's?
    // not allow them to be empty strings maybe?
    Ok(id)
}

// Turns a GET/PUT /boot-source HTTP request into a ParsedRequest
fn parse_boot_source_req<'a>(
    path: &'a str,
    method: Method,
    body: &Chunk,
) -> Result<'a, ParsedRequest> {
    let path_tokens: Vec<&str> = path[1..].split_terminator('/').collect();

    match path_tokens[1..].len() {
        0 if method == Method::PUT => {
            METRICS.put_api_requests.boot_source_count.inc();
            Ok(serde_json::from_slice::<BootSourceConfig>(body)
                .map_err(|e| {
                    METRICS.put_api_requests.boot_source_fails.inc();
                    Error::SerdeJson(e)
                })?.into_parsed_request(None, method)
                .map_err(|s| {
                    METRICS.put_api_requests.boot_source_fails.inc();
                    Error::Generic(StatusCode::BAD_REQUEST, s)
                })?)
        }
        _ => Err(Error::InvalidPathMethod(path, method)),
    }
}

// Turns HTTP requests on /mmds into a ParsedRequest
// This is a rather dummy method with the purpose of keeping the same code structure as before.
// We will need to refactor this as some point.
fn parse_mmds_request<'a>(
    path: &'a str,
    method: Method,
    body: &Chunk,
) -> Result<'a, ParsedRequest> {
    let path_tokens: Vec<&str> = path[1..].split_terminator('/').collect();

    match path_tokens[1..].len() {
        0 if method == Method::GET => Ok(ParsedRequest::GetMMDS),
        0 if method == Method::PUT => {
            match serde_json::from_slice(&body) {
                Ok(val) => return Ok(ParsedRequest::PutMMDS(val)),
                Err(e) => return Err(Error::SerdeJson(e)),
            };
        }
        0 if method == Method::PATCH => match serde_json::from_slice(&body) {
            Ok(val) => return Ok(ParsedRequest::PatchMMDS(val)),
            Err(e) => return Err(Error::SerdeJson(e)),
        },
        _ => Err(Error::InvalidPathMethod(path, method)),
    }
}

// Turns a GET/PUT /drives HTTP request into a ParsedRequest
fn parse_drives_req<'a>(path: &'a str, method: Method, body: &Chunk) -> Result<'a, ParsedRequest> {
    let path_tokens: Vec<&str> = path[1..].split_terminator('/').collect();
    let id_from_path = if path_tokens.len() > 1 {
        checked_id(path_tokens[1])?
    } else {
        return Err(Error::EmptyID);
    };

    match path_tokens[1..].len() {
        1 if method == Method::PUT => {
            METRICS.put_api_requests.drive_count.inc();

            let device_cfg = serde_json::from_slice::<BlockDeviceConfig>(body).map_err(|e| {
                METRICS.put_api_requests.drive_fails.inc();
                Error::SerdeJson(e)
            })?;
            Ok(device_cfg
                .into_parsed_request(Some(id_from_path.to_string()), method)
                .map_err(|s| {
                    METRICS.put_api_requests.drive_fails.inc();
                    Error::Generic(StatusCode::BAD_REQUEST, s)
                })?)
        }

        1 if method == Method::PATCH => {
            METRICS.patch_api_requests.drive_count.inc();

            Ok(PatchDrivePayload {
                fields: serde_json::from_slice(body).map_err(|e| {
                    METRICS.patch_api_requests.drive_fails.inc();
                    Error::SerdeJson(e)
                })?,
            }.into_parsed_request(Some(id_from_path.to_string()), method)
            .map_err(|s| {
                METRICS.patch_api_requests.drive_fails.inc();
                Error::Generic(StatusCode::BAD_REQUEST, s)
            })?)
        }

        _ => Err(Error::InvalidPathMethod(path, method)),
    }
}

// Turns a GET/PUT /logger HTTP request into a ParsedRequest
fn parse_logger_req<'a>(path: &'a str, method: Method, body: &Chunk) -> Result<'a, ParsedRequest> {
    let path_tokens: Vec<&str> = path[1..].split_terminator('/').collect();

    match path_tokens[1..].len() {
        0 if method == Method::PUT => {
            METRICS.put_api_requests.logger_count.inc();
            Ok(serde_json::from_slice::<LoggerConfig>(body)
                .map_err(|e| {
                    METRICS.put_api_requests.logger_fails.inc();
                    Error::SerdeJson(e)
                })?.into_parsed_request(None, method)
                .map_err(|s| {
                    METRICS.put_api_requests.logger_fails.inc();
                    Error::Generic(StatusCode::BAD_REQUEST, s)
                })?)
        }
        _ => Err(Error::InvalidPathMethod(path, method)),
    }
}

// Turns a GET/PUT /machine-config HTTP request into a ParsedRequest
fn parse_machine_config_req<'a>(
    path: &'a str,
    method: Method,
    body: &Chunk,
) -> Result<'a, ParsedRequest> {
    let path_tokens: Vec<&str> = path[1..].split_terminator('/').collect();

    match path_tokens[1..].len() {
        0 if method == Method::GET => {
            METRICS.get_api_requests.machine_cfg_count.inc();
            let empty_machine_config = VmConfig {
                vcpu_count: None,
                mem_size_mib: None,
                ht_enabled: None,
                cpu_template: None,
            };
            Ok(empty_machine_config
                .into_parsed_request(None, method)
                .map_err(|s| {
                    METRICS.get_api_requests.machine_cfg_fails.inc();
                    Error::Generic(StatusCode::BAD_REQUEST, s)
                })?)
        }

        0 if method == Method::PUT => {
            METRICS.put_api_requests.machine_cfg_count.inc();
            Ok(serde_json::from_slice::<VmConfig>(body)
                .map_err(|e| {
                    METRICS.put_api_requests.machine_cfg_fails.inc();
                    Error::SerdeJson(e)
                })?.into_parsed_request(None, method)
                .map_err(|s| {
                    METRICS.put_api_requests.machine_cfg_fails.inc();
                    Error::Generic(StatusCode::BAD_REQUEST, s)
                })?)
        }
        _ => Err(Error::InvalidPathMethod(path, method)),
    }
}

// Turns a GET/PUT /network-interfaces HTTP request into a ParsedRequest
fn parse_netif_req<'a>(path: &'a str, method: Method, body: &Chunk) -> Result<'a, ParsedRequest> {
    let path_tokens: Vec<&str> = path[1..].split_terminator('/').collect();
    let id_from_path = if path_tokens.len() > 1 {
        checked_id(path_tokens[1])?
    } else {
        return Err(Error::EmptyID);
    };

    match path_tokens[1..].len() {
        1 if method == Method::PUT => {
            METRICS.put_api_requests.network_count.inc();

            Ok(serde_json::from_slice::<NetworkInterfaceConfig>(body)
                .map_err(|e| {
                    METRICS.put_api_requests.network_fails.inc();
                    Error::SerdeJson(e)
                })?.into_parsed_request(Some(id_from_path.to_string()), method)
                .map_err(|s| {
                    METRICS.put_api_requests.network_fails.inc();
                    Error::Generic(StatusCode::BAD_REQUEST, s)
                })?)
        }
        _ => Err(Error::InvalidPathMethod(path, method)),
    }
}

#[cfg(feature = "vsock")]
// Turns a GET/PUT /vsocks HTTP request into a ParsedRequest.
fn parse_vsocks_req<'a>(path: &'a str, method: Method, body: &Chunk) -> Result<'a, ParsedRequest> {
    let path_tokens: Vec<&str> = path[1..].split_terminator('/').collect();
    let id_from_path = if path_tokens.len() > 1 {
        checked_id(path_tokens[1])?
    } else {
        return Err(Error::EmptyID);
    };

    match path_tokens[1..].len() {
        1 if method == Method::PUT => Ok(serde_json::from_slice::<VsockDeviceConfig>(body)
            .map_err(|e| Error::SerdeJson(e))?
            .into_parsed_request(Some(id_from_path.to_string()), method)
            .map_err(|s| {
                METRICS.put_api_requests.network_fails.inc();
                Error::Generic(StatusCode::BAD_REQUEST, s)
            })?),
        _ => Err(Error::InvalidPathMethod(path, method)),
    }
}

// This turns an incoming HTTP request into a ParsedRequest, which is an item containing both the
// message to be passed to the VMM, and associated entities, such as channels which allow the
// reception of the outcome back from the VMM.
// TODO: finish implementing/parsing all possible requests.
fn parse_request<'a>(method: Method, path: &'a str, body: &Chunk) -> Result<'a, ParsedRequest> {
    // Commenting this out for now.
    /*
    if cfg!(debug_assertions) {
        println!(
            "{}",
            format!(
                "got req: {} {}\n{}",
                method,
                path,
                str::from_utf8(body.as_ref()).unwrap()
                // when time will come, we could better do
                // serde_json::from_slice(&body).unwrap()
            )
        );
    }
    */

    if !path.starts_with('/') {
        return Err(Error::InvalidPathMethod(path, method));
    }

    // We use path[1..] here to skip the initial '/'.
    let path_tokens: Vec<&str> = path[1..].split_terminator('/').collect();

    if path_tokens.len() == 0 {
        if method == Method::GET {
            return Ok(ParsedRequest::GetInstanceInfo);
        } else {
            return Err(Error::InvalidPathMethod(path, method));
        }
    }

    match path_tokens[0] {
        "actions" => parse_actions_req(path, method, body),
        "boot-source" => parse_boot_source_req(path, method, body),
        "drives" => parse_drives_req(path, method, body),
        "logger" => parse_logger_req(path, method, body),
        "machine-config" => parse_machine_config_req(path, method, body),
        "network-interfaces" => parse_netif_req(path, method, body),
        "mmds" => parse_mmds_request(path, method, body),
        #[cfg(feature = "vsock")]
        "vsocks" => parse_vsocks_req(path, method, body),
        _ => Err(Error::InvalidPathMethod(path, method)),
    }
}

// A helper function which is always used when a message is placed into the communication channel
// with the VMM (so we don't forget to write to the EventFd).
fn send_to_vmm(
    req: VmmAction,
    sender: Sender<VmmAction>,
    send_event: &EventFd,
) -> result::Result<(), ()> {
    sender.send(req).map_err(|_| ())?;
    send_event.write(1).map_err(|_| ())
}

// In hyper, a struct that implements the Service trait is created to handle each incoming
// request. This is the one for our ApiServer.
pub struct ApiServerHttpService {
    // MMDS info directly accessible from this API thread.
    mmds_info: Arc<Mutex<Mmds>>,
    // VMM instance info directly accessible from this API thread.
    vmm_shared_info: Arc<RwLock<InstanceInfo>>,
    // This allows sending messages to the VMM thread. It makes sense to use a Rc for the sender
    // (instead of cloning) because everything happens on a single thread, so there's no risk of
    // having races (if that was even a problem to begin with).
    api_request_sender: Sender<VmmAction>,
    // We write to this EventFd to let the VMM know about new messages.
    vmm_send_event: Arc<EventFd>,
}

impl ApiServerHttpService {
    pub fn new(
        mmds_info: Arc<Mutex<Mmds>>,
        vmm_shared_info: Arc<RwLock<InstanceInfo>>,
        api_request_sender: Sender<VmmAction>,
        vmm_send_event: Arc<EventFd>,
    ) -> Self {
        ApiServerHttpService {
            mmds_info,
            vmm_shared_info,
            api_request_sender,
            vmm_send_event,
        }
    }
}


impl IntoFuture for ApiServerHttpService {
    type Future = future::FutureResult<Self::Item, Self::Error>;
    type Item = Self;
    type Error = ServiceError;

    fn into_future(self) -> Self::Future {
        future::ok(self)
    }
}

pub type FutureObj<T, E> = Box<Future<Item = T, Error = E> + Send>;
impl Service for ApiServerHttpService {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = ServiceError;
    type Future = FutureObj<Response<Self::ResBody>, Self::Error>;

    // This function returns a future that will resolve at some point to the response for
    // the HTTP request contained in req.
    fn call(&mut self, req: Request<Self::ReqBody>) -> Self::Future {
        // We do all this cloning to be able too move everything we need
        // into the closure that follows.
        let mmds_info = self.mmds_info.clone();
        let method = req.method().clone();
        let method_copy = req.method().clone();
        let path = String::from(req.uri().path());
        let shared_info_lock = self.vmm_shared_info.clone();
        let api_request_sender = self.api_request_sender.clone();
        let vmm_send_event = self.vmm_send_event.clone();

        // for nice looking match arms
        use request::ParsedRequest::*;

        // The request body is itself a future (a stream of Chunks to be more precise),
        // so we have to define a future that waits for all the pieces first (via concat2),
        // and then does something with the newly available body (via and_then).
        Box::new(req.into_body().concat2().map_err(ServiceError::Hyper).and_then(move |b: Chunk| {
            // When this will be executed, the body is available. We start by parsing the request.
            match parse_request(method, path.as_ref(), &b) {
                Ok(parsed_req) => match parsed_req {
                    GetInstanceInfo => {
                        METRICS.get_api_requests.instance_info_count.inc();

                        // unwrap() to crash if the other thread poisoned this lock
                        let shared_info = shared_info_lock
                            .read()
                            .expect("Failed to read shared_info due to poisoned lock");
                        // Serialize it to a JSON string.
                        let body_result = serde_json::to_string(&(*shared_info));
                        match body_result {
                            Ok(body) => Either::A(future::ok(json_response(StatusCode::OK, body))),
                            Err(e) => {
                                // This is an api server metrics as the shared info is obtained internally.
                                METRICS.get_api_requests.instance_info_fails.inc();
                                Either::A(future::ok(json_response(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    json_fault_message(e.to_string()),
                                )))
                            }
                        }
                    }
                    PatchMMDS(json_value) => {
                        let mut mmds = mmds_info
                            .lock()
                            .expect("Failed to acquire lock on MMDS info");
                        match mmds.is_initialized() {
                            true => {
                                mmds.patch_data(json_value);
                                Either::A(future::ok(empty_response(StatusCode::NO_CONTENT)))
                            }
                            false => Either::A(future::ok(json_response(
                                StatusCode::NOT_FOUND,
                                json_fault_message("The MMDS resource does not exist."),
                            ))),
                        }
                    }
                    PutMMDS(json_value) => {
                        mmds_info
                            .lock()
                            .expect("Failed to acquire lock on MMDS info")
                            .put_data(json_value);
                        Either::A(future::ok(empty_response(StatusCode::NoContent)))
                    }
                    GetMMDS => Either::A(future::ok(json_response(
                        StatusCode::Ok,
                        mmds_info
                            .lock()
                            .expect("Failed to acquire lock on MMDS info")
                            .get_data_str(),
                    ))),
                    Sync(sync_req, outcome_receiver) => {
                        if send_to_vmm(sync_req, api_request_sender, &vmm_send_event).is_err() {
                            METRICS.api_server.sync_vmm_send_timeout_count.inc();
                            return Either::A(future::err(ServiceError::Generic));
                        }

                        // metric-logging related variables for being able to log response details
                        let b_str = String::from_utf8_lossy(&b.to_vec()).to_string();
                        let b_str_err = String::from_utf8_lossy(&b.to_vec()).to_string();
                        let path_copy = path.clone();
                        let path_copy_err = path_copy.clone();
                        let method_copy_err = method_copy.clone();

                        info!("Sent {}", describe(&method_copy, &path, &b_str));

                        // Sync requests don't receive a response until the outcome is returned.
                        // Once more, this just registers a closure to run when the result is
                        // available.
                        Either::B(
                            outcome_receiver
                                .map(move |x| {
                                    info!(
                                        "Received Success on {}",
                                        describe(&method_copy, &path_copy, &b_str)
                                    );
                                    x.generate_response()
                                }).map_err(move |e| {
                                    info!(
                                        "Received Error on {}",
                                        describe(&method_copy_err, &path_copy_err, &b_str_err)
                                    );
                                    METRICS.api_server.sync_outcome_fails.inc();
                                    ServiceError::CanceledFuture(e)
                                }),
                        )
                    }
                },
                Err(e) => Either::A(future::ok(e.into())),
            }
        }))
    }
}

/// Helper function for metric-logging purposes on API requests
/// `method` is whether PUT or GET
/// `path` and `body` represent path of the API request and body, respectively
fn describe(method: &Method, path: &String, body: &String) -> String {
    format!(
        "synchronous {:?} request {:?} with body {:?}",
        method, path, body
    )
}

#[cfg(test)]
mod tests {
    extern crate net_util;

    use self::net_util::MacAddr;
    use super::*;

    use serde_json::{Map, Value};
    use std::path::PathBuf;
    use std::result;

    use futures::sync::oneshot;
    use hyper::{Body, header::{HeaderMap, HeaderName, HeaderValue}};
    use vmm::vmm_config::machine_config::CpuFeaturesTemplate;
    use vmm::VmmAction;

    impl<'a> PartialEq for Error<'a> {
        fn eq(&self, other: &Error<'a>) -> bool {
            use super::Error::*;

            match (self, other) {
                (Generic(sts, err), Generic(other_sts, other_err)) => {
                    sts == other_sts && err == other_err
                }
                (EmptyID, EmptyID) => true,
                (InvalidPathMethod(path, method), InvalidPathMethod(other_path, other_method)) => {
                    path == other_path && method == other_method
                }
                // Serde Errors do not implement PartialEq.
                (SerdeJson(_), SerdeJson(_)) => true,
                _ => false,
            }
        }
    }

    fn body_to_string(body: hyper::Body) -> String {
        let ret = body
            .fold(Vec::new(), |mut acc, chunk| {
                acc.extend_from_slice(&*chunk);
                Ok::<_, hyper::Error>(acc)
            }).and_then(move |value| Ok(value));

        String::from_utf8_lossy(
            &ret.wait()
                .expect("Couldn't convert request body into String due to Future polling failure"),
        ).into()
    }

    fn get_dummy_serde_error() -> serde_json::Error {
        // Returns a dummy serde error. This is used for testing that the errors returned
        // by parsing requests are SerdeJson(SerdeError(..)).
        let serde_json_err: result::Result<serde_json::Value, serde_json::Error> =
            serde_json::from_str("{");
        serde_json_err.unwrap_err()
    }

    macro_rules! assert_is_json {
        ($response:expr) => {
            assert_eq!(
                $response.headers().get("content-type"),
                Some(&HeaderValue::from_static("application/json"))
            );
        };
    }

    #[derive(Serialize, Deserialize)]
    struct Foo {
        bar: u32,
    }

    #[test]
    fn test_build_response_base() {
        let mut headers = HeaderMap::new();
        let content_type = HeaderName::from_static("content-type");
        let plain = HeaderValue::from_static("text/plain");

        headers.insert(
            &content_type,
            plain.clone(),
        );

        let body = String::from("This is a test");
        let response = build_response_base::<String>(StatusCode::OK, Some(headers), Some(body.clone()));

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().len(), 1);
        assert_eq!(response.headers().get(content_type), Some(&plain));
        assert_eq!(body_to_string(response.into_body()), body);
    }

    #[test]
    fn test_empty_response() {
        let response = empty_response(StatusCode::OK);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().len(), 0);
        assert_eq!(body_to_string(response.into_body()), body_to_string(Body::empty()));
    }

    #[test]
    fn test_json_response() {
        let body = String::from("This is not a valid JSON string, but the function works");
        let response = json_response::<String>(StatusCode::OK, body.clone());
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().len(), 1);
        assert_is_json!(response);
        assert_eq!(body_to_string(response.into_body()), body);
    }

    #[test]
    fn test_basic_json_body() {
        let body = basic_json_body("42", "the answer to life, the universe and everything");
        assert_eq!(
            body,
            "{\n  \"42\": \"the answer to life, the universe and everything\"\n}"
        );
    }

    #[test]
    fn test_json_fault_message() {
        let body = json_fault_message("This is an error message");
        assert_eq!(
            body,
            "{\n  \"fault_message\": \"This is an error message\"\n}"
        );
    }

    #[test]
    fn test_error_to_response() {
        let json_err_key = "fault_message";
        let json_err_val = "This is an error message";
        let err_message = format!("{{\n  \"{}\": \"{}\"\n}}", &json_err_key, &json_err_val);
        let message = String::from("This is an error message");
        let mut response: hyper::Response<Body> =
            Error::Generic(StatusCode::SERVICE_UNAVAILABLE, message).into();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_is_json!(response);
        assert_eq!(body_to_string(response.into_body()), err_message);

        response = Error::EmptyID.into();
        let json_err_val = "The ID cannot be empty.";
        let err_message = format!("{{\n  \"{}\": \"{}\"\n}}", &json_err_key, &json_err_val);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_is_json!(response);
        assert_eq!(body_to_string(response.into_body()), err_message);

        let path = String::from("/foo");
        let method = Method::OPTIONS;
        response = Error::InvalidPathMethod(&path, method.clone()).into();
        let json_err_val = format!("Invalid request method and/or path: {} {}", &method, &path);
        let err_message = format!("{{\n  \"{}\": \"{}\"\n}}", &json_err_key, &json_err_val);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_to_string(response.into_body()), err_message);

        let res = serde_json::from_str::<Foo>(&"foo");
        match res {
            Ok(_) => {}
            Err(e) => {
                response = Error::SerdeJson(e).into();
                assert_eq!(response.status(), StatusCode::BAD_REQUEST);
                assert_is_json!(response);
            }
        }
    }

    #[test]
    fn test_checked_id() {
        assert!(checked_id("dummy").is_ok());
    }

    #[test]
    fn test_parse_actions_req() {
        // PUT InstanceStart
        let json = "{
                \"action_type\": \"InstanceStart\"
              }";
        let body: Chunk = Chunk::from(json);
        let path = "/foo";

        match parse_actions_req(path, Method::PUT, &body) {
            Ok(pr) => {
                let (sender, receiver) = oneshot::channel();
                assert!(pr.eq(&ParsedRequest::Sync(
                    VmmAction::StartMicroVm(sender),
                    receiver
                )));
            }
            _ => assert!(false),
        }

        // PUT BlockDeviceRescan
        let json = r#"{
                "action_type": "BlockDeviceRescan",
                "payload": "dummy_id"
              }"#;
        let body: Chunk = Chunk::from(json);
        let path = "/foo";
        match parse_actions_req(path, Method::PUT, &body) {
            Ok(pr) => {
                let (sender, receiver) = oneshot::channel();
                assert!(pr.eq(&ParsedRequest::Sync(
                    VmmAction::RescanBlockDevice("dummy_id".to_string(), sender),
                    receiver
                )));
            }
            _ => assert!(false),
        }

        // Error cases

        // Test PUT with invalid path.
        let path = "/foo/bar/baz";
        let expected_err = Error::InvalidPathMethod(path, Method::PUT);
        assert!(parse_actions_req(path, Method::PUT, &Chunk::from("foo")) == Err(expected_err));

        // Test PUT with invalid action body (serde erorr).
        let actions_path = "/actions";
        assert!(
            parse_actions_req(actions_path, Method::PUT, &Chunk::from("foo"))
                == Err(Error::SerdeJson(get_dummy_serde_error()))
        );

        // Test PUT BadRequest due to invalid payload.
        let expected_err = Error::Generic(
            StatusCode::BAD_REQUEST,
            "InstanceStart does not support a payload.".to_string(),
        );
        let body = r#"{
            "action_type": "InstanceStart",
            "payload": {
                "foo": "bar"
            }
        }"#;
        assert!(
            parse_actions_req(actions_path, Method::PUT, &Chunk::from(body)) == Err(expected_err)
        );

        // Test invalid method.
        let expected_err = Error::InvalidPathMethod(actions_path, Method::POST);
        assert!(
            parse_actions_req(
                actions_path,
                Method::POST,
                &Chunk::from("{\"action_type\": \"InstanceStart\"}")
            ) == Err(expected_err)
        );
    }

    #[test]
    fn test_parse_boot_source_req() {
        let boot_source_path = "/boot-source";
        let boot_source_json = r#"{
                "kernel_image_path": "/foo/bar",
                "boot_args": "baz"
              }"#;
        let body: Chunk = Chunk::from(boot_source_json);

        // PUT
        // Falling back to json deserialization for constructing the "correct" request because not
        // all of BootSourceBody's members are accessible. Rather than making them all public just
        // for the purpose of unit tests, it's preferable to trust the deserialization.
        let boot_source_cfg = serde_json::from_slice::<BootSourceConfig>(&body).unwrap();
        match parse_boot_source_req(boot_source_path, Method::PUT, &body) {
            Ok(pr) => {
                let (sender, receiver) = oneshot::channel();
                assert!(pr.eq(&ParsedRequest::Sync(
                    VmmAction::ConfigureBootSource(boot_source_cfg, sender),
                    receiver,
                )));
            }
            _ => assert!(false),
        }

        // Error cases
        // Test case for invalid path.
        let dummy_path = "/boot-source/dummy";
        let expected_err = Error::InvalidPathMethod(dummy_path, Method::PUT);
        assert!(
            parse_boot_source_req(dummy_path, Method::PUT, &Chunk::from(boot_source_json))
                == Err(expected_err)
        );

        // Test case for invalid method (GET).
        let expected_err = Error::InvalidPathMethod(boot_source_path, Method::GET);
        assert!(
            parse_boot_source_req(boot_source_path, Method::GET, &Chunk::from("{}"))
                == Err(expected_err)
        );

        // Test case for invalid body (serde  error).
        assert!(
            parse_boot_source_req(boot_source_path, Method::PUT, &Chunk::from("foo"))
                == Err(Error::SerdeJson(get_dummy_serde_error()))
        );
    }

    #[test]
    fn test_parse_drives_req() {
        let valid_drive_path = "/drives/id_1";
        let json = "{
                \"drive_id\": \"id_1\",
                \"path_on_host\": \"/foo/bar\",
                \"is_root_device\": true,
                \"is_read_only\": true
              }";
        let body: Chunk = Chunk::from(json);

        // PUT
        let drive_desc = BlockDeviceConfig {
            drive_id: String::from("id_1"),
            path_on_host: PathBuf::from(String::from("/foo/bar")),
            is_root_device: true,
            partuuid: None,
            is_read_only: true,
            rate_limiter: None,
        };

        match drive_desc.into_parsed_request(Some(String::from("id_1")), Method::PUT) {
            Ok(pr) => match parse_drives_req(valid_drive_path, Method::PUT, &body) {
                Ok(pr_drive) => assert!(pr.eq(&pr_drive)),
                _ => assert!(false),
            },
            _ => assert!(false),
        }

        // Error Cases
        // Test Case for invalid payload (id from path does not match the id from the body).
        let expected_error = Err(Error::Generic(
            StatusCode::BAD_REQUEST,
            String::from("The id from the path does not match the id from the body!"),
        ));
        let path = "/drives/invalid_id";
        assert!(parse_drives_req(path, Method::PUT, &body) == expected_error);

        // Serde Error: Payload does not serialize to BlockDeviceConfig struct.
        assert!(
            parse_drives_req(valid_drive_path, Method::PUT, &Chunk::from("dummy_payload"))
                == Err(Error::SerdeJson(get_dummy_serde_error()))
        );

        // Test Case for invalid path (path does not contain the id).
        assert!(parse_drives_req("/foo", Method::PUT, &body) == Err(Error::EmptyID));

        // Test Case for invalid path (more than 2 tokens in path).
        let path = "/a/b/c";
        let expected_error = Err(Error::InvalidPathMethod(path, Method::PUT));
        assert!(parse_drives_req(path, Method::PUT, &body) == expected_error);

        // PATCH
        let json = r#"{
                "drive_id": "id_1",
                "path_on_host": "dummy"
              }"#;
        let valid_body: Chunk = Chunk::from(json);
        let mut payload_map = Map::new();
        payload_map.insert(
            String::from("drive_id"),
            Value::String(String::from("id_1")),
        );
        payload_map.insert(
            String::from("path_on_host"),
            Value::String(String::from("dummy")),
        );
        let patch_payload = PatchDrivePayload {
            fields: Value::Object(payload_map),
        };

        match patch_payload.into_parsed_request(Some("id_1".to_string()), Method::PATCH) {
            Ok(pr) => match parse_drives_req(valid_drive_path, Method::PATCH, &valid_body) {
                Ok(pr_drive) => assert!(pr.eq(&pr_drive)),
                _ => assert!(false),
            },
            _ => assert!(false),
        }

        // Test case where id from path is different.
        let expected_error = Err(Error::Generic(
            StatusCode::BAD_REQUEST,
            String::from("The id from the path does not match the id from the body!"),
        ));
        let path = "/drives/invalid_id";

        assert!(parse_drives_req(path, Method::PATCH, &valid_body) == expected_error);

        // Serde Error: Payload is an invalid JSON object.
        assert!(
            parse_drives_req(
                valid_drive_path,
                Method::PATCH,
                &Chunk::from("{drive_id: 1234}")
            ) == Err(Error::SerdeJson(get_dummy_serde_error()))
        );

        // Deserializing to a BlockDeviceConfig should fail when mandatory fields are missing.
        let json = "{
                \"drive_id\": \"bar\"
              }";
        let expected_error = Err(Error::Generic(
            StatusCode::BAD_REQUEST,
            String::from("Required key path_on_host not present in the json."),
        ));
        let body: Chunk = Chunk::from(json);
        assert!(parse_drives_req("/foo/bar", Method::PATCH, &body) == expected_error);
    }

    #[test]
    fn test_parse_logger_source_req() {
        let logger_path = "/logger";
        let json = "{
                \"log_fifo\": \"tmp1\",
                \"metrics_fifo\": \"tmp2\",
                \"level\": \"Info\",
                \"show_level\": true,
                \"show_log_origin\": true
              }";
        let logger_body: Chunk = Chunk::from(json);

        // PUT
        let logger_config =
            serde_json::from_slice::<LoggerConfig>(&logger_body).expect("deserialization failed");
        match parse_logger_req(logger_path, Method::PUT, &logger_body) {
            Ok(pr) => {
                let (sender, receiver) = oneshot::channel();
                assert!(pr.eq(&ParsedRequest::Sync(
                    VmmAction::ConfigureLogger(logger_config, sender),
                    receiver,
                )));
            }
            _ => assert!(false),
        }

        // Error cases
        // Error Case: Serde Deserialization fails due to invalid payload.
        assert!(
            parse_logger_req(logger_path, Method::PUT, &Chunk::from("foo"))
                == Err(Error::SerdeJson(get_dummy_serde_error()))
        );

        // Error Case: Invalid path.
        let expected_err = Err(Error::InvalidPathMethod("/foo/bar", Method::PUT));
        assert!(parse_logger_req(&"/foo/bar", Method::PUT, &Chunk::from("foo")) == expected_err);
    }

    #[test]
    fn test_parse_machine_config_req() {
        let path = "/machine-config";
        let json = "{
                \"vcpu_count\": 42,
                \"mem_size_mib\": 102,
                \"ht_enabled\": true,
                \"cpu_template\": \"T2\"
              }";
        let body: Chunk = Chunk::from(json);

        // GET
        assert!(parse_machine_config_req(path, Method::GET, &body).is_ok());

        // Error Cases
        // Error Case: Invalid Path.
        let expected_err = Err(Error::InvalidPathMethod("/foo/bar", Method::GET));
        assert!(parse_machine_config_req("/foo/bar", Method::GET, &body) == expected_err);

        // PUT
        let vm_config = VmConfig {
            vcpu_count: Some(42),
            mem_size_mib: Some(1025),
            ht_enabled: Some(true),
            cpu_template: Some(CpuFeaturesTemplate::T2),
        };

        match vm_config.into_parsed_request(None, Method::PUT) {
            Ok(parsed_req) => match parse_machine_config_req(&path, Method::PUT, &body) {
                Ok(other_parsed_req) => assert!(parsed_req.eq(&other_parsed_req)),
                _ => assert!(false),
            },
            _ => assert!(false),
        }

        // Error cases
        // Error Case: Invalid payload (cannot deserialize the body into a VmConfig object).
        assert!(
            parse_machine_config_req(path, Method::PUT, &Chunk::from("foo bar"))
                == Err(Error::SerdeJson(get_dummy_serde_error()))
        );

        // Error Case: Invalid payload (payload is empty).
        let expected_err = Err(Error::Generic(
            StatusCode::BAD_REQUEST,
            String::from("Empty request."),
        ));
        assert!(parse_machine_config_req(path, Method::PUT, &Chunk::from("{}")) == expected_err);
    }

    #[test]
    fn test_parse_netif_req() {
        let path = "/network-interfaces/id_1";
        let net_id = String::from("id_1");
        let json = "{
                \"iface_id\": \"id_1\",
                \"host_dev_name\": \"foo\",
                \"guest_mac\": \"12:34:56:78:9a:BC\"
              }";
        let body: Chunk = Chunk::from(json);

        // PUT
        let netif = NetworkInterfaceConfig {
            iface_id: net_id.clone(),
            host_dev_name: String::from("foo"),
            guest_mac: Some(MacAddr::parse_str("12:34:56:78:9a:BC").unwrap()),
            rx_rate_limiter: None,
            tx_rate_limiter: None,
            allow_mmds_requests: false,
            tap: None,
        };

        match netif.into_parsed_request(Some(net_id), Method::PUT) {
            Ok(pr) => match parse_netif_req(&path, Method::PUT, &body) {
                Ok(pr_netif) => assert!(pr.eq(&pr_netif)),
                _ => assert!(false),
            },
            _ => assert!(false),
        }

        // Error cases
        // Error Case: The id from the path does not match the id from the body.
        let expected_err = Err(Error::Generic(
            StatusCode::BAD_REQUEST,
            String::from("The id from the path does not match the id from the body!"),
        ));
        let path = "/network-interfaces/invalid_id";

        assert!(parse_netif_req(path, Method::PUT, &body) == expected_err);

        // Error Case: Invalid payload (cannot deserialize the body into a NetworkInterfaceBody object).
        assert!(
            parse_netif_req(path, Method::PUT, &Chunk::from("foo bar"))
                == Err(Error::SerdeJson(get_dummy_serde_error()))
        );

        // Error Case: Invalid Path.
        assert!(
            parse_netif_req(path, Method::PATCH, &body,)
                == Err(Error::InvalidPathMethod(path, Method::PATCH))
        )
    }

    #[test]
    fn test_parse_mmds_request() {
        let path = "/mmds";
        let empty_json = "{}";
        let body = Chunk::from(empty_json);

        // Test for GET request
        match parse_mmds_request(path, Method::GET, &body) {
            Ok(parsed_req) => assert!(parsed_req.eq(&ParsedRequest::GetMMDS)),
            Err(_) => assert!(false),
        };

        let dummy_json = "{\
                \"latest\": {\
                    \"meta-data\": {\
                        \"iam\": \"dummy\"\
                    },\
                    \"user-data\": 1522850095\
                }
            }";

        // Test for PUT request
        let body = Chunk::from(dummy_json);
        match parse_mmds_request(path, Method::PUT, &body) {
            Ok(parsed_req) => assert!(parsed_req.eq(&ParsedRequest::PutMMDS(
                serde_json::from_slice(&body).unwrap()
            ))),
            Err(_) => assert!(false),
        };

        // Test for PATCH request
        let patch_json = "{\"user-data\": 15}";
        let body = Chunk::from(patch_json);
        match parse_mmds_request(path, Method::PATCH, &body) {
            Ok(parsed_req) => assert!(parsed_req.eq(&ParsedRequest::PatchMMDS(
                serde_json::from_slice(&body).unwrap()
            ))),
            Err(_) => assert!(false),
        };

        // Test for invalid json on PUT
        let invalid_json = "\"latest\": {}}";
        let body = Chunk::from(invalid_json);
        assert!(
            parse_mmds_request(path, Method::PUT, &body)
                == Err(Error::SerdeJson(get_dummy_serde_error()))
        );

        // Test for invalid json on PATCH
        let invalid_json = "\"latest\": {}}";
        let body = Chunk::from(invalid_json);
        assert!(
            parse_mmds_request(path, Method::PATCH, &body)
                == Err(Error::SerdeJson(get_dummy_serde_error()))
        );

        // Test for invalid path
        let path = "/mmds/something";
        let expected_err = Err(Error::InvalidPathMethod(path, Method::GET));
        assert!(parse_mmds_request(path, Method::GET, &body) == expected_err);
    }

    #[test]
    fn test_parse_request() {
        let body: Chunk = Chunk::from("{ \"foo\": \"bar\" }");

        assert!(parse_request(Method::GET, "foo/bar", &body).is_err());

        let all_methods = vec![
            Method::PUT,
            Method::OPTIONS,
            Method::POST,
            Method::DELETE,
            Method::HEAD,
            Method::TRACE,
            Method::CONNECT,
            Method::PATCH,
            Method::from_bytes(b"foobar").unwrap(),
        ];

        for method in &all_methods {
            assert!(parse_request(method.clone(), "/foo", &body).is_err());
        }

        // Test empty request
        match parse_request(Method::GET, "/", &body) {
            Ok(pr) => assert!(pr.eq(&ParsedRequest::GetInstanceInfo)),
            _ => assert!(false),
        }
        for method in &all_methods {
            if *method != Method::GET {
                assert!(parse_request(method.clone(), "/", &body).is_err());
            }
        }

        // Test all valid requests
        // Each request type is unit tested separately
        for path in vec![
            "/boot-source",
            "/drives",
            "/machine-config",
            "/network-interfaces",
        ] {
            for method in &all_methods {
                if *method != Method::GET && *method != Method::PUT {
                    assert!(parse_request(method.clone(), path, &body).is_err());
                }
            }
        }
    }

    #[test]
    fn test_describe() {
        let body: String = String::from("{ \"foo\": \"bar\" }");
        let msj = describe(&Method::GET, &String::from("/foo/bar"), &body);
        assert_eq!(
            msj,
            "synchronous Get request \"/foo/bar\" with body \"{ \\\"foo\\\": \\\"bar\\\" }\""
        );
        let msj = describe(&Method::PUT, &String::from("/foo/bar"), &body);
        assert_eq!(
            msj,
            "synchronous Put request \"/foo/bar\" with body \"{ \\\"foo\\\": \\\"bar\\\" }\""
        );
    }
}
