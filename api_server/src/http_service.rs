use std::rc::Rc;
use std::result;
use std::str;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, RwLock};

use futures::future::{self, Either};
use futures::{Future, Stream};

use hyper::{self, Chunk, Headers, Method, StatusCode};
use serde_json;

use data_model::mmds::Mmds;
use data_model::vm::{BlockDeviceConfig, VmConfig};
use logger::{Metric, METRICS};
use request::actions::ActionBody;
use request::drive::PatchDrivePayload;
use request::{GenerateHyperResponse, IntoParsedRequest, ParsedRequest};
use sys_util::EventFd;
use vmm::vmm_config::boot_source::BootSourceConfig;
use vmm::vmm_config::instance_info::InstanceInfo;
use vmm::vmm_config::logger::LoggerConfig;
use vmm::vmm_config::net::NetworkInterfaceBody;
use vmm::VmmAction;

fn build_response_base<B: Into<hyper::Body>>(
    status: StatusCode,
    maybe_headers: Option<Headers>,
    maybe_body: Option<B>,
) -> hyper::Response {
    let mut response = hyper::Response::new().with_status(status);
    if let Some(headers) = maybe_headers {
        response = response.with_headers(headers);
    }
    if let Some(body) = maybe_body {
        response.set_body(body);
    }
    response
}

// An HTTP response with just a status code.
pub fn empty_response(status: StatusCode) -> hyper::Response {
    build_response_base::<String>(status, None, None)
}

// An HTTP response which also includes a body.
pub fn json_response<T: Into<hyper::Body>>(status: StatusCode, body: T) -> hyper::Response {
    let mut headers = Headers::new();
    headers.set(hyper::header::ContentType::json());
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
    InvalidID,
    // The HTTP method & request path combination is not valid.
    InvalidPathMethod(&'a str, Method),
    // An error occurred when deserializing the json body of a request.
    SerdeJson(serde_json::Error),
}

// It's convenient to turn errors into HTTP responses directly.
impl<'a> Into<hyper::Response> for Error<'a> {
    fn into(self) -> hyper::Response {
        match self {
            Error::Generic(status, msg) => json_response(status, json_fault_message(msg)),
            Error::InvalidID => {
                json_response(StatusCode::BadRequest, json_fault_message("Invalid ID"))
            }
            Error::InvalidPathMethod(path, method) => json_response(
                StatusCode::BadRequest,
                json_fault_message(format!(
                    "Invalid request method and/or path: {} {}",
                    method, path
                )),
            ),
            Error::SerdeJson(e) => {
                json_response(StatusCode::BadRequest, json_fault_message(e.to_string()))
            }
        }
    }
}

type Result<'a, T> = result::Result<T, Error<'a>>;

// This function is supposed to do id validation for requests.
fn checked_id(id: &str) -> Result<&str> {
    // todo: are there any checks we want to do on id's?
    // not allow them to be empty strings maybe?
    Ok(id)
}

// Turns a GET/PUT /actions HTTP request into a ParsedRequest
fn parse_actions_req<'a>(
    path_tokens: &Vec<&str>,
    path: &'a str,
    method: Method,
    body: &Chunk,
) -> Result<'a, ParsedRequest> {
    match path_tokens.len() {
        1 if method == Method::Put => {
            METRICS.put_api_requests.actions_count.inc();
            Ok(serde_json::from_slice::<ActionBody>(body.as_ref())
                .map_err(|e| {
                    METRICS.put_api_requests.actions_fails.inc();
                    Error::SerdeJson(e)
                })?.into_parsed_request(None, method)
                .map_err(|msg| {
                    METRICS.put_api_requests.actions_fails.inc();
                    Error::Generic(StatusCode::BadRequest, msg)
                })?)
        }
        _ => Err(Error::InvalidPathMethod(path, method)),
    }
}

// Turns a GET/PUT /boot-source HTTP request into a ParsedRequest
fn parse_boot_source_req<'a>(
    path_tokens: &Vec<&str>,
    path: &'a str,
    method: Method,
    body: &Chunk,
) -> Result<'a, ParsedRequest> {
    match path_tokens[1..].len() {
        0 if method == Method::Get => Ok(ParsedRequest::Dummy),

        0 if method == Method::Put => {
            METRICS.put_api_requests.boot_source_count.inc();
            Ok(serde_json::from_slice::<BootSourceConfig>(body)
                .map_err(|e| {
                    METRICS.put_api_requests.boot_source_fails.inc();
                    Error::SerdeJson(e)
                })?.into_parsed_request(None, method)
                .map_err(|s| {
                    METRICS.put_api_requests.boot_source_fails.inc();
                    Error::Generic(StatusCode::BadRequest, s)
                })?)
        }
        _ => Err(Error::InvalidPathMethod(path, method)),
    }
}

// Turns HTTP requests on /mmds into a ParsedRequest
// This is a rather dummy method with the purpose of keeping the same code structure as before.
// We will need to refactor this as some point.
fn parse_mmds_request<'a>(
    path_tokens: &Vec<&str>,
    path: &'a str,
    method: Method,
    body: &Chunk,
) -> Result<'a, ParsedRequest> {
    match path_tokens[1..].len() {
        0 if method == Method::Get => Ok(ParsedRequest::GetMMDS),
        0 if method == Method::Put => {
            match serde_json::from_slice(&body) {
                Ok(val) => return Ok(ParsedRequest::PutMMDS(val)),
                Err(e) => return Err(Error::SerdeJson(e)),
            };
        }
        0 if method == Method::Patch => match serde_json::from_slice(&body) {
            Ok(val) => return Ok(ParsedRequest::PatchMMDS(val)),
            Err(e) => return Err(Error::SerdeJson(e)),
        },
        _ => Err(Error::InvalidPathMethod(path, method)),
    }
}

// Turns a GET/PUT /drives HTTP request into a ParsedRequest
fn parse_drives_req<'a>(
    path_tokens: &Vec<&str>,
    path: &'a str,
    method: Method,
    id_from_path: &Option<&str>,
    body: &Chunk,
) -> Result<'a, ParsedRequest> {
    match path_tokens[1..].len() {
        0 if method == Method::Get => Ok(ParsedRequest::Dummy),

        1 if method == Method::Get => Ok(ParsedRequest::Dummy),

        1 if method == Method::Put => {
            let unwrapped_id = id_from_path.ok_or(Error::InvalidID)?;
            METRICS.put_api_requests.drive_count.inc();

            let device_cfg = serde_json::from_slice::<BlockDeviceConfig>(body).map_err(|e| {
                METRICS.put_api_requests.drive_fails.inc();
                Error::SerdeJson(e)
            })?;
            Ok(device_cfg
                .into_parsed_request(Some(unwrapped_id.to_string()), method)
                .map_err(|s| {
                    METRICS.put_api_requests.drive_fails.inc();
                    Error::Generic(StatusCode::BadRequest, s)
                })?)
        }

        1 if method == Method::Patch => {
            METRICS.patch_api_requests.drive_count.inc();

            Ok(PatchDrivePayload {
                fields: serde_json::from_slice(body).map_err(|e| {
                    METRICS.patch_api_requests.drive_fails.inc();
                    Error::SerdeJson(e)
                })?,
            }.into_parsed_request(None, method)
            .map_err(|s| {
                METRICS.patch_api_requests.drive_fails.inc();
                Error::Generic(StatusCode::BadRequest, s)
            })?)
        }

        _ => Err(Error::InvalidPathMethod(path, method)),
    }
}

// Turns a GET/PUT /logger HTTP request into a ParsedRequest
fn parse_logger_req<'a>(
    path_tokens: &Vec<&str>,
    path: &'a str,
    method: Method,
    body: &Chunk,
) -> Result<'a, ParsedRequest> {
    match path_tokens[1..].len() {
        0 if method == Method::Get => Ok(ParsedRequest::Dummy),

        0 if method == Method::Put => {
            METRICS.put_api_requests.logger_count.inc();
            Ok(serde_json::from_slice::<LoggerConfig>(body)
                .map_err(|e| {
                    METRICS.put_api_requests.logger_fails.inc();
                    Error::SerdeJson(e)
                })?.into_parsed_request(None, method)
                .map_err(|s| {
                    METRICS.put_api_requests.logger_fails.inc();
                    Error::Generic(StatusCode::BadRequest, s)
                })?)
        }
        _ => Err(Error::InvalidPathMethod(path, method)),
    }
}

// Turns a GET/PUT /machine-config HTTP request into a ParsedRequest
fn parse_machine_config_req<'a>(
    path_tokens: &Vec<&str>,
    path: &'a str,
    method: Method,
    body: &Chunk,
) -> Result<'a, ParsedRequest> {
    match path_tokens[1..].len() {
        0 if method == Method::Get => {
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
                    Error::Generic(StatusCode::BadRequest, s)
                })?)
        }

        0 if method == Method::Put => {
            METRICS.put_api_requests.machine_cfg_count.inc();
            Ok(serde_json::from_slice::<VmConfig>(body)
                .map_err(|e| {
                    METRICS.put_api_requests.machine_cfg_fails.inc();
                    Error::SerdeJson(e)
                })?.into_parsed_request(None, method)
                .map_err(|s| {
                    METRICS.put_api_requests.machine_cfg_fails.inc();
                    Error::Generic(StatusCode::BadRequest, s)
                })?)
        }
        _ => Err(Error::InvalidPathMethod(path, method)),
    }
}

// Turns a GET/PUT /network-interfaces HTTP request into a ParsedRequest
fn parse_netif_req<'a>(
    path_tokens: &Vec<&str>,
    path: &'a str,
    method: Method,
    id_from_path: &Option<&str>,
    body: &Chunk,
) -> Result<'a, ParsedRequest> {
    match path_tokens[1..].len() {
        0 if method == Method::Get => Ok(ParsedRequest::Dummy),

        1 if method == Method::Get => Ok(ParsedRequest::Dummy),

        1 if method == Method::Put => {
            let unwrapped_id = id_from_path.ok_or(Error::InvalidID)?;
            METRICS.put_api_requests.network_count.inc();

            Ok(serde_json::from_slice::<NetworkInterfaceBody>(body)
                .map_err(|e| {
                    METRICS.put_api_requests.network_fails.inc();
                    Error::SerdeJson(e)
                })?.into_parsed_request(Some(unwrapped_id.to_string()), method)
                .map_err(|s| {
                    METRICS.put_api_requests.network_fails.inc();
                    Error::Generic(StatusCode::BadRequest, s)
                })?)
        }
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

    // The unwraps on id_from_path in later code should not panic because they are only
    // called when path_tokens.len() > 1.
    let id_from_path = if path_tokens.len() > 1 {
        Some(checked_id(path_tokens[1])?)
    } else {
        None
    };

    if path_tokens.len() == 0 {
        if method == Method::Get {
            return Ok(ParsedRequest::GetInstanceInfo);
        } else {
            return Err(Error::InvalidPathMethod(path, method));
        }
    }

    match path_tokens[0] {
        "actions" => parse_actions_req(&path_tokens, path, method, body),
        "boot-source" => parse_boot_source_req(&path_tokens, path, method, body),
        "drives" => parse_drives_req(&path_tokens, path, method, &id_from_path, body),
        "logger" => parse_logger_req(&path_tokens, path, method, body),
        "machine-config" => parse_machine_config_req(&path_tokens, path, method, body),
        "network-interfaces" => parse_netif_req(&path_tokens, path, method, &id_from_path, body),
        "mmds" => parse_mmds_request(&path_tokens, path, method, body),
        _ => Err(Error::InvalidPathMethod(path, method)),
    }
}

// A helper function which is always used when a message is placed into the communication channel
// with the VMM (so we don't forget to write to the EventFd).
fn send_to_vmm(
    req: VmmAction,
    sender: &mpsc::Sender<Box<VmmAction>>,
    send_event: &EventFd,
) -> result::Result<(), ()> {
    sender.send(Box::new(req)).map_err(|_| ())?;
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
    api_request_sender: Rc<mpsc::Sender<Box<VmmAction>>>,
    // We write to this EventFd to let the VMM know about new messages.
    vmm_send_event: Rc<EventFd>,
}

impl ApiServerHttpService {
    pub fn new(
        mmds_info: Arc<Mutex<Mmds>>,
        vmm_shared_info: Arc<RwLock<InstanceInfo>>,
        api_request_sender: Rc<mpsc::Sender<Box<VmmAction>>>,
        vmm_send_event: Rc<EventFd>,
    ) -> Self {
        ApiServerHttpService {
            mmds_info,
            vmm_shared_info,
            api_request_sender,
            vmm_send_event,
        }
    }
}

impl hyper::server::Service for ApiServerHttpService {
    type Request = hyper::Request;
    type Response = hyper::Response;
    type Error = hyper::error::Error;
    type Future = Box<Future<Item = Self::Response, Error = Self::Error>>;

    // This function returns a future that will resolve at some point to the response for
    // the HTTP request contained in req.
    fn call(&self, req: Self::Request) -> Self::Future {
        // We do all this cloning to be able too move everything we need
        // into the closure that follows.
        let mmds_info = self.mmds_info.clone();
        let method = req.method().clone();
        let method_copy = req.method().clone();
        let path = String::from(req.path());
        let shared_info_lock = self.vmm_shared_info.clone();
        let api_request_sender = self.api_request_sender.clone();
        let vmm_send_event = self.vmm_send_event.clone();

        // for nice looking match arms
        use request::ParsedRequest::*;

        // The request body is itself a future (a stream of Chunks to be more precise),
        // so we have to define a future that waits for all the pieces first (via concat2),
        // and then does something with the newly available body (via and_then).
        Box::new(req.body().concat2().and_then(move |b| {
            // When this will be executed, the body is available. We start by parsing the request.
            match parse_request(method, path.as_ref(), &b) {
                Ok(parsed_req) => match parsed_req {
                    // TODO: remove this when all actions are implemented.
                    Dummy => Either::A(future::ok(json_response(StatusCode::Ok, "I'm a dummy."))),
                    GetInstanceInfo => {
                        METRICS.get_api_requests.instance_info_count.inc();

                        // unwrap() to crash if the other thread poisoned this lock
                        let shared_info = shared_info_lock.read().unwrap();
                        // Serialize it to a JSON string.
                        let body_result = serde_json::to_string(&(*shared_info));
                        match body_result {
                            Ok(body) => Either::A(future::ok(json_response(StatusCode::Ok, body))),
                            Err(e) => {
                                // This is an api server metrics as the shared info is obtained internally.
                                METRICS.api_server.instance_info_fails.inc();
                                Either::A(future::ok(json_response(
                                    StatusCode::InternalServerError,
                                    json_fault_message(e.to_string()),
                                )))
                            }
                        }
                    }
                    PatchMMDS(json_value) => {
                        let mut mmds = mmds_info.lock().unwrap();
                        match mmds.is_initialized() {
                            true => {
                                mmds.patch_data(json_value);
                                Either::A(future::ok(empty_response(StatusCode::NoContent)))
                            }
                            false => Either::A(future::ok(json_response(
                                StatusCode::NotFound,
                                json_fault_message("The MMDS resource does not exist."),
                            ))),
                        }
                    }
                    PutMMDS(json_value) => {
                        let status_code = match mmds_info.lock().unwrap().is_initialized() {
                            true => StatusCode::NoContent,
                            false => StatusCode::Created,
                        };
                        mmds_info.lock().unwrap().put_data(json_value);
                        Either::A(future::ok(empty_response(status_code)))
                    }
                    GetMMDS => Either::A(future::ok(json_response(
                        StatusCode::Ok,
                        mmds_info.lock().unwrap().get_data_str(),
                    ))),
                    Sync(sync_req, outcome_receiver) => {
                        if send_to_vmm(sync_req, &api_request_sender, &vmm_send_event).is_err() {
                            METRICS.api_server.sync_vmm_send_timeout_count.inc();
                            return Either::A(future::err(hyper::Error::Timeout));
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
                                })
                                .map_err(move |_| {
                                    info!(
                                        "Received Error on {}",
                                        describe(
                                            &method_copy_err,
                                            &path_copy_err,
                                            &b_str_err
                                        )
                                    );
                                    METRICS.api_server.sync_outcome_fails.inc();
                                    hyper::Error::Timeout
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

    use data_model::vm::CpuFeaturesTemplate;
    use futures::sync::oneshot;
    use hyper::header::{ContentType, Headers};
    use hyper::Body;
    use vmm::vmm_config::DeviceState;
    use vmm::VmmAction;

    impl<'a> PartialEq for Error<'a> {
        fn eq(&self, other: &Error<'a>) -> bool {
            use super::Error::*;

            match (self, other) {
                (Generic(sts, err), Generic(other_sts, other_err)) => {
                    sts == other_sts && err == other_err
                }
                (InvalidID, InvalidID) => true,
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

        String::from_utf8_lossy(&ret.wait().unwrap()).into()
    }

    #[derive(Serialize, Deserialize)]
    struct Foo {
        bar: u32,
    }

    #[test]
    fn test_build_response_base() {
        let mut headers = Headers::new();
        let content_type_hdr = ContentType::plaintext();
        headers.set(ContentType::plaintext());
        let body = String::from("This is a test");
        let resp = build_response_base::<String>(StatusCode::Ok, Some(headers), Some(body.clone()));

        assert_eq!(resp.status(), StatusCode::Ok);
        assert_eq!(resp.headers().len(), 1);
        assert_eq!(resp.headers().get::<ContentType>(), Some(&content_type_hdr));
        assert_eq!(body_to_string(resp.body()), body);
    }

    #[test]
    fn test_empty_response() {
        let resp = empty_response(StatusCode::Ok);
        assert_eq!(resp.status(), StatusCode::Ok);
        assert_eq!(resp.headers().len(), 0);
        assert_eq!(body_to_string(resp.body()), body_to_string(Body::empty()));
    }

    #[test]
    fn test_json_response() {
        let body = String::from("This is not a valid JSON string, but the function works");
        let resp = json_response::<String>(StatusCode::Ok, body.clone());
        assert_eq!(resp.status(), StatusCode::Ok);
        assert_eq!(resp.headers().len(), 1);
        assert_eq!(
            resp.headers().get::<ContentType>(),
            Some(&ContentType::json())
        );
        assert_eq!(body_to_string(resp.body()), body);
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
        let mut response: hyper::Response =
            Error::Generic(StatusCode::ServiceUnavailable, message).into();
        assert_eq!(response.status(), StatusCode::ServiceUnavailable);
        assert_eq!(
            response.headers().get::<ContentType>(),
            Some(&ContentType::json())
        );
        assert_eq!(body_to_string(response.body()), err_message);

        response = Error::InvalidID.into();
        let json_err_val = "Invalid ID";
        let err_message = format!("{{\n  \"{}\": \"{}\"\n}}", &json_err_key, &json_err_val);
        assert_eq!(response.status(), StatusCode::BadRequest);
        assert_eq!(
            response.headers().get::<ContentType>(),
            Some(&ContentType::json())
        );
        assert_eq!(body_to_string(response.body()), err_message);

        let path = String::from("/foo");
        let method = Method::Options;
        response = Error::InvalidPathMethod(&path, method.clone()).into();
        let json_err_val = format!("Invalid request method and/or path: {} {}", &method, &path);
        let err_message = format!("{{\n  \"{}\": \"{}\"\n}}", &json_err_key, &json_err_val);
        assert_eq!(response.status(), StatusCode::BadRequest);
        assert_eq!(
            response.headers().get::<ContentType>(),
            Some(&ContentType::json())
        );
        assert_eq!(body_to_string(response.body()), err_message);

        let res = serde_json::from_str::<Foo>(&"foo");
        match res {
            Ok(_) => {}
            Err(e) => {
                response = Error::SerdeJson(e).into();
                assert_eq!(response.status(), StatusCode::BadRequest);
                assert_eq!(
                    response.headers().get::<ContentType>(),
                    Some(&ContentType::json())
                );
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
        let path_tokens: Vec<&str> = path[1..].split_terminator('/').collect();

        match parse_actions_req(&path_tokens, &path, Method::Put, &body) {
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
        let path_tokens: Vec<&str> = path[1..].split_terminator('/').collect();
        match parse_actions_req(&path_tokens, &path, Method::Put, &body) {
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
        let expected_err = Error::InvalidPathMethod(path, Method::Put);
        assert!(
            parse_actions_req(
                &path[1..].split_terminator('/').collect(),
                &path,
                Method::Put,
                &Chunk::from("foo"),
            ) == Err(expected_err)
        );

        // Test PUT with invalid action body (serde erorr).
        let actions_path = "/actions";
        // Fake a serde json error so we can use it to test that the error returned from
        // parse_actions_req comes from serde.
        let serde_json_err: result::Result<serde_json::Value, serde_json::Error> =
            serde_json::from_str("{");
        let serde_json_err: serde_json::Error = serde_json_err.unwrap_err();
        assert!(
            parse_actions_req(
                &actions_path[1..].split_terminator('/').collect(),
                &actions_path,
                Method::Put,
                &Chunk::from("foo"),
            ) == Err(Error::SerdeJson(serde_json_err))
        );

        // Test PUT BadRequest due to invalid payload.
        let expected_err = Error::Generic(
            StatusCode::BadRequest,
            "InstanceStart does not support a payload.".to_string(),
        );
        let body = r#"{
            "action_type": "InstanceStart",
            "payload": {
                "foo": "bar"
            }
        }"#;
        assert!(
            parse_actions_req(
                &actions_path[1..].split_terminator('/').collect(),
                &actions_path,
                Method::Put,
                &Chunk::from(body)
            ) == Err(expected_err)
        );

        // Test invalid method.
        let expected_err = Error::InvalidPathMethod(actions_path, Method::Post);
        assert!(
            parse_actions_req(
                &actions_path.split_terminator('/').collect(),
                &actions_path,
                Method::Post,
                &Chunk::from("{\"action_type\": \"InstanceStart\"}")
            ) == Err(expected_err)
        );
    }

    #[test]
    fn test_parse_boot_source_req() {
        let path = "/foo";
        let path_tokens: Vec<&str> = path[1..].split_terminator('/').collect();
        let json = r#"{
                "kernel_image_path": "/foo/bar",
                "boot_args": "baz"
              }"#;
        let body: Chunk = Chunk::from(json);

        // GET
        match parse_boot_source_req(&path_tokens, &path, Method::Get, &body) {
            Ok(pr_dummy) => assert!(pr_dummy.eq(&ParsedRequest::Dummy)),
            _ => assert!(false),
        }

        // PUT
        // Falling back to json deserialization for constructing the "correct" request because not
        // all of BootSourceBody's members are accessible. Rather than making them all public just
        // for the purpose of unit tests, it's preferable to trust the deserialization.
        let res_bsb = serde_json::from_slice::<BootSourceConfig>(&body);
        match res_bsb {
            Ok(boot_source_body) => {
                match parse_boot_source_req(&path_tokens, &path, Method::Put, &body) {
                    Ok(pr) => {
                        let (sender, receiver) = oneshot::channel();
                        assert!(pr.eq(&ParsedRequest::Sync(
                            VmmAction::ConfigureBootSource(boot_source_body, sender),
                            receiver,
                        )));
                    }
                    _ => assert!(false),
                }
            }
            _ => assert!(false),
        }

        // Error cases
        assert!(
            parse_boot_source_req(&path_tokens, &path, Method::Put, &Chunk::from("foo")).is_err()
        );

        assert!(
            parse_boot_source_req(
                &"/foo/bar"[1..].split_terminator('/').collect(),
                &"/foo/bar",
                Method::Put,
                &Chunk::from("foo")
            ).is_err()
        );
    }

    #[test]
    fn test_parse_drives_req() {
        let path = "/foo/bar";
        let path_tokens: Vec<&str> = path[1..].split_terminator('/').collect();
        let id_from_path = Some(path_tokens[1]);
        let json = "{
                \"drive_id\": \"bar\",
                \"path_on_host\": \"/foo/bar\",
                \"is_root_device\": true,
                \"is_read_only\": true
              }";
        let body: Chunk = Chunk::from(json);

        // GET
        match parse_drives_req(
            &"/foo"[1..].split_terminator('/').collect(),
            &"/foo",
            Method::Get,
            &None,
            &body,
        ) {
            Ok(pr_dummy) => assert!(pr_dummy.eq(&ParsedRequest::Dummy)),
            _ => assert!(false),
        }

        match parse_drives_req(&path_tokens, &path, Method::Get, &id_from_path, &body) {
            Ok(pr_dummy) => assert!(pr_dummy.eq(&ParsedRequest::Dummy)),
            _ => assert!(false),
        }

        // PUT
        let drive_desc = BlockDeviceConfig {
            drive_id: String::from("bar"),
            path_on_host: PathBuf::from(String::from("/foo/bar")),
            is_root_device: true,
            partuuid: None,
            is_read_only: true,
            rate_limiter: None,
        };

        match drive_desc.into_parsed_request(Some(String::from("bar")), Method::Put) {
            Ok(pr) => match parse_drives_req(
                &"/foo/bar"[1..].split_terminator('/').collect(),
                &"/foo/bar",
                Method::Put,
                &Some("bar"),
                &body,
            ) {
                Ok(pr_drive) => assert!(pr.eq(&pr_drive)),
                _ => assert!(false),
            },
            _ => assert!(false),
        }

        assert!(
            parse_drives_req(
                &"/foo"[1..].split_terminator('/').collect(),
                &"/foo",
                Method::Put,
                &None,
                &body
            ).is_err()
        );

        // PATCH
        let json = r#"{
                "drive_id": "bar",
                "path_on_host": "dummy"
              }"#;
        let body: Chunk = Chunk::from(json);
        let mut payload_map = Map::<String, Value>::new();
        payload_map.insert(String::from("drive_id"), Value::String(String::from("bar")));
        payload_map.insert(
            String::from("path_on_host"),
            Value::String(String::from("dummy")),
        );
        let patch_payload = PatchDrivePayload {
            fields: Value::Object(payload_map),
        };

        match patch_payload.into_parsed_request(None, Method::Patch) {
            Ok(pr) => {
                match parse_drives_req(&path_tokens, &path, Method::Patch, &id_from_path, &body) {
                    Ok(pr_drive) => assert!(pr.eq(&pr_drive)),
                    _ => assert!(false),
                }
            }
            _ => assert!(false),
        }

        // Test case where id from path is different.
        assert!(
            parse_drives_req(
                &"/foo/bar"[1..].split_terminator('/').collect(),
                &"/foo/bar",
                Method::Put,
                &Some("barr"),
                &body
            ).is_err()
        );

        // Test case where the id of the request body is different.
        let json = "{
                \"drive_id\": \"barr\",
                \"path_on_host\": \"/foo/bar\",
                \"is_root_device\": true,
                \"is_read_only\": true
              }";
        let body: Chunk = Chunk::from(json);
        assert!(
            parse_drives_req(
                &"/foo/bar"[1..].split_terminator('/').collect(),
                &"/foo/bar",
                Method::Put,
                &Some("bar"),
                &body
            ).is_err()
        );

        // Deserializing to a BlockDeviceConfig should fail when mandatory fields are missing.
        let json = "{
                \"drive_id\": \"bar\",
                \"path_on_host\": \"/foo/bar\",
                \"is_read_only\": true
              }";
        let body: Chunk = Chunk::from(json);
        assert!(
            parse_drives_req(
                &"/foo/bar"[1..].split_terminator('/').collect(),
                &"/foo/bar",
                Method::Put,
                &Some("bar"),
                &body
            ).is_err()
        );

        // Test case where the PATCH payload is invalid.
        let json = "{
                \"drive_id\": \"bar\",
                \"foo\"
              }";
        let body: Chunk = Chunk::from(json);
        assert!(
            parse_drives_req(
                &"/foo/bar"[1..].split_terminator('/').collect(),
                &"/foo/bar",
                Method::Patch,
                &Some("bar"),
                &body
            ).is_err()
        );
    }

    #[test]
    fn test_parse_logger_source_req() {
        let path = "/foo";
        let path_tokens: Vec<&str> = path[1..].split_terminator('/').collect();
        let json = "{
                \"log_fifo\": \"tmp1\",
                \"metrics_fifo\": \"tmp2\",
                \"level\": \"Info\",
                \"show_level\": true,
                \"show_log_origin\": true
              }";
        let body: Chunk = Chunk::from(json);

        // GET
        match parse_logger_req(&path_tokens, &path, Method::Get, &body) {
            Ok(pr_dummy) => assert!(pr_dummy.eq(&ParsedRequest::Dummy)),
            _ => assert!(false),
        }

        // PUT
        let logger_body =
            serde_json::from_slice::<LoggerConfig>(&body).expect("deserialization failed");
        match parse_logger_req(&path_tokens, &path, Method::Put, &body) {
            Ok(pr) => {
                let (sender, receiver) = oneshot::channel();
                assert!(pr.eq(&ParsedRequest::Sync(
                    VmmAction::ConfigureLogger(logger_body, sender),
                    receiver,
                )));
            }
            _ => assert!(false),
        }

        // Error cases
        assert!(parse_logger_req(&path_tokens, &path, Method::Put, &Chunk::from("foo")).is_err());

        assert!(
            parse_logger_req(
                &"/foo/bar"[1..].split_terminator('/').collect(),
                &"/foo/bar",
                Method::Put,
                &Chunk::from("foo")
            ).is_err()
        );
    }

    #[test]
    fn test_parse_machine_config_req() {
        let path = "/foo";
        let path_tokens: Vec<&str> = path[1..].split_terminator('/').collect();
        let json = "{
                \"vcpu_count\": 42,
                \"mem_size_mib\": 1025,
                \"ht_enabled\": true,
                \"cpu_template\": \"T2\"
              }";
        let body: Chunk = Chunk::from(json);

        // GET
        assert!(parse_machine_config_req(&path_tokens, &path, Method::Get, &body).is_ok());

        assert!(
            parse_machine_config_req(
                &"/foo/bar"[1..].split_terminator('/').collect(),
                &"/foo/bar",
                Method::Get,
                &body
            ).is_err()
        );

        // PUT
        let vm_config = VmConfig {
            vcpu_count: Some(42),
            mem_size_mib: Some(1025),
            ht_enabled: Some(true),
            cpu_template: Some(CpuFeaturesTemplate::T2),
        };

        match vm_config.into_parsed_request(None, Method::Put) {
            Ok(parsed_req) => {
                match parse_machine_config_req(&path_tokens, &path, Method::Put, &body) {
                    Ok(other_parsed_req) => assert!(parsed_req.eq(&other_parsed_req)),
                    _ => assert!(false),
                }
            }
            _ => assert!(false),
        }

        // Error cases
        assert!(
            parse_machine_config_req(&path_tokens, &path, Method::Put, &Chunk::from("foo bar"))
                .is_err()
        );

        assert!(
            parse_machine_config_req(
                &path_tokens,
                &path,
                Method::Put,
                &Chunk::from("{\"foo\": \"bar\"}")
            ).is_err()
        );

        assert!(
            parse_machine_config_req(
                &"/foo/bar"[1..].split_terminator('/').collect(),
                &"/foo/bar",
                Method::Put,
                &Chunk::from("{\"foo\": \"bar\"")
            ).is_err()
        );

        assert!(
            parse_machine_config_req(&path_tokens, &path, Method::Put, &Chunk::from("{}")).is_err()
        );
    }

    #[test]
    fn test_parse_netif_req() {
        let path = "/foo/bar";
        let path_tokens: Vec<&str> = path[1..].split_terminator('/').collect();
        let id_from_path = Some(path_tokens[1]);
        let json = "{
                \"iface_id\": \"bar\",
                \"state\": \"Attached\",
                \"host_dev_name\": \"foo\",
                \"guest_mac\": \"12:34:56:78:9a:BC\"
              }";
        let body: Chunk = Chunk::from(json);

        // GET
        match parse_netif_req(
            &"/foo"[1..].split_terminator('/').collect(),
            &"/foo",
            Method::Get,
            &None,
            &body,
        ) {
            Ok(pr_dummy) => assert!(pr_dummy.eq(&ParsedRequest::Dummy)),
            _ => assert!(false),
        }

        match parse_netif_req(&path_tokens, &path, Method::Get, &id_from_path, &body) {
            Ok(pr_dummy) => assert!(pr_dummy.eq(&ParsedRequest::Dummy)),
            _ => assert!(false),
        }

        // PUT
        let netif = NetworkInterfaceBody {
            iface_id: String::from("bar"),
            state: DeviceState::Attached,
            host_dev_name: String::from("foo"),
            guest_mac: Some(MacAddr::parse_str("12:34:56:78:9a:BC").unwrap()),
            rx_rate_limiter: None,
            tx_rate_limiter: None,
            allow_mmds_requests: false,
        };

        match netif.into_parsed_request(Some(String::from("bar")), Method::Put) {
            Ok(pr) => match parse_netif_req(
                &"/foo/bar"[1..].split_terminator('/').collect(),
                &"/foo/bar",
                Method::Put,
                &Some("bar"),
                &body,
            ) {
                Ok(pr_netif) => assert!(pr.eq(&pr_netif)),
                _ => assert!(false),
            },
            _ => assert!(false),
        }

        // Error cases
        assert!(
            parse_netif_req(
                &"/foo/bar"[1..].split_terminator('/').collect(),
                &"/foo/bar",
                Method::Put,
                &Some("barr"),
                &body
            ).is_err()
        );

        assert!(
            parse_netif_req(
                &"/foo/bar"[1..].split_terminator('/').collect(),
                &"/foo/bar",
                Method::Put,
                &Some("bar"),
                &Chunk::from("foo bar")
            ).is_err()
        );

        assert!(
            parse_netif_req(
                &"/foo/bar"[1..].split_terminator('/').collect(),
                &"/foo/bar",
                Method::Put,
                &Some("bar"),
                &Chunk::from("{\"foo\": \"bar\"}")
            ).is_err()
        );

        assert!(
            parse_netif_req(
                &"/foo"[1..].split_terminator('/').collect(),
                &"/foo",
                Method::Put,
                &None,
                &body
            ).is_err()
        );
    }

    #[test]
    fn test_parse_mmds_request() {
        let path = "/mmds";
        let path_tokens: Vec<&str> = path[1..].split_terminator('/').collect();
        let empty_json = "{}";
        let body = Chunk::from(empty_json);

        // Test for GET request
        match parse_mmds_request(&path_tokens, path, Method::Get, &body) {
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
        match parse_mmds_request(&path_tokens, path, Method::Put, &body) {
            Ok(parsed_req) => assert!(parsed_req.eq(&ParsedRequest::PutMMDS(
                serde_json::from_slice(&body).unwrap()
            ))),
            Err(_) => assert!(false),
        };

        // Test for PATCH request
        let patch_json = "{\"user-data\": 15}";
        let body = Chunk::from(patch_json);
        match parse_mmds_request(&path_tokens, path, Method::Patch, &body) {
            Ok(parsed_req) => assert!(parsed_req.eq(&ParsedRequest::PatchMMDS(
                serde_json::from_slice(&body).unwrap()
            ))),
            Err(_) => assert!(false),
        };

        // Test for invalid json on PUT
        let invalid_json = "\"latest\": {}}";
        let body = Chunk::from(invalid_json);
        assert!(parse_mmds_request(&path_tokens, path, Method::Put, &body).is_err());

        // Test for invalid json on PATCH
        let invalid_json = "\"latest\": {}}";
        let body = Chunk::from(invalid_json);
        assert!(parse_mmds_request(&path_tokens, path, Method::Patch, &body).is_err());

        // Test for invalid path
        let path = "/mmds/something";
        let path_tokens: Vec<&str> = path[1..].split_terminator('/').collect();
        assert!(parse_mmds_request(&path_tokens, path, Method::Get, &body).is_err());
    }

    #[test]
    fn test_parse_request() {
        let body: Chunk = Chunk::from("{ \"foo\": \"bar\" }");

        assert!(parse_request(Method::Get, "foo/bar", &body).is_err());

        let all_methods = vec![
            Method::Put,
            Method::Options,
            Method::Post,
            Method::Delete,
            Method::Head,
            Method::Trace,
            Method::Connect,
            Method::Patch,
            Method::Extension(String::from("foobar")),
        ];

        for method in &all_methods {
            assert!(parse_request(method.clone(), "/foo", &body).is_err());
        }

        // Test empty request
        match parse_request(Method::Get, "/", &body) {
            Ok(pr) => assert!(pr.eq(&ParsedRequest::GetInstanceInfo)),
            _ => assert!(false),
        }
        for method in &all_methods {
            if *method != Method::Get {
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
            assert!(parse_request(Method::Get, path, &body).is_ok());
            for method in &all_methods {
                if *method != Method::Get && *method != Method::Put {
                    assert!(parse_request(method.clone(), path, &body).is_err());
                }
            }
        }
    }

    #[test]
    fn test_describe() {
        let body: String = String::from("{ \"foo\": \"bar\" }");
        let msj = describe(&Method::Get, &String::from("/foo/bar"), &body);
        assert_eq!(
            msj,
            "synchronous Get request \"/foo/bar\" with body \"{ \\\"foo\\\": \\\"bar\\\" }\""
        );
        let msj = describe(&Method::Put, &String::from("/foo/bar"), &body);
        assert_eq!(
            msj,
            "synchronous Put request \"/foo/bar\" with body \"{ \\\"foo\\\": \\\"bar\\\" }\""
        );
    }
}
