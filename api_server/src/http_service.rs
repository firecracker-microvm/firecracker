use std::cell::RefCell;
use std::rc::Rc;
use std::result;
use std::str;
use std::sync::mpsc;
use std::sync::{Arc, RwLock};

use futures::future::{self, Either};
use futures::{Future, Stream};

use hyper::{self, Chunk, Headers, Method, StatusCode};
use serde_json;
use tokio_core::reactor::Handle;

use super::{ActionMap, ActionMapValue};
use data_model::vm::MachineConfiguration;
use logger::{Metric, METRICS};
use request::instance_info::InstanceInfo;
use request::{self, ApiRequest, AsyncOutcome, AsyncRequestBody, IntoParsedRequest, ParsedRequest};
use sys_util::EventFd;

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
    // PUT for an action id that already exists
    ActionExists,
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
            Error::ActionExists => json_response(
                StatusCode::Conflict,
                json_fault_message("An action with the same id already exists."),
            ),
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
    id_from_path: &Option<&str>,
    body: &Chunk,
    action_map: &mut Rc<RefCell<ActionMap>>,
) -> Result<'a, ParsedRequest> {
    match path_tokens[1..].len() {
        0 if method == Method::Get => Ok(ParsedRequest::GetActions),

        1 if method == Method::Get => {
            METRICS.get_api_requests.actions_count.inc();
            let unwrapped_id = id_from_path.ok_or_else(|| {
                METRICS.get_api_requests.actions_fails.inc();
                (Error::InvalidID)
            })?;
            Ok(ParsedRequest::GetAction(String::from(unwrapped_id)))
        }

        1 if method == Method::Put => {
            let unwrapped_id = id_from_path.ok_or_else(|| {
                METRICS.put_api_requests.actions_fails.inc();
                Error::InvalidID
            })?;
            METRICS.put_api_requests.actions_count.inc();
            let async_body: AsyncRequestBody =
                serde_json::from_slice(body.as_ref()).map_err(|e| {
                    METRICS.put_api_requests.actions_fails.inc();
                    Error::SerdeJson(e)
                })?;
            let parsed_req = async_body.to_parsed_request(unwrapped_id).map_err(|msg| {
                METRICS.put_api_requests.actions_fails.inc();
                Error::Generic(StatusCode::BadRequest, msg)
            })?;
            action_map
                .borrow_mut()
                .insert_unique(
                    String::from(unwrapped_id),
                    ActionMapValue::Pending(async_body),
                )
                .map_err(|_| {
                    METRICS.put_api_requests.actions_fails.inc();
                    Error::ActionExists
                })?;
            Ok(parsed_req)
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
            Ok(serde_json::from_slice::<request::BootSourceBody>(body)
                .map_err(|e| {
                    METRICS.put_api_requests.boot_source_fails.inc();
                    Error::SerdeJson(e)
                })?
                .into_parsed_request()
                .map_err(|s| {
                    METRICS.put_api_requests.boot_source_fails.inc();
                    Error::Generic(StatusCode::BadRequest, s)
                })?)
        }
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
            METRICS.put_api_requests.drive_count.inc();

            Ok(serde_json::from_slice::<request::DriveDescription>(body)
                .map_err(|e| {
                    METRICS.put_api_requests.drive_fails.inc();
                    Error::SerdeJson(e)
                })?
                .into_parsed_request(id_from_path.unwrap())
                .map_err(|s| {
                    METRICS.put_api_requests.drive_fails.inc();
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
            Ok(
                serde_json::from_slice::<request::APILoggerDescription>(body)
                    .map_err(|e| {
                        METRICS.put_api_requests.logger_fails.inc();
                        Error::SerdeJson(e)
                    })?
                    .into_parsed_request()
                    .map_err(|s| {
                        METRICS.put_api_requests.logger_fails.inc();
                        Error::Generic(StatusCode::BadRequest, s)
                    })?,
            )
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
            let empty_machine_config = MachineConfiguration {
                vcpu_count: None,
                mem_size_mib: None,
                ht_enabled: None,
                cpu_template: None,
            };
            Ok(empty_machine_config
                .into_parsed_request(method)
                .map_err(|s| {
                    METRICS.get_api_requests.machine_cfg_fails.inc();
                    Error::Generic(StatusCode::BadRequest, s)
                })?)
        }

        0 if method == Method::Put => {
            METRICS.put_api_requests.machine_cfg_count.inc();
            Ok(serde_json::from_slice::<MachineConfiguration>(body)
                .map_err(|e| {
                    METRICS.put_api_requests.machine_cfg_fails.inc();
                    Error::SerdeJson(e)
                })?
                .into_parsed_request(method)
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

            Ok(
                serde_json::from_slice::<request::NetworkInterfaceBody>(body)
                    .map_err(|e| {
                        METRICS.put_api_requests.network_fails.inc();
                        Error::SerdeJson(e)
                    })?
                    .into_parsed_request(unwrapped_id)
                    .map_err(|s| {
                        METRICS.put_api_requests.network_fails.inc();
                        Error::Generic(StatusCode::BadRequest, s)
                    })?,
            )
        }
        _ => Err(Error::InvalidPathMethod(path, method)),
    }
}

// This turns an incoming HTTP request into a ParsedRequest, which is an item containing both the
// message to be passed to the VMM, and associated entities, such as channels which allow the
// reception of the outcome back from the VMM.
// TODO: finish implementing/parsing all possible requests.
fn parse_request<'a>(
    action_map: &mut Rc<RefCell<ActionMap>>,
    method: Method,
    path: &'a str,
    body: &Chunk,
) -> Result<'a, ParsedRequest> {
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
        "actions" => parse_actions_req(&path_tokens, path, method, &id_from_path, body, action_map),
        "boot-source" => parse_boot_source_req(&path_tokens, path, method, body),
        "drives" => parse_drives_req(&path_tokens, path, method, &id_from_path, body),
        "logger" => parse_logger_req(&path_tokens, path, method, body),
        "machine-config" => parse_machine_config_req(&path_tokens, path, method, body),
        "network-interfaces" => parse_netif_req(&path_tokens, path, method, &id_from_path, body),
        _ => Err(Error::InvalidPathMethod(path, method)),
    }
}

// A helper function which is always used when a message is placed into the communication channel
// with the VMM (so we don't forget to write to the EventFd).
fn send_to_vmm(
    req: ApiRequest,
    sender: &mpsc::Sender<Box<ApiRequest>>,
    send_event: &EventFd,
) -> result::Result<(), ()> {
    sender.send(Box::new(req)).map_err(|_| ())?;
    send_event.write(1).map_err(|_| ())
}

// In hyper, a struct that implements the Service trait is created to handle each incoming
// request. This is the one for our ApiServer.
pub struct ApiServerHttpService {
    // VMM instance info directly accessible from this API thread.
    vmm_shared_info: Arc<RwLock<InstanceInfo>>,
    // This allows sending messages to the VMM thread. It makes sense to use a Rc for the sender
    // (instead of cloning) because everything happens on a single thread, so there's no risk of
    // having races (if that was even a problem to begin with).
    api_request_sender: Rc<mpsc::Sender<Box<ApiRequest>>>,
    // We write to this EventFd to let the VMM know about new messages.
    vmm_send_event: Rc<EventFd>,
    // Keeps records on async actions.
    action_map: Rc<RefCell<ActionMap>>,
    // A tokio core handle, used to spawn futures.
    handle: Rc<Handle>,
}

impl ApiServerHttpService {
    pub fn new(
        vmm_shared_info: Arc<RwLock<InstanceInfo>>,
        api_request_sender: Rc<mpsc::Sender<Box<ApiRequest>>>,
        vmm_send_event: Rc<EventFd>,
        action_map: Rc<RefCell<ActionMap>>,
        handle: Rc<Handle>,
    ) -> Self {
        ApiServerHttpService {
            vmm_shared_info,
            api_request_sender,
            vmm_send_event,
            action_map,
            handle,
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
        let mut action_map = self.action_map.clone();
        let method = req.method().clone();
        let method_copy = req.method().clone();
        let path = String::from(req.path());
        let shared_info_lock = self.vmm_shared_info.clone();
        let api_request_sender = self.api_request_sender.clone();
        let handle = self.handle.clone();
        let vmm_send_event = self.vmm_send_event.clone();

        // for nice looking match arms
        use request::ParsedRequest::*;

        // The request body is itself a future (a stream of Chunks to be more precise),
        // so we have to define a future that waits for all the pieces first (via concat2),
        // and then does something with the newly available body (via and_then).
        Box::new(req.body().concat2().and_then(move |b| {
            // When this will be executed, the body is available. We start by parsing the request.
            match parse_request(&mut action_map, method, path.as_ref(), &b) {
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
                    GetActions => {
                        // TODO: return a proper response, both here and for other requests which
                        // are in a similar condition right now.
                        // not yet documented; should I add rate metric?
                        Either::A(future::ok(empty_response(StatusCode::Ok)))
                    }
                    GetAction(id) => {
                        METRICS.get_api_requests.action_info_count.inc();
                        match action_map.borrow().get(&id) {
                            Some(value) => match *value {
                                ActionMapValue::Pending(_) => Either::A(future::ok(json_response(
                                    StatusCode::Conflict,
                                    json_fault_message("Action is still pending."),
                                ))),
                                ActionMapValue::JsonResponse(ref status, ref body) => Either::A(
                                    future::ok(json_response(status.clone(), body.clone())),
                                ),
                            },
                            None => Either::A(future::ok(json_response(
                                StatusCode::NotFound,
                                json_fault_message("Action not found."),
                            ))),
                        }
                    }
                    Async(id, async_req, outcome_receiver) => {
                        if send_to_vmm(
                            ApiRequest::Async(async_req),
                            &api_request_sender,
                            &vmm_send_event,
                        ).is_err()
                        {
                            METRICS.api_server.async_vmm_send_timeout_count.inc();
                            // hyper::Error::Cancel would have been more appropriate, but it's no
                            // longer available for some reason.
                            return Either::A(future::err(hyper::Error::Timeout));
                        }

                        let b_str = String::from_utf8_lossy(&b.to_vec()).to_string();
                        let path_dbg = path.clone();
                        trace!("Sent {}", describe(false, &method_copy, &path, &b_str));

                        // We have to explicitly spawn a future that will handle the outcome of the
                        // async request.
                        handle.spawn(
                            outcome_receiver
                                .map(move |outcome| {
                                    // Let's see if the action is still in the map (it might have
                                    // been evicted by newer actions, although that's extremely
                                    // unlikely under normal circumstances).
                                    let (response_status, json_body) = match action_map
                                        .borrow_mut()
                                        .get_mut(id.as_str())
                                    {
                                        // Pending is the only possible status before the outcome is
                                        // resolved, so we know all other match arms are equivalent.
                                        Some(&mut ActionMapValue::Pending(ref mut async_body)) => {
                                            match outcome {
                                                AsyncOutcome::Ok(timestamp) => {
                                                    async_body.set_timestamp(timestamp);
                                                    trace!(
                                                        "Received Success on {}",
                                                        describe(
                                                            false,
                                                            &method_copy,
                                                            &path_dbg,
                                                            &b_str
                                                        )
                                                    );
                                                    // We use unwrap because the serialize operation
                                                    // should not fail in this case.
                                                    (
                                                        StatusCode::Ok,
                                                        serde_json::to_string(&async_body).unwrap(),
                                                    )
                                                }
                                                AsyncOutcome::Error(msg) => {
                                                    trace!(
                                                        "Received Error on {}",
                                                        describe(
                                                            false,
                                                            &method_copy,
                                                            &path_dbg,
                                                            &b_str
                                                        )
                                                    );
                                                    METRICS.api_server.async_outcome_fails.inc();
                                                    (
                                                        StatusCode::BadRequest,
                                                        json_fault_message(msg),
                                                    )
                                                }
                                            }
                                        }
                                        _ => {
                                            METRICS.api_server.async_missed_actions_count.inc();
                                            return;
                                        }
                                    };
                                    // Replace the old value with the already built response.
                                    action_map.borrow_mut().insert(
                                        id,
                                        ActionMapValue::JsonResponse(response_status, json_body),
                                    );
                                })
                                .map_err(|_| {
                                    METRICS.api_server.async_outcome_fails.inc();
                                }),
                        );

                        // This is returned immediately; the previous handle.spawn() just registers
                        // the provided closure to run when the outcome is complete.
                        Either::A(future::ok(empty_response(StatusCode::Created)))
                    }
                    Sync(sync_req, outcome_receiver) => {
                        if send_to_vmm(
                            ApiRequest::Sync(sync_req),
                            &api_request_sender,
                            &vmm_send_event,
                        ).is_err()
                        {
                            METRICS.api_server.sync_vmm_send_timeout_count.inc();
                            return Either::A(future::err(hyper::Error::Timeout));
                        }

                        // metric-logging related variables for being able to log response details
                        let b_str = String::from_utf8_lossy(&b.to_vec()).to_string();
                        let b_str_err = String::from_utf8_lossy(&b.to_vec()).to_string();
                        let path_copy = path.clone();
                        let path_copy_err = path_copy.clone();
                        let method_copy_err = method_copy.clone();

                        trace!("Sent {}", describe(true, &method_copy, &path, &b_str));

                        // Sync requests don't receive a response until the outcome is returned.
                        // Once more, this just registers a closure to run when the result is
                        // available.
                        Either::B(
                            outcome_receiver
                                .map(move |x| {
                                    trace!(
                                        "Received Success on {}",
                                        describe(true, &method_copy, &path_copy, &b_str)
                                    );
                                    x.generate_response()
                                })
                                .map_err(move |_| {
                                    trace!(
                                        "Received Error on {}",
                                        describe(
                                            true,
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
/// `sync` refers to whether or not the function is synchronous or not (false)
/// `method` is whether PUT or GET
/// `path` and `body` represent path of the API request and body, respectively
fn describe(sync: bool, method: &Method, path: &String, body: &String) -> String {
    match sync {
        false => format!(
            "asynchronous {:?} request {:?} with body {:?}",
            method, path, body
        ),
        true => format!(
            "synchronous {:?} request {:?} with body {:?}",
            method, path, body
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_model::vm::CpuFeaturesTemplate;
    use fc_util::LriHashMap;
    use futures::sync::oneshot;
    use hyper::header::{ContentType, Headers};
    use hyper::Body;
    use net_util::MacAddr;
    use request::async::AsyncRequest;
    use request::sync::{DeviceState, DriveDescription, DrivePermissions, NetworkInterfaceBody,
                        SyncRequest};

    fn body_to_string(body: hyper::Body) -> String {
        let ret = body.fold(Vec::new(), |mut acc, chunk| {
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
        let mut response: hyper::Response = Error::ActionExists.into();
        assert_eq!(response.status(), StatusCode::Conflict);
        assert_eq!(
            response.headers().get::<ContentType>(),
            Some(&ContentType::json())
        );

        let json_err_key = "fault_message";
        let json_err_val = "This is an error message";
        let err_message = format!("{{\n  \"{}\": \"{}\"\n}}", &json_err_key, &json_err_val);
        let message = String::from("This is an error message");
        response = Error::Generic(StatusCode::ServiceUnavailable, message).into();
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
                println!("{:?}", &e);
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
        let mut action_map: Rc<RefCell<ActionMap>> =
            Rc::new(RefCell::new(LriHashMap::<String, ActionMapValue>::new(1)));
        let path = "/foo/bar";
        let path_tokens: Vec<&str> = path[1..].split_terminator('/').collect();
        let id_from_path = Some(path_tokens[1]);
        let json = "{
                \"action_id\": \"bar\",
                \"action_type\": \"InstanceStart\",
                \"instance_device_detach_action\": {\
                    \"device_type\": \"Drive\",
                    \"device_resource_id\": \"dummy\",
                    \"force\": true},
                \"timestamp\": 1522850095
              }";
        let body: Chunk = Chunk::from(json);

        // GET GetActions
        match parse_actions_req(
            &"/foo"[1..].split_terminator('/').collect(),
            &"/foo",
            Method::Get,
            &id_from_path,
            &body,
            &mut action_map,
        ) {
            Ok(pr) => assert!(pr.eq(&ParsedRequest::GetActions)),
            _ => assert!(false),
        }

        // GET GetAction
        match parse_actions_req(
            &path_tokens,
            &path,
            Method::Get,
            &id_from_path,
            &body,
            &mut action_map,
        ) {
            Ok(pr) => assert!(pr.eq(&ParsedRequest::GetAction(String::from("bar")))),
            _ => assert!(false),
        }

        // PUT
        match parse_actions_req(
            &path_tokens,
            &path,
            Method::Put,
            &id_from_path,
            &body,
            &mut action_map,
        ) {
            Ok(pr) => {
                let (sender, receiver) = oneshot::channel();
                assert!(pr.eq(&ParsedRequest::Async(
                    String::from("bar"),
                    AsyncRequest::StartInstance(sender),
                    receiver
                )));

                match action_map.borrow_mut().get_mut("bar") {
                    Some(&mut ActionMapValue::Pending(ref body)) => {
                        // The components of AsyncRequestBody are private, so an object can't be
                        // instantiated here. Reverting to comparison by string formatting.
                        assert_eq!(
                            format!("{:?}", body),
                            "AsyncRequestBody { \
                             action_id: \"bar\", \
                             action_type: InstanceStart, \
                             instance_device_detach_action: Some(\
                             InstanceDeviceDetachAction { \
                             device_type: Drive, \
                             device_resource_id: \"dummy\", \
                             force: true }), \
                             timestamp: Some(1522850095) }"
                        );
                    }
                    _ => assert!(false),
                };
            }
            _ => assert!(false),
        }

        // Error cases
        assert!(
            parse_actions_req(
                &path_tokens,
                &path,
                Method::Put,
                &id_from_path,
                &Chunk::from("foo"),
                &mut action_map
            ).is_err()
        );

        assert!(
            parse_actions_req(
                &"/foo/bar/baz"[1..].split_terminator('/').collect(),
                &"/foo/bar/baz",
                Method::Put,
                &id_from_path,
                &Chunk::from("foo"),
                &mut action_map
            ).is_err()
        );
    }

    #[test]
    fn test_parse_boot_source_req() {
        let path = "/foo";
        let path_tokens: Vec<&str> = path[1..].split_terminator('/').collect();
        let json = "{
                \"boot_source_id\": \"bar\",
                \"source_type\": \"LocalImage\",
                \"local_image\": {\"kernel_image_path\": \"/foo/bar\"},
                \"boot_args\": \"baz\"
              }";
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
        let res_bsb = serde_json::from_slice::<request::BootSourceBody>(&body);
        match res_bsb {
            Ok(boot_source_body) => {
                match parse_boot_source_req(&path_tokens, &path, Method::Put, &body) {
                    Ok(pr) => {
                        let (sender, receiver) = oneshot::channel();
                        assert!(pr.eq(&ParsedRequest::Sync(
                            SyncRequest::PutBootSource(boot_source_body, sender),
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
                \"state\": \"Attached\",
                \"is_root_device\": true,
                \"permissions\": \"ro\"
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
        let drive_desc = DriveDescription {
            drive_id: String::from("bar"),
            path_on_host: String::from("/foo/bar"),
            state: DeviceState::Attached,
            is_root_device: true,
            permissions: DrivePermissions::ro,
            rate_limiter: None,
        };

        match drive_desc.into_parsed_request("bar") {
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
        let mcb = MachineConfiguration {
            vcpu_count: Some(42),
            mem_size_mib: Some(1025),
            ht_enabled: Some(true),
            cpu_template: Some(CpuFeaturesTemplate::T2),
        };

        match mcb.into_parsed_request(Method::Put) {
            Ok(pr) => match parse_machine_config_req(&path_tokens, &path, Method::Put, &body) {
                Ok(pr_mcb) => assert!(pr.eq(&pr_mcb)),
                _ => assert!(false),
            },
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
        };

        match netif.into_parsed_request("bar") {
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
    fn test_parse_request() {
        let mut action_map: Rc<RefCell<ActionMap>> =
            Rc::new(RefCell::new(LriHashMap::<String, ActionMapValue>::new(1)));
        let body: Chunk = Chunk::from("{ \"foo\": \"bar\" }");

        assert!(parse_request(&mut action_map, Method::Get, "foo/bar", &body).is_err());

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
            assert!(parse_request(&mut action_map, method.clone(), "/foo", &body).is_err());
        }

        // Test empty request
        match parse_request(&mut action_map, Method::Get, "/", &body) {
            Ok(pr) => assert!(pr.eq(&ParsedRequest::GetInstanceInfo)),
            _ => assert!(false),
        }
        for method in &all_methods {
            if *method != Method::Get {
                assert!(parse_request(&mut action_map, method.clone(), "/", &body).is_err());
            }
        }

        // Test requests with valid id_from_path
        assert!(parse_request(&mut action_map, Method::Get, "/actions/foobar", &body).is_ok());
        for method in &all_methods {
            if *method != Method::Get {
                assert!(parse_request(&mut action_map, method.clone(), "/foo/bar", &body).is_err());
            }
        }

        // Test all valid requests
        // Each request type is unit tested separately
        for path in vec![
            "/actions",
            "/boot-source",
            "/drives",
            "/machine-config",
            "/network-interfaces",
        ] {
            assert!(parse_request(&mut action_map, Method::Get, path, &body).is_ok());
            for method in &all_methods {
                if *method != Method::Get && *method != Method::Put {
                    assert!(parse_request(&mut action_map, method.clone(), path, &body).is_err());
                }
            }
        }
    }

    #[test]
    fn test_describe() {
        let body: String = String::from("{ \"foo\": \"bar\" }");
        let msj = describe(true, &Method::Get, &String::from("/foo/bar"), &body);
        assert_eq!(
            msj,
            "synchronous Get request \"/foo/bar\" with body \"{ \\\"foo\\\": \\\"bar\\\" }\""
        );
        let msj = describe(true, &Method::Put, &String::from("/foo/bar"), &body);
        assert_eq!(
            msj,
            "synchronous Put request \"/foo/bar\" with body \"{ \\\"foo\\\": \\\"bar\\\" }\""
        );
        let msj = describe(false, &Method::Get, &String::from("/foo/bar"), &body);
        assert_eq!(
            msj,
            "asynchronous Get request \"/foo/bar\" with body \"{ \\\"foo\\\": \\\"bar\\\" }\""
        );
        let msj = describe(false, &Method::Put, &String::from("/foo/bar"), &body);
        assert_eq!(
            msj,
            "asynchronous Put request \"/foo/bar\" with body \"{ \\\"foo\\\": \\\"bar\\\" }\""
        );
    }
}
