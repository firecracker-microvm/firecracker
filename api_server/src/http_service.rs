use std::cell::RefCell;
use std::rc::Rc;
use std::result;
use std::str;
use std::sync::mpsc;

use futures::{Future, Stream};
use futures::future::{self, Either};

use hyper::{self, Chunk, Headers, Method, StatusCode};
use serde_json;
use tokio_core::reactor::Handle;

use request::{self, ApiRequest, AsyncOutcome, AsyncRequestBody, ParsedRequest};
use super::{ActionMap, ActionMapValue};
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
    // The HTTP method & request path combination is not valid.
    InvalidPathMethod(&'a str, Method),
    // An error occured when deserializing the json body of a request.
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
    if cfg!(debug_assertions) {
        println!(
            "{}",
            format!(
                "got req: {} {}\n{}",
                method,
                path,
                str::from_utf8(body.as_ref()).unwrap()
            )
        );
    }

    if !path.starts_with('/') {
        return Err(Error::InvalidPathMethod(path, method));
    }

    // We use path[1..] here to skip the initial '/'.
    let v: Vec<&str> = path[1..].split_terminator('/').collect();

    // We're defining these to have nicer looking matches below.
    let is_get = method == Method::Get;
    let is_put = method == Method::Put;
    let _is_delete = method == Method::Delete;

    if v.len() == 0 {
        // todo: On GET, this should return the "GET /" defined in the API,
        // otherwise an error.
        return Ok(ParsedRequest::Dummy);
    }

    // The unwraps on id_from_path in later code should not panic because they are only
    // called when v.len() > 1.
    let id_from_path = if v.len() > 1 {
        Some(checked_id(v[1])?)
    } else {
        None
    };

    match v[0] {
        "actions" => match v[1..].len() {
            0 if is_get => Ok(ParsedRequest::GetActions),

            1 if is_get => Ok(ParsedRequest::GetAction(String::from(
                id_from_path.unwrap(),
            ))),

            1 if is_put => {
                let async_body: AsyncRequestBody =
                    serde_json::from_slice(body.as_ref()).map_err(Error::SerdeJson)?;
                let parsed_req = async_body
                    .to_parsed_request(id_from_path.unwrap())
                    .map_err(|msg| Error::Generic(StatusCode::BadRequest, msg))?;
                action_map
                    .borrow_mut()
                    .insert_unique(
                        String::from(id_from_path.unwrap()),
                        ActionMapValue::Pending(async_body),
                    )
                    .map_err(|_| Error::ActionExists)?;
                Ok(parsed_req)
            }
            _ => Err(Error::InvalidPathMethod(path, method)),
        },
        "boot-source" => match v[1..].len() {
            0 if is_get => Ok(ParsedRequest::Dummy),

            0 if is_put => Ok(serde_json::from_slice::<request::BootSourceBody>(body)
                .map_err(Error::SerdeJson)?
                .into_parsed_request()
                .map_err(|s| Error::Generic(StatusCode::BadRequest, s))?),
            _ => Err(Error::InvalidPathMethod(path, method)),
        },
        "drives" => match v[1..].len() {
            0 if is_get => Ok(ParsedRequest::Dummy),

            1 if is_get => Ok(ParsedRequest::Dummy),

            1 if is_put => Ok(serde_json::from_slice::<request::DriveDescription>(body)
                .map_err(Error::SerdeJson)?
                .into_parsed_request(id_from_path.unwrap())
                .map_err(|s| Error::Generic(StatusCode::BadRequest, s))?),
            _ => Err(Error::InvalidPathMethod(path, method)),
        },
        "machine-config" => match v[1..].len() {
            0 if is_get => Ok(ParsedRequest::Dummy),

            0 if is_put => Ok(
                serde_json::from_slice::<request::MachineConfigurationBody>(body)
                    .map_err(Error::SerdeJson)?
                    .into_parsed_request()
                    .map_err(|s| Error::Generic(StatusCode::BadRequest, s))?,
            ),
            _ => Err(Error::InvalidPathMethod(path, method)),
        },
        "network-interfaces" => match v[1..].len() {
            0 if is_get => Ok(ParsedRequest::Dummy),

            1 if is_get => Ok(ParsedRequest::Dummy),

            1 if is_put => Ok(
                serde_json::from_slice::<request::NetworkInterfaceBody>(body)
                    .map_err(Error::SerdeJson)?
                    .into_parsed_request(id_from_path.unwrap())
                    .map_err(|s| Error::Generic(StatusCode::BadRequest, s))?,
            ),
            _ => Err(Error::InvalidPathMethod(path, method)),
        },
        "vsocks" => match v[1..].len() {
            0 if is_get => Ok(ParsedRequest::Dummy),

            1 if is_get => Ok(ParsedRequest::Dummy),

            1 if is_put => Ok(serde_json::from_slice::<request::VsockJsonBody>(body)
                .map_err(Error::SerdeJson)?
                .into_parsed_request(id_from_path.unwrap())
                .map_err(|s| Error::Generic(StatusCode::BadRequest, s))?),

            _ => Err(Error::InvalidPathMethod(path, method)),
        },
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
        api_request_sender: Rc<mpsc::Sender<Box<ApiRequest>>>,
        vmm_send_event: Rc<EventFd>,
        action_map: Rc<RefCell<ActionMap>>,
        handle: Rc<Handle>,
    ) -> Self {
        ApiServerHttpService {
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
        let path = String::from(req.path());
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
                    GetActions => {
                        // TODO: return a proper response, both here and for other requests which
                        // are in a similar condition right now.
                        Either::A(future::ok(empty_response(StatusCode::Ok)))
                    }
                    GetAction(_id) => {
                        // todo: what should we do when an action id is not found vs. not processed
                        // by the vmm yet?
                        Either::A(future::ok(empty_response(StatusCode::Ok)))
                    }
                    Async(id, async_req, outcome_receiver) => {
                        if send_to_vmm(
                            ApiRequest::Async(async_req),
                            &api_request_sender,
                            &vmm_send_event,
                        ).is_err()
                        {
                            // hyper::Error::Cancel would have been more appropriate, but it's no
                            // longer available for some reason.
                            return Either::A(future::err(hyper::Error::Timeout));
                        }

                        // We have to explicitly spawn a future that will handle the outcome of the
                        // async request.
                        handle.spawn(
                            outcome_receiver
                                .map(move |outcome| {
                                    // Let's see if the action is still in the map (it might have
                                    // been evicted by newer actions, although that's extremely
                                    // unlikely under in normal circumstances).
                                    let hyper_response = match action_map
                                        .borrow_mut()
                                        .get_mut(id.as_str())
                                    {
                                        // Pending is the only possible status before the outcome is
                                        // resolved, so we know all other match arms are equivalent.
                                        Some(&mut ActionMapValue::Pending(ref mut async_body)) => {
                                            match outcome {
                                                AsyncOutcome::Ok(timestamp) => {
                                                    async_body.set_timestamp(timestamp);
                                                    // We use unwrap because the serialize operation
                                                    // should not fail in this case.
                                                    json_response(
                                                        StatusCode::Ok,
                                                        serde_json::to_string(&async_body).unwrap(),
                                                    )
                                                }
                                                AsyncOutcome::Error(msg) => json_response(
                                                    StatusCode::BadRequest,
                                                    json_fault_message(msg),
                                                ),
                                            }
                                        }
                                        _ => return,
                                    };
                                    // Replace the old value with the already built response.
                                    action_map
                                        .borrow_mut()
                                        .insert(id, ActionMapValue::Response(hyper_response));
                                })
                                .map_err(|_| ()),
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
                            return Either::A(future::err(hyper::Error::Timeout));
                        }

                        // Sync requests don't receive a response until the outcome is returned.
                        // Once more, this just registers a closure to run when the result is
                        // available.
                        Either::B(
                            outcome_receiver
                                .map(|x| x.generate_response())
                                .map_err(|_| hyper::Error::Timeout),
                        )
                    }
                },
                Err(e) => Either::A(future::ok(e.into())),
            }
        }))
    }
}
