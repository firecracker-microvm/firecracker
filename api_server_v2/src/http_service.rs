use std::cell::RefCell;
use std::rc::Rc;
use std::result;
use std::str;

use hyper::{self, Chunk, Headers, Method, StatusCode};
use serde_json;

use request::{self, AsyncRequestBody, ParsedRequest};
use super::{ActionMap, ActionMapValue};

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
fn empty_response(status: StatusCode) -> hyper::Response {
    build_response_base::<String>(status, None, None)
}

// An HTTP response which also includes a body.
fn json_response<T: Into<hyper::Body>>(status: StatusCode, body: T) -> hyper::Response {
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

fn json_fault_message<T: AsRef<str>>(msg: T) -> String {
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

// It's convenient to turn errors into HTTP responses.
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
        "drives" => match v[1..].len() {
            0 if is_get => Ok(ParsedRequest::Dummy),

            1 if is_get => Ok(ParsedRequest::Dummy),

            1 if is_put => Ok(serde_json::from_slice::<request::DriveDescription>(body)
                .map_err(Error::SerdeJson)?
                .into_parsed_request(id_from_path.unwrap())
                .map_err(|s| Error::Generic(StatusCode::BadRequest, s))?),
            _ => Err(Error::InvalidPathMethod(path, method)),
        },
        _ => Err(Error::InvalidPathMethod(path, method)),
    }
}
