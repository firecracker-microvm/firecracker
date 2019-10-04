// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

use micro_http::{Body, Method, Request, Response, StatusCode, Version};
use request::instance_info::parse_get_instance_info;
use request::logger::parse_put_logger;
use request::mmds::{parse_get_mmds, parse_patch_mmds, parse_put_mmds};
use {ApiServer, VmmAction, VmmData};

#[allow(clippy::large_enum_variant)]
pub enum ParsedRequest {
    GetInstanceInfo,
    GetMMDS,
    PatchMMDS(Value),
    PutMMDS(Value),
    Sync(VmmAction),
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

        match (request.method(), path_tokens[0], request.body.as_ref()) {
            (Method::Get, "", None) => parse_get_instance_info(),
            (Method::Get, "mmds", None) => parse_get_mmds(),
            (Method::Put, "logger", Some(body)) => parse_put_logger(body),
            (Method::Put, "mmds", Some(body)) => parse_put_mmds(body),
            (Method::Patch, "mmds", Some(body)) => parse_patch_mmds(body),
            (method, unknown_uri, _) => {
                Err(Error::InvalidPathMethod(unknown_uri.to_string(), method))
            }
        }
    }

    pub fn convert_to_response(
        request_outcome: std::result::Result<VmmData, vmm::VmmActionError>,
    ) -> Response {
        match request_outcome {
            Ok(vmm_data) => match vmm_data {
                VmmData::Empty => {
                    info!("The request was executed successfully. Status code: 204 No Content.");
                    Response::new(Version::Http11, StatusCode::NoContent)
                }
                VmmData::MachineConfiguration(vm_config) => {
                    // Will come in later commit.
                    unimplemented!();
                    Response::new(Version::Http11, StatusCode::OK);
                }
            },
            Err(vmm_action_error) => {
                error!(
                    "Received Error. Status code: 400 Bad Request. Message: {}",
                    vmm_action_error
                );
                let mut response = Response::new(Version::Http11, StatusCode::BadRequest);
                response.set_body(Body::new(vmm_action_error.to_string()));
                response
            }
        }
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
///
fn describe(method: Method, path: &str, body: Option<&Body>) -> String {
    match (path, body) {
        ("/mmds", Some(_)) | (_, None) => format!("synchronous {:?} request on {:?}", method, path),
        (_, Some(value)) => format!(
            "synchronous {:?} request on {:?} with body {:?}",
            method,
            path,
            std::str::from_utf8(value.body.as_slice())
                .unwrap_or("inconvertible to UTF-8")
                .to_string()
        ),
    }
}

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

// It's convenient to turn errors into HTTP responses directly.
impl Into<Response> for Error {
    fn into(self) -> Response {
        match self {
            Error::Generic(status, msg) => {
                ApiServer::json_response(status, ApiServer::json_fault_message(msg))
            }
            Error::EmptyID => ApiServer::json_response(
                StatusCode::BadRequest,
                ApiServer::json_fault_message("The ID cannot be empty."),
            ),
            Error::InvalidID => ApiServer::json_response(
                StatusCode::BadRequest,
                ApiServer::json_fault_message(
                    "API Resource IDs can only contain alphanumeric characters and underscores.",
                ),
            ),
            Error::InvalidPathMethod(path, method) => ApiServer::json_response(
                StatusCode::BadRequest,
                ApiServer::json_fault_message(format!(
                    "Invalid request method and/or path: {} {}",
                    std::str::from_utf8(method.raw()).unwrap(),
                    path
                )),
            ),
            Error::SerdeJson(e) => ApiServer::json_response(
                StatusCode::BadRequest,
                ApiServer::json_fault_message(e.to_string()),
            ),
        }
    }
}
