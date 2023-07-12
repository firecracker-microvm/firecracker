// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;

use hyper::{Method, StatusCode};
use logger::error;
use vmm::rpc_interface::VmmAction;

#[derive(Debug)]
pub(crate) enum RequestAction {
    Sync(Box<VmmAction>),
    ShutdownInternal, // !!! not an API, used by shutdown to thread::join the API thread
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
}

#[derive(Debug)]
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

    /// Helper function to avoid boiler-plate code.
    pub(crate) fn new_sync(vmm_action: VmmAction) -> ParsedRequest {
        ParsedRequest::new(RequestAction::Sync(Box::new(vmm_action)))
    }
}

/// Generates a `GenericError` for each request method.
pub(crate) fn method_to_error(method: Method) -> Result<ParsedRequest, Error> {
    match method {
        Method::GET => Err(Error::Generic(
            StatusCode::BAD_REQUEST,
            "GET request cannot have a body.".to_string(),
        )),
        Method::PUT => Err(Error::Generic(
            StatusCode::BAD_REQUEST,
            "Empty PUT request.".to_string(),
        )),
        Method::PATCH => Err(Error::Generic(
            StatusCode::BAD_REQUEST,
            "Empty PATCH request.".to_string(),
        )),
        _ => unreachable!(),
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
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
    #[error("Invalid request method and/or path: {1} {0}.")]
    InvalidPathMethod(String, Method),
    // An error occurred when deserializing the json body of a request.
    #[error("An error occurred when deserializing the json body of a request: {0}.")]
    SerdeJson(#[from] serde_json::Error),
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
pub mod tests {
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
}
