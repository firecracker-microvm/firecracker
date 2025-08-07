// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod memory;

use micro_http::{Body, Method};

use crate::api_server::parsed_request::{ParsedRequest, RequestError};
use crate::api_server::request::hotplug::memory::parse_put_memory_hotplug;

pub(crate) fn parse_hotplug(
    method: Method,
    token: Option<&str>,
    body: Option<&Body>,
) -> Result<ParsedRequest, RequestError> {
    let token =
        token.ok_or_else(|| RequestError::InvalidPathMethod("hotplug".to_string(), method))?;
    match (method, token, body) {
        (Method::Put, "memory", Some(body)) => parse_put_memory_hotplug(body),
        (method, unknown_uri, _) => Err(RequestError::InvalidPathMethod(
            unknown_uri.to_string(),
            method,
        )),
    }
}
