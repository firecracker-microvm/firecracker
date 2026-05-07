// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::enclave::EnclaveConfig;

use super::super::parsed_request::{ParsedRequest, RequestError};
use super::Body;

pub(crate) fn parse_put_enclave<'a>(
    body: &Body,
    mut path_tokens: impl Iterator<Item = &'a str>,
) -> Result<ParsedRequest, RequestError> {
    if path_tokens.next().is_some() {
        return Err(RequestError::Generic(
            micro_http::StatusCode::BadRequest,
            "Enclave endpoint does not support sub-paths.".into(),
        ));
    }
    let config = serde_json::from_slice::<EnclaveConfig>(body.raw())?;
    Ok(ParsedRequest::new_sync(VmmAction::SetEnclaveConfig(config)))
}

pub(crate) fn parse_get_enclave<'a>(
    mut path_tokens: impl Iterator<Item = &'a str>,
) -> Result<ParsedRequest, RequestError> {
    if path_tokens.next().is_some() {
        return Err(RequestError::Generic(
            micro_http::StatusCode::BadRequest,
            "Enclave endpoint does not support sub-paths.".into(),
        ));
    }
    Ok(ParsedRequest::new_sync(VmmAction::GetEnclaveConfig))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_put_enclave_request() {
        let json = r#"{
            "debug_mode": true
        }"#;
        parse_put_enclave(&Body::new(json), [].into_iter()).unwrap();
    }

    #[test]
    fn test_parse_put_enclave_minimal() {
        let json = "{}";
        parse_put_enclave(&Body::new(json), [].into_iter()).unwrap();
    }

    #[test]
    fn test_parse_put_enclave_invalid() {
        parse_put_enclave(&Body::new("invalid"), [].into_iter()).unwrap_err();
    }

    #[test]
    fn test_parse_get_enclave() {
        parse_get_enclave([].into_iter()).unwrap();
        parse_get_enclave(["extra"].into_iter()).unwrap_err();
    }

    #[test]
    fn test_parse_put_enclave_rejects_subpath() {
        let json = "{}";
        parse_put_enclave(&Body::new(json), ["extra"].into_iter()).unwrap_err();
    }
}
