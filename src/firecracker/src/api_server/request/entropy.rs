// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::entropy::EntropyDeviceConfig;

use super::super::parsed_request::{ParsedRequest, RequestError};
use super::Body;

pub(crate) fn parse_put_entropy(body: &Body) -> Result<ParsedRequest, RequestError> {
    let cfg = serde_json::from_slice::<EntropyDeviceConfig>(body.raw())?;
    Ok(ParsedRequest::new_sync(VmmAction::SetEntropyDevice(cfg)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_put_entropy_request() {
        parse_put_entropy(&Body::new("invalid_payload")).unwrap_err();

        // PUT with invalid fields.
        let body = r#"{
            "some_id": 4
        }"#;
        parse_put_entropy(&Body::new(body)).unwrap_err();

        // PUT with valid fields.
        let body = r#"{}"#;
        parse_put_entropy(&Body::new(body)).unwrap();
    }
}
