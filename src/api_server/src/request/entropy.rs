// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::entropy::EntropyDeviceConfig;

use crate::parsed_request::{Error, ParsedRequest};
use crate::request::Body;

pub(crate) fn parse_put_entropy(body: &Body) -> Result<ParsedRequest, Error> {
    let cfg = serde_json::from_slice::<EntropyDeviceConfig>(body.raw())?;
    Ok(ParsedRequest::new_sync(VmmAction::SetEntropyDevice(cfg)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_put_entropy_request() {
        assert!(parse_put_entropy(&Body::new("invalid_payload")).is_err());

        // PUT with invalid fields.
        let body = r#"{
            "some_id": 4
        }"#;
        assert!(parse_put_entropy(&Body::new(body)).is_err());

        // PUT with valid fields.
        let body = r#"{}"#;
        assert!(parse_put_entropy(&Body::new(body)).is_ok());
    }
}
