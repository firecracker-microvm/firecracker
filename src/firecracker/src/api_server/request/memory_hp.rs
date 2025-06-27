// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::memory_hp::MemoryHpConfig;

use super::super::parsed_request::{ParsedRequest, RequestError};
use super::Body;

pub(crate) fn parse_put_memory_hp(body: &Body) -> Result<ParsedRequest, RequestError> {
    Ok(ParsedRequest::new_sync(VmmAction::SetMemoryHpDevice(
        serde_json::from_slice::<MemoryHpConfig>(body.raw())?,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_server::parsed_request::tests::vmm_action_from_request;

    #[test]
    fn test_parse_put_memory_hp_request() {
        parse_put_memory_hp(&Body::new("invalid_payload")).unwrap_err();

        // PUT with invalid fields.
        let body = r#"{
            "total_size_mib": "bar"
        }"#;
        parse_put_memory_hp(&Body::new(body)).unwrap_err();

        // PUT with valid input fields.
        let body = r#"{
            "total_size_mib": 2048
        }"#;
        let expected_config = MemoryHpConfig {
            total_size_mib: 2048,
        };
        assert_eq!(
            vmm_action_from_request(parse_put_memory_hp(&Body::new(body)).unwrap()),
            VmmAction::SetMemoryHpDevice(expected_config)
        );
    }
}
