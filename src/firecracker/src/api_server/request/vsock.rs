// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::logger::{IncMetric, METRICS};
use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::vsock::VsockDeviceConfig;

use super::super::parsed_request::{ParsedRequest, RequestError};
use super::Body;

pub(crate) fn parse_put_vsock(body: &Body) -> Result<ParsedRequest, RequestError> {
    METRICS.put_api_requests.vsock_count.inc();
    let vsock_cfg = serde_json::from_slice::<VsockDeviceConfig>(body.raw()).inspect_err(|_| {
        METRICS.put_api_requests.vsock_fails.inc();
    })?;

    // Check for the presence of deprecated `vsock_id` field.
    let mut deprecation_message = None;
    if vsock_cfg.vsock_id.is_some() {
        // vsock_id field in request is deprecated.
        METRICS.deprecated_api.deprecated_http_api_calls.inc();
        deprecation_message = Some("PUT /vsock: vsock_id field is deprecated.");
    }

    // Construct the `ParsedRequest` object.
    let mut parsed_req = ParsedRequest::new_sync(VmmAction::SetVsockDevice(vsock_cfg));
    // If `vsock_id` was present, set the deprecation message in `parsing_info`.
    if let Some(msg) = deprecation_message {
        parsed_req.parsing_info().append_deprecation_message(msg);
    }

    Ok(parsed_req)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_server::parsed_request::tests::depr_action_from_req;

    #[test]
    fn test_parse_put_vsock_request() {
        let body = r#"{
            "guest_cid": 42,
            "uds_path": "vsock.sock"
        }"#;
        parse_put_vsock(&Body::new(body)).unwrap();

        let body = r#"{
            "guest_cid": 42,
            "invalid_field": false
        }"#;
        parse_put_vsock(&Body::new(body)).unwrap_err();
    }

    #[test]
    fn test_depr_vsock_id() {
        let body = r#"{
            "vsock_id": "foo",
            "guest_cid": 42,
            "uds_path": "vsock.sock"
        }"#;
        depr_action_from_req(
            parse_put_vsock(&Body::new(body)).unwrap(),
            Some("PUT /vsock: vsock_id field is deprecated.".to_string()),
        );

        let body = r#"{
            "guest_cid": 42,
            "uds_path": "vsock.sock"
        }"#;
        let (_, mut parsing_info) = parse_put_vsock(&Body::new(body)).unwrap().into_parts();
        assert!(parsing_info.take_deprecation_message().is_none());
    }
}
