// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use logger::{IncMetric, METRICS};
use vmm::vmm_config::vsock::VsockDeviceConfig;

use super::super::VmmAction;
use crate::parsed_request::{Error, ParsedRequest};

pub(crate) fn parse_put_vsock(body: serde_json::Value) -> Result<ParsedRequest, Error> {
    METRICS.put_api_requests.vsock_count.inc();
    let vsock_cfg = serde_json::from_value::<VsockDeviceConfig>(body).map_err(|err| {
        METRICS.put_api_requests.vsock_fails.inc();
        err
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

    #[test]
    fn test_parse_put_vsock_request() {
        assert!(parse_put_vsock(serde_json::Value::Null).is_ok());

        let body = serde_json::json!({
          "guest_cid": 42,
          "invalid_field": false
        });
        assert!(parse_put_vsock(body).is_err());
    }
}
