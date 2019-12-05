// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::VmmAction;
use request::{Body, Error, ParsedRequest};
use vmm::vmm_config::vsock::VsockDeviceConfig;

pub fn parse_put_vsock(body: &Body) -> Result<ParsedRequest, Error> {
    Ok(ParsedRequest::Sync(VmmAction::SetVsockDevice(
        serde_json::from_slice::<VsockDeviceConfig>(body.raw()).map_err(Error::SerdeJson)?,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_vsock_request() {
        let body = r#"{
                "vsock_id": "foo",
                "guest_cid": 42,
                "uds_path": "vsock.sock"
              }"#;
        assert!(parse_put_vsock(&Body::new(body)).is_ok());

        let body = r#"{
                "vsock_id": "foo",
                "guest_cid": 42,
                "invalid_field": false
              }"#;
        assert!(parse_put_vsock(&Body::new(body)).is_err());
    }
}
