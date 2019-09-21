// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::result;

use futures::sync::oneshot;
use hyper::Method;

use request::{IntoParsedRequest, ParsedRequest};
use vmm::vmm_config::vsock::VsockDeviceConfig;
use vmm::VmmAction;

impl IntoParsedRequest for VsockDeviceConfig {
    fn into_parsed_request(
        self,
        _: Option<String>,
        _: Method,
    ) -> result::Result<ParsedRequest, String> {
        let (sender, receiver) = oneshot::channel();
        Ok(ParsedRequest::Sync(
            VmmAction::SetVsockDevice(self, sender),
            receiver,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vsock_into_parsed_request() {
        let vsock = VsockDeviceConfig {
            vsock_id: String::from("foo"),
            guest_cid: 42,
            uds_path: "vsock.sock".to_string(),
        };
        assert!(vsock
            .clone()
            .into_parsed_request(Some(String::from("foo")), Method::Put)
            .is_ok());
    }
}
