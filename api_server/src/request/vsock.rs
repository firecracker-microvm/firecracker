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
        id_from_path: Option<String>,
        _: Method,
    ) -> result::Result<ParsedRequest, String> {
        let id_from_path = id_from_path.unwrap_or_default();
        if id_from_path != self.id.as_str() {
            return Err(String::from(
                "The id from the path does not match the id from the body!",
            ));
        }

        let (sender, receiver) = oneshot::channel();
        Ok(ParsedRequest::Sync(
            VmmAction::InsertVsockDevice(self, sender),
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
            id: String::from("foo"),
            guest_cid: 42,
        };
        assert!(vsock
            .clone()
            .into_parsed_request(Some(String::from("bar")), Method::Put)
            .is_err());
        assert!(vsock
            .clone()
            .into_parsed_request(Some(String::from("foo")), Method::Put)
            .is_ok());
    }
}
