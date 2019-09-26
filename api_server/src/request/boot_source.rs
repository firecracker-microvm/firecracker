// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::result;

use futures::sync::oneshot;
use hyper::Method;

use request::{IntoParsedRequest, ParsedRequest};
use vmm::vmm_config::boot_source::BootSourceConfig;
use vmm::VmmAction;

impl IntoParsedRequest for BootSourceConfig {
    fn into_parsed_request(
        self,
        _: Option<String>,
        _: Method,
    ) -> result::Result<ParsedRequest, String> {
        let (sender, receiver) = oneshot::channel();
        Ok(ParsedRequest::Sync(
            Box::new(VmmAction::ConfigureBootSource(self, sender)),
            receiver,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_into_parsed_request() {
        let body = BootSourceConfig {
            kernel_image_path: String::from("/foo/bar"),
            boot_args: Some(String::from("foobar")),
        };
        let same_body = BootSourceConfig {
            kernel_image_path: String::from("/foo/bar"),
            boot_args: Some(String::from("foobar")),
        };
        let (sender, receiver) = oneshot::channel();
        assert!(body
            .into_parsed_request(None, Method::Put)
            .eq(&Ok(ParsedRequest::Sync(
                Box::new(VmmAction::ConfigureBootSource(same_body, sender)),
                receiver
            ))))
    }
}
