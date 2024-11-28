// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::logger::{IncMetric, METRICS};
use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::boot_source::BootSourceConfig;

use super::super::parsed_request::{ParsedRequest, RequestError};
use super::Body;

pub(crate) fn parse_put_boot_source(body: &Body) -> Result<ParsedRequest, RequestError> {
    METRICS.put_api_requests.boot_source_count.inc();
    Ok(ParsedRequest::new_sync(VmmAction::ConfigureBootSource(
        serde_json::from_slice::<BootSourceConfig>(body.raw()).inspect_err(|_| {
            METRICS.put_api_requests.boot_source_fails.inc();
        })?,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_boot_request() {
        parse_put_boot_source(&Body::new("invalid_payload")).unwrap_err();

        let body = r#"{
            "kernel_image_path": "/foo/bar",
            "initrd_path": "/bar/foo",
            "boot_args": "foobar"
        }"#;
        let same_body = BootSourceConfig {
            kernel_image_path: String::from("/foo/bar"),
            initrd_path: Some(String::from("/bar/foo")),
            boot_args: Some(String::from("foobar")),
        };
        let parsed_req = parse_put_boot_source(&Body::new(body)).unwrap();

        assert_eq!(
            parsed_req,
            ParsedRequest::new_sync(VmmAction::ConfigureBootSource(same_body))
        );
    }
}
