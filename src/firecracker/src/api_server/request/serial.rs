// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use micro_http::Body;
use vmm::logger::{IncMetric, METRICS};
use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::serial::SerialConfig;

use crate::api_server::parsed_request::{ParsedRequest, RequestError};

pub(crate) fn parse_put_serial(body: &Body) -> Result<ParsedRequest, RequestError> {
    METRICS.put_api_requests.serial_count.inc();
    let res = serde_json::from_slice::<SerialConfig>(body.raw());
    let config = res.inspect_err(|_| {
        METRICS.put_api_requests.serial_fails.inc();
    })?;
    Ok(ParsedRequest::new_sync(VmmAction::ConfigureSerial(config)))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::api_server::parsed_request::tests::vmm_action_from_request;

    #[test]
    fn test_parse_put_serial_request() {
        let body = r#"{"serial_out_path": "serial"}"#;

        let expected_config = SerialConfig {
            serial_out_path: Some(PathBuf::from("serial")),
        };
        assert_eq!(
            vmm_action_from_request(parse_put_serial(&Body::new(body)).unwrap()),
            VmmAction::ConfigureSerial(expected_config)
        );
    }
}
