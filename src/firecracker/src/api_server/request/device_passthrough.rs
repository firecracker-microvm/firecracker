// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::logger::{IncMetric, METRICS};
use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::device_passthrough::DevicePassthroughConfig;

use super::super::parsed_request::{ParsedRequest, RequestError, checked_id};
use super::{Body, StatusCode};

pub(crate) fn parse_put_device_passthrough(
    body: &Body,
    id_from_path: Option<&str>,
) -> Result<ParsedRequest, RequestError> {
    METRICS.put_api_requests.device_passthrough_count.inc();
    let id = if let Some(id) = id_from_path {
        checked_id(id)?
    } else {
        METRICS.put_api_requests.device_passthrough_fails.inc();
        return Err(RequestError::EmptyID);
    };

    let device_cfg =
        serde_json::from_slice::<DevicePassthroughConfig>(body.raw()).inspect_err(|_| {
            METRICS.put_api_requests.device_passthrough_fails.inc();
        })?;

    if id != device_cfg.id {
        METRICS.put_api_requests.device_passthrough_fails.inc();
        Err(RequestError::Generic(
            StatusCode::BadRequest,
            "The id from the path does not match the id from the body!".to_string(),
        ))
    } else {
        Ok(ParsedRequest::new_sync(VmmAction::InsertPassthroughDevice(
            device_cfg,
        )))
    }
}

#[cfg(test)]
mod tests {
    use vmm::pci::PciSBDF;

    use super::*;
    use crate::api_server::parsed_request::tests::vmm_action_from_request;

    #[test]
    fn test_parse_put_device_passthrough_request() {
        // No body, no id
        parse_put_device_passthrough(&Body::new("invalid_payload"), None).unwrap_err();
        // Invalid body, with id
        parse_put_device_passthrough(&Body::new("invalid_payload"), Some("id")).unwrap_err();

        // Mismatched ids
        let body = r#"{
            "id": "bar",
            "sbdf": "0000:00:1f.0"
        }"#;
        parse_put_device_passthrough(&Body::new(body), Some("foo")).unwrap_err();

        // Missing required field
        let body = r#"{
            "id": "dev0"
        }"#;
        parse_put_device_passthrough(&Body::new(body), Some("dev0")).unwrap_err();

        // Valid request
        let body = r#"{
            "id": "dev0",
            "sbdf": "0000:00:1f.0"
        }"#;
        let r = vmm_action_from_request(
            parse_put_device_passthrough(&Body::new(body), Some("dev0")).unwrap(),
        );

        let expected_config = DevicePassthroughConfig {
            id: "dev0".to_string(),
            sbdf: PciSBDF::new(0x0, 0x0, 0x1f, 0x0),
        };
        assert_eq!(r, VmmAction::InsertPassthroughDevice(expected_config));
    }
}
