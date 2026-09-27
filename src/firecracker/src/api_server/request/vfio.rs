// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::logger::{IncMetric, METRICS};
use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::vfio::VfioDeviceConfig;

use super::super::parsed_request::{ParsedRequest, RequestError, checked_id};
use super::{Body, StatusCode};

pub(crate) fn parse_put_vfio(
    body: &Body,
    id_from_path: Option<&str>,
) -> Result<ParsedRequest, RequestError> {
    METRICS.put_api_requests.vfio_count.inc();
    let id = if let Some(id) = id_from_path {
        checked_id(id)?
    } else {
        METRICS.put_api_requests.vfio_fails.inc();
        return Err(RequestError::EmptyID);
    };

    let device_cfg = serde_json::from_slice::<VfioDeviceConfig>(body.raw()).inspect_err(|_| {
        METRICS.put_api_requests.vfio_fails.inc();
    })?;

    if id != device_cfg.id {
        METRICS.put_api_requests.vfio_fails.inc();
        Err(RequestError::Generic(
            StatusCode::BadRequest,
            "The id from the path does not match the id from the body!".to_string(),
        ))
    } else {
        Ok(ParsedRequest::new_sync(VmmAction::InsertVfioDevice(
            device_cfg,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_put_vfio_request() {
        parse_put_vfio(&Body::new("invalid_payload"), None).unwrap_err();
        parse_put_vfio(&Body::new("invalid_payload"), Some("id")).unwrap_err();

        // Empty body is not valid.
        parse_put_vfio(&Body::new("{}"), Some("1")).unwrap_err();

        // Mismatched id between path and body.
        let body = r#"{
            "id": "dev0",
            "path": "/sys/bus/pci/devices/0000:01:00.0"
        }"#;
        parse_put_vfio(&Body::new(body), Some("other")).unwrap_err();

        // Valid request.
        let body = r#"{
            "id": "dev0",
            "path": "/sys/bus/pci/devices/0000:01:00.0"
        }"#;
        parse_put_vfio(&Body::new(body), Some("dev0")).unwrap();
    }
}
