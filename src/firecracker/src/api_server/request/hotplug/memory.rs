// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use micro_http::Body;
use vmm::logger::{IncMetric, METRICS};
use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::memory_hotplug::{MemoryHotplugConfig, MemoryHotplugSizeUpdate};

use crate::api_server::parsed_request::{ParsedRequest, RequestError};

pub(crate) fn parse_put_memory_hotplug(body: &Body) -> Result<ParsedRequest, RequestError> {
    METRICS.put_api_requests.hotplug_memory_count.inc();
    let config = serde_json::from_slice::<MemoryHotplugConfig>(body.raw()).inspect_err(|_| {
        METRICS.put_api_requests.hotplug_memory_fails.inc();
    })?;
    Ok(ParsedRequest::new_sync(VmmAction::SetMemoryHotplugDevice(
        config,
    )))
}

pub(crate) fn parse_get_memory_hotplug() -> Result<ParsedRequest, RequestError> {
    METRICS.get_api_requests.hotplug_memory_count.inc();
    Ok(ParsedRequest::new_sync(VmmAction::GetMemoryHotplugStatus))
}

pub(crate) fn parse_patch_memory_hotplug(body: &Body) -> Result<ParsedRequest, RequestError> {
    METRICS.patch_api_requests.hotplug_memory_count.inc();
    let config =
        serde_json::from_slice::<MemoryHotplugSizeUpdate>(body.raw()).inspect_err(|_| {
            METRICS.patch_api_requests.hotplug_memory_fails.inc();
        })?;
    Ok(ParsedRequest::new_sync(VmmAction::UpdateMemoryHotplugSize(
        config,
    )))
}

#[cfg(test)]
mod tests {
    use vmm::devices::virtio::mem::{
        VIRTIO_MEM_DEFAULT_BLOCK_SIZE_MIB, VIRTIO_MEM_DEFAULT_SLOT_SIZE_MIB,
    };
    use vmm::vmm_config::memory_hotplug::MemoryHotplugSizeUpdate;

    use super::*;
    use crate::api_server::parsed_request::tests::vmm_action_from_request;

    #[test]
    fn test_parse_put_memory_hotplug_request() {
        parse_put_memory_hotplug(&Body::new("invalid_payload")).unwrap_err();

        // PUT with invalid fields.
        let body = r#"{
            "total_size_mib": "bar"
        }"#;
        parse_put_memory_hotplug(&Body::new(body)).unwrap_err();

        // PUT with valid input fields with defaults.
        let body = r#"{
            "total_size_mib": 2048
        }"#;
        let expected_config = MemoryHotplugConfig {
            total_size_mib: 2048,
            block_size_mib: VIRTIO_MEM_DEFAULT_BLOCK_SIZE_MIB,
            slot_size_mib: VIRTIO_MEM_DEFAULT_SLOT_SIZE_MIB,
        };
        assert_eq!(
            vmm_action_from_request(parse_put_memory_hotplug(&Body::new(body)).unwrap()),
            VmmAction::SetMemoryHotplugDevice(expected_config)
        );

        // PUT with valid input fields.
        let body = r#"{
            "total_size_mib": 2048,
            "block_size_mib": 64,
            "slot_size_mib": 64
        }"#;
        let expected_config = MemoryHotplugConfig {
            total_size_mib: 2048,
            block_size_mib: 64,
            slot_size_mib: 64,
        };
        assert_eq!(
            vmm_action_from_request(parse_put_memory_hotplug(&Body::new(body)).unwrap()),
            VmmAction::SetMemoryHotplugDevice(expected_config)
        );
    }

    #[test]
    fn test_parse_parse_get_memory_hotplug_request() {
        assert_eq!(
            vmm_action_from_request(parse_get_memory_hotplug().unwrap()),
            VmmAction::GetMemoryHotplugStatus
        );
    }

    #[test]
    fn test_parse_patch_memory_hotplug_request() {
        parse_patch_memory_hotplug(&Body::new("invalid_payload")).unwrap_err();

        // PATCH with invalid fields.
        let body = r#"{
            "requested_size_mib": "bar"
        }"#;
        parse_patch_memory_hotplug(&Body::new(body)).unwrap_err();

        // PATCH with valid input fields.
        let body = r#"{
            "requested_size_mib": 2048
        }"#;
        let expected_config = MemoryHotplugSizeUpdate {
            requested_size_mib: 2048,
        };
        assert_eq!(
            vmm_action_from_request(parse_patch_memory_hotplug(&Body::new(body)).unwrap()),
            VmmAction::UpdateMemoryHotplugSize(expected_config)
        );
    }
}
