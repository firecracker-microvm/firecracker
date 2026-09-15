// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod memory;

use micro_http::Body;
use serde::Deserialize;
use vmm::devices::virtio::device::VirtioDeviceType;
use vmm::rpc_interface::VmmAction;

use super::super::parsed_request::{ParsedRequest, RequestError, checked_id};

/// Body of a device DELETE request.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnplugParams {
    /// Remove the device immediately instead of waiting for the guest to
    /// release it.
    #[serde(default)]
    force: bool,
}

pub(crate) fn parse_unplug_device(
    device_type: VirtioDeviceType,
    id_from_path: Option<&str>,
    body: Option<&Body>,
) -> Result<ParsedRequest, RequestError> {
    let id = checked_id(id_from_path.ok_or(RequestError::EmptyID)?)?;
    let params: UnplugParams = match body {
        Some(body) => serde_json::from_slice(body.raw())?,
        None => UnplugParams::default(),
    };

    Ok(ParsedRequest::new_sync(VmmAction::HotUnplugDevice(
        (device_type, id.to_string()),
        params.force,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_server::parsed_request::tests::vmm_action_from_request;

    fn parse(body: Option<&str>) -> Result<ParsedRequest, RequestError> {
        let body = body.map(Body::new);
        parse_unplug_device(VirtioDeviceType::Block, Some("block0"), body.as_ref())
    }

    fn force_flag(body: Option<&str>) -> bool {
        match vmm_action_from_request(parse(body).unwrap()) {
            VmmAction::HotUnplugDevice(id, force) => {
                assert_eq!(id, (VirtioDeviceType::Block, "block0".to_string()));
                force
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn test_parse_unplug_device_request() {
        // No body, an empty object and an explicit false all ask for a graceful
        // removal.
        assert!(!force_flag(None));
        assert!(!force_flag(Some("{}")));
        assert!(!force_flag(Some(r#"{ "force": false }"#)));

        assert!(force_flag(Some(r#"{ "force": true }"#)));

        // An ID is required.
        parse_unplug_device(VirtioDeviceType::Block, None, None).unwrap_err();

        // Bad bodies are rejected rather than silently treated as a default.
        parse(Some("invalid_payload")).unwrap_err();
        parse(Some(r#"{ "force": "yes" }"#)).unwrap_err();
        parse(Some(r#"{ "forced": true }"#)).unwrap_err();
    }
}
