// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod memory;

use vmm::devices::virtio::device::VirtioDeviceType;
use vmm::rpc_interface::VmmAction;

use super::super::parsed_request::{ParsedRequest, RequestError, checked_id};

pub(crate) fn parse_unplug_device(
    device_type: VirtioDeviceType,
    id_from_path: Option<&str>,
) -> Result<ParsedRequest, RequestError> {
    let id = checked_id(id_from_path.ok_or(RequestError::EmptyID)?)?;
    Ok(ParsedRequest::new_sync(VmmAction::HotUnplugDevice((
        device_type,
        id.to_string(),
    ))))
}
