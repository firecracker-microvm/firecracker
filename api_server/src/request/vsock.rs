// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::VmmAction;
use request::{Body, Error, ParsedRequest};
use vmm::vmm_config::vsock::VsockDeviceConfig;

pub fn parse_put_vsock(body: &Body) -> Result<ParsedRequest, Error> {
    Ok(ParsedRequest::Sync(VmmAction::SetVsockDevice(
        serde_json::from_slice::<VsockDeviceConfig>(body.raw()).map_err(Error::SerdeJson)?,
    )))
}
