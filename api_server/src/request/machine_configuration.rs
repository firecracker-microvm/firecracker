// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0<Paste>

use super::super::VmmAction;
use logger::{Metric, METRICS};
use request::Body;
use request::Error;
use request::StatusCode;

use request::ParsedRequest;
use vmm::vmm_config::machine_config::VmConfig;

pub fn parse_get_machine_config() -> Result<ParsedRequest, Error> {
    METRICS.get_api_requests.machine_cfg_count.inc();
    Ok(ParsedRequest::Sync(VmmAction::GetVmConfiguration))
}

pub fn parse_put_machine_config(maybe_body: Option<&Body>) -> Result<ParsedRequest, Error> {
    METRICS.put_api_requests.machine_cfg_count.inc();
    match maybe_body {
        Some(body) => {
            let vm_config = serde_json::from_slice::<VmConfig>(body.raw()).map_err(|e| {
                METRICS.put_api_requests.machine_cfg_fails.inc();
                Error::SerdeJson(e)
            })?;
            if vm_config.vcpu_count.is_none()
                || vm_config.mem_size_mib.is_none()
                || vm_config.ht_enabled.is_none()
            {
                return Err(Error::Generic(
                    StatusCode::BadRequest,
                    "Missing mandatory fields.".to_string(),
                ));
            }
            Ok(ParsedRequest::Sync(VmmAction::SetVmConfiguration(
                vm_config,
            )))
        }
        None => Err(Error::Generic(
            StatusCode::BadRequest,
            "Missing mandatory fields.".to_string(),
        )),
    }
}

pub fn parse_patch_machine_config(maybe_body: Option<&Body>) -> Result<ParsedRequest, Error> {
    METRICS.patch_api_requests.machine_cfg_count.inc();
    match maybe_body {
        Some(body) => {
            let vm_config = serde_json::from_slice::<VmConfig>(body.raw()).map_err(|e| {
                METRICS.patch_api_requests.machine_cfg_fails.inc();
                Error::SerdeJson(e)
            })?;
            if vm_config.vcpu_count.is_none()
                && vm_config.mem_size_mib.is_none()
                && vm_config.cpu_template.is_none()
                && vm_config.ht_enabled.is_none()
            {
                return Err(Error::Generic(
                    StatusCode::BadRequest,
                    "Empty PATCH request.".to_string(),
                ));
            }
            Ok(ParsedRequest::Sync(VmmAction::SetVmConfiguration(
                vm_config,
            )))
        }
        None => Err(Error::Generic(
            StatusCode::BadRequest,
            "Empty PATCH request.".to_string(),
        )),
    }
}
