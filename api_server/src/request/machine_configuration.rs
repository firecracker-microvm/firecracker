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

#[cfg(test)]
mod tests {
    use super::*;

    use vmm::vmm_config::machine_config::CpuFeaturesTemplate;

    #[test]
    fn test_parse_get_machine_config_request() {
        assert!(parse_get_machine_config().is_ok());
    }

    #[test]
    fn test_parse_put_machine_config_request() {
        assert!(parse_put_machine_config(None).is_err());
        assert!(parse_put_machine_config(Some(&Body::new("invalid_payload"))).is_err());

        let config_clone = VmConfig {
            vcpu_count: Some(8),
            mem_size_mib: Some(1024),
            ht_enabled: Some(true),
            cpu_template: Some(CpuFeaturesTemplate::T2),
        };
        let body = r#"{
                "vcpu_count": 8,
                "mem_size_mib": 1024,
                "ht_enabled": true,
                "cpu_template": "T2"
              }"#;
        match parse_put_machine_config(Some(&Body::new(body))) {
            Ok(ParsedRequest::Sync(VmmAction::SetVmConfiguration(config))) => {
                assert_eq!(config, config_clone)
            }
            _ => panic!("Test failed."),
        }

        let body = r#"{
                "vcpu_count": 8,
                "mem_size_mib": 1024
              }"#;
        assert!(parse_put_machine_config(Some(&Body::new(body))).is_err());
    }

    #[test]
    fn test_parse_patch_machine_config_request() {
        assert!(parse_patch_machine_config(None).is_err());
        assert!(parse_patch_machine_config(Some(&Body::new("invalid_payload"))).is_err());

        let body = r#"{}"#;
        assert!(parse_patch_machine_config(Some(&Body::new(body))).is_err());

        let body = r#"{
                "vcpu_count": 8,
                "mem_size_mib": 1024
              }"#;
        assert!(parse_patch_machine_config(Some(&Body::new(body))).is_ok());
        let body = r#"{
                "vcpu_count": 8,
                "mem_size_mib": 1024,
                "ht_enabled": false
              }"#;
        assert!(parse_patch_machine_config(Some(&Body::new(body))).is_ok());
    }
}
