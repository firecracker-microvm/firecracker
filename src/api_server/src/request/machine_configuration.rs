// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0<Paste>

use vmm::logger::{IncMetric, METRICS};
use vmm::vmm_config::machine_config::{MachineConfig, MachineConfigUpdate};

use super::super::VmmAction;
use crate::parsed_request::{method_to_error, Error, ParsedRequest};
use crate::request::{Body, Method};

pub(crate) fn parse_get_machine_config() -> Result<ParsedRequest, Error> {
    METRICS.get_api_requests.machine_cfg_count.inc();
    Ok(ParsedRequest::new_sync(VmmAction::GetVmMachineConfig))
}

pub(crate) fn parse_put_machine_config(body: &Body) -> Result<ParsedRequest, Error> {
    METRICS.put_api_requests.machine_cfg_count.inc();
    let config = serde_json::from_slice::<MachineConfig>(body.raw()).map_err(|err| {
        METRICS.put_api_requests.machine_cfg_fails.inc();
        err
    })?;

    let config_update = MachineConfigUpdate::from(config);

    Ok(ParsedRequest::new_sync(VmmAction::UpdateVmConfiguration(
        config_update,
    )))
}

pub(crate) fn parse_patch_machine_config(body: &Body) -> Result<ParsedRequest, Error> {
    METRICS.patch_api_requests.machine_cfg_count.inc();
    let config_update =
        serde_json::from_slice::<MachineConfigUpdate>(body.raw()).map_err(|err| {
            METRICS.patch_api_requests.machine_cfg_fails.inc();
            err
        })?;

    if config_update.is_empty() {
        return method_to_error(Method::Patch);
    }

    Ok(ParsedRequest::new_sync(VmmAction::UpdateVmConfiguration(
        config_update,
    )))
}

#[cfg(test)]
mod tests {
    use vmm::cpu_config::templates::StaticCpuTemplate;

    use super::*;
    use crate::parsed_request::tests::vmm_action_from_request;

    #[test]
    fn test_parse_get_machine_config_request() {
        assert!(parse_get_machine_config().is_ok());
        assert!(METRICS.get_api_requests.machine_cfg_count.count() > 0);
    }

    #[test]
    fn test_parse_put_machine_config_request() {
        // 1. Test case for invalid payload.
        assert!(parse_put_machine_config(&Body::new("invalid_payload")).is_err());
        assert!(METRICS.put_api_requests.machine_cfg_fails.count() > 0);

        // 2. Test case for mandatory fields.
        let body = r#"{
                "mem_size_mib": 1024
              }"#;
        assert!(parse_put_machine_config(&Body::new(body)).is_err());

        let body = r#"{
                "vcpu_count": 8
                }"#;
        assert!(parse_put_machine_config(&Body::new(body)).is_err());

        // 3. Test case for success scenarios for both architectures.
        let body = r#"{
                "vcpu_count": 8,
                "mem_size_mib": 1024
              }"#;
        let expected_config = MachineConfigUpdate {
            vcpu_count: Some(8),
            mem_size_mib: Some(1024),
            smt: Some(false),
            cpu_template: Some(StaticCpuTemplate::None),
            track_dirty_pages: Some(false),
        };

        match vmm_action_from_request(parse_put_machine_config(&Body::new(body)).unwrap()) {
            VmmAction::UpdateVmConfiguration(config) => assert_eq!(config, expected_config),
            _ => panic!("Test failed."),
        }

        let body = r#"{
                "vcpu_count": 8,
                "mem_size_mib": 1024,
                "smt": false,
                "track_dirty_pages": true
            }"#;
        let expected_config = MachineConfigUpdate {
            vcpu_count: Some(8),
            mem_size_mib: Some(1024),
            smt: Some(false),
            cpu_template: Some(StaticCpuTemplate::None),
            track_dirty_pages: Some(true),
        };

        match vmm_action_from_request(parse_put_machine_config(&Body::new(body)).unwrap()) {
            VmmAction::UpdateVmConfiguration(config) => assert_eq!(config, expected_config),
            _ => panic!("Test failed."),
        }

        // 4. Test that applying a CPU template is successful on x86_64 while on aarch64, it is not.
        let body = r#"{
                "vcpu_count": 8,
                "mem_size_mib": 1024,
                "smt": false,
                "cpu_template": "T2",
                "track_dirty_pages": true
              }"#;

        #[cfg(target_arch = "x86_64")]
        {
            let expected_config = MachineConfigUpdate {
                vcpu_count: Some(8),
                mem_size_mib: Some(1024),
                smt: Some(false),
                cpu_template: Some(StaticCpuTemplate::T2),
                track_dirty_pages: Some(true),
            };

            match vmm_action_from_request(parse_put_machine_config(&Body::new(body)).unwrap()) {
                VmmAction::UpdateVmConfiguration(config) => assert_eq!(config, expected_config),
                _ => panic!("Test failed."),
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            assert!(parse_put_machine_config(&Body::new(body)).is_err());
        }

        // 5. Test that setting `smt: true` is successful on x86_64 while on aarch64, it is not.
        let body = r#"{
            "vcpu_count": 8,
            "mem_size_mib": 1024,
            "smt": true,
            "track_dirty_pages": true
          }"#;

        #[cfg(target_arch = "x86_64")]
        {
            let expected_config = MachineConfigUpdate {
                vcpu_count: Some(8),
                mem_size_mib: Some(1024),
                smt: Some(true),
                cpu_template: Some(StaticCpuTemplate::None),
                track_dirty_pages: Some(true),
            };

            match vmm_action_from_request(parse_put_machine_config(&Body::new(body)).unwrap()) {
                VmmAction::UpdateVmConfiguration(config) => assert_eq!(config, expected_config),
                _ => panic!("Test failed."),
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            assert!(parse_put_machine_config(&Body::new(body)).is_err());
        }
    }

    #[test]
    fn test_parse_patch_machine_config_request() {
        // 1. Test cases for invalid payload.
        assert!(parse_patch_machine_config(&Body::new("invalid_payload")).is_err());

        // 2. Check currently supported fields that can be patched.
        let body = r#"{
                "track_dirty_pages": true
              }"#;
        assert!(parse_patch_machine_config(&Body::new(body)).is_ok());

        // On aarch64, CPU template is also not patch compatible.
        let body = r#"{
                "cpu_template": "T2"
              }"#;
        #[cfg(target_arch = "aarch64")]
        assert!(parse_patch_machine_config(&Body::new(body)).is_err());
        #[cfg(target_arch = "x86_64")]
        assert!(parse_patch_machine_config(&Body::new(body)).is_ok());

        let body = r#"{
                "vcpu_count": 8,
                "mem_size_mib": 1024
              }"#;
        assert!(parse_patch_machine_config(&Body::new(body)).is_ok());

        // On aarch64, we allow `smt` to be configured to `false` but not `true`.
        let body = r#"{
                "vcpu_count": 8,
                "mem_size_mib": 1024,
                "smt": false
              }"#;
        assert!(parse_patch_machine_config(&Body::new(body)).is_ok());

        // 3. Check to see if an empty body returns an error.
        let body = r#"{}"#;
        assert!(parse_patch_machine_config(&Body::new(body)).is_err());
    }
}
