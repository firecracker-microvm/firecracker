// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::logger::{IncMetric, METRICS};
use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::machine_config::{MachineConfig, MachineConfigUpdate};

use super::super::parsed_request::{ParsedRequest, RequestError, method_to_error};
use super::{Body, Method};

pub(crate) fn parse_get_machine_config() -> Result<ParsedRequest, RequestError> {
    METRICS.get_api_requests.machine_cfg_count.inc();
    Ok(ParsedRequest::new_sync(VmmAction::GetVmMachineConfig))
}

pub(crate) fn parse_put_machine_config(body: &Body) -> Result<ParsedRequest, RequestError> {
    METRICS.put_api_requests.machine_cfg_count.inc();
    let config = serde_json::from_slice::<MachineConfig>(body.raw()).inspect_err(|_| {
        METRICS.put_api_requests.machine_cfg_fails.inc();
    })?;

    // Check for the presence of deprecated `cpu_template` field.
    let mut deprecation_message = None;
    if config.cpu_template.is_some() {
        // `cpu_template` field in request is deprecated.
        METRICS.deprecated_api.deprecated_http_api_calls.inc();
        deprecation_message = Some("PUT /machine-config: cpu_template field is deprecated.");
    }

    // Convert `MachineConfig` to `MachineConfigUpdate`.
    let config_update = MachineConfigUpdate::from(config);

    // Construct the `ParsedRequest` object.
    let mut parsed_req =
        ParsedRequest::new_sync(VmmAction::UpdateMachineConfiguration(config_update));
    // If `cpu_template` was present, set the deprecation message in `parsing_info`.
    if let Some(msg) = deprecation_message {
        parsed_req.parsing_info().append_deprecation_message(msg);
    }

    Ok(parsed_req)
}

pub(crate) fn parse_patch_machine_config(body: &Body) -> Result<ParsedRequest, RequestError> {
    METRICS.patch_api_requests.machine_cfg_count.inc();
    let config_update =
        serde_json::from_slice::<MachineConfigUpdate>(body.raw()).inspect_err(|_| {
            METRICS.patch_api_requests.machine_cfg_fails.inc();
        })?;

    if config_update.is_empty() {
        return method_to_error(Method::Patch);
    }

    // Check for the presence of deprecated `cpu_template` field.
    let mut deprecation_message = None;
    if config_update.cpu_template.is_some() {
        // `cpu_template` field in request is deprecated.
        METRICS.deprecated_api.deprecated_http_api_calls.inc();
        deprecation_message = Some("PATCH /machine-config: cpu_template field is deprecated.");
    }

    // Construct the `ParsedRequest` object.
    let mut parsed_req =
        ParsedRequest::new_sync(VmmAction::UpdateMachineConfiguration(config_update));
    // If `cpu_template` was present, set the deprecation message in `parsing_info`.
    if let Some(msg) = deprecation_message {
        parsed_req.parsing_info().append_deprecation_message(msg);
    }

    Ok(parsed_req)
}

#[cfg(test)]
mod tests {
    use vmm::cpu_config::templates::StaticCpuTemplate;
    use vmm::vmm_config::machine_config::HugePageConfig;

    use super::*;
    use crate::api_server::parsed_request::tests::{depr_action_from_req, vmm_action_from_request};

    #[test]
    fn test_parse_get_machine_config_request() {
        parse_get_machine_config().unwrap();
        assert!(METRICS.get_api_requests.machine_cfg_count.count() > 0);
    }

    #[test]
    fn test_parse_put_machine_config_request() {
        // 1. Test case for invalid payload.
        parse_put_machine_config(&Body::new("invalid_payload")).unwrap_err();
        assert!(METRICS.put_api_requests.machine_cfg_fails.count() > 0);

        // 2. Test case for mandatory fields.
        let body = r#"{
            "mem_size_mib": 1024
        }"#;
        parse_put_machine_config(&Body::new(body)).unwrap_err();

        let body = r#"{
            "vcpu_count": 8
        }"#;
        parse_put_machine_config(&Body::new(body)).unwrap_err();

        let huge_pages_cases = [
            ("None", HugePageConfig::None),
            ("2M", HugePageConfig::Hugetlbfs2M),
        ];

        for (huge_page, expected) in huge_pages_cases {
            // 3. Test case for success scenarios for both architectures.
            let body = format!(
                r#"{{
                "vcpu_count": 8,
                "mem_size_mib": 1024,
                "huge_pages": "{huge_page}"
            }}"#
            );
            let expected_config = MachineConfigUpdate {
                vcpu_count: Some(8),
                mem_size_mib: Some(1024),
                smt: Some(false),
                cpu_template: None,
                track_dirty_pages: Some(false),
                huge_pages: Some(expected),
                #[cfg(feature = "gdb")]
                gdb_socket_path: None,
            };
            assert_eq!(
                vmm_action_from_request(parse_put_machine_config(&Body::new(body)).unwrap()),
                VmmAction::UpdateMachineConfiguration(expected_config)
            );
        }

        let body = r#"{
            "vcpu_count": 8,
            "mem_size_mib": 1024,
            "cpu_template": "None"
        }"#;
        let expected_config = MachineConfigUpdate {
            vcpu_count: Some(8),
            mem_size_mib: Some(1024),
            smt: Some(false),
            cpu_template: Some(StaticCpuTemplate::None),
            track_dirty_pages: Some(false),
            huge_pages: Some(HugePageConfig::None),
            #[cfg(feature = "gdb")]
            gdb_socket_path: None,
        };
        assert_eq!(
            vmm_action_from_request(parse_put_machine_config(&Body::new(body)).unwrap()),
            VmmAction::UpdateMachineConfiguration(expected_config)
        );

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
            cpu_template: None,
            track_dirty_pages: Some(true),
            huge_pages: Some(HugePageConfig::None),
            #[cfg(feature = "gdb")]
            gdb_socket_path: None,
        };
        assert_eq!(
            vmm_action_from_request(parse_put_machine_config(&Body::new(body)).unwrap()),
            VmmAction::UpdateMachineConfiguration(expected_config)
        );

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
                huge_pages: Some(HugePageConfig::None),
                #[cfg(feature = "gdb")]
                gdb_socket_path: None,
            };
            assert_eq!(
                vmm_action_from_request(parse_put_machine_config(&Body::new(body)).unwrap()),
                VmmAction::UpdateMachineConfiguration(expected_config)
            );
        }
        #[cfg(target_arch = "aarch64")]
        {
            parse_put_machine_config(&Body::new(body)).unwrap_err();
        }

        // 5. Test that setting `smt: true` is successful
        let body = r#"{
            "vcpu_count": 8,
            "mem_size_mib": 1024,
            "smt": true,
            "track_dirty_pages": true
        }"#;
        let expected_config = MachineConfigUpdate {
            vcpu_count: Some(8),
            mem_size_mib: Some(1024),
            smt: Some(true),
            cpu_template: None,
            track_dirty_pages: Some(true),
            huge_pages: Some(HugePageConfig::None),
            #[cfg(feature = "gdb")]
            gdb_socket_path: None,
        };
        assert_eq!(
            vmm_action_from_request(parse_put_machine_config(&Body::new(body)).unwrap()),
            VmmAction::UpdateMachineConfiguration(expected_config)
        );

        // 6. Test nonsense values for huge page size
        let body = r#"{
            "vcpu_count": 8,
            "mem_size_mib": 1024,
            "huge_pages": "7M"
        }"#;
        parse_put_machine_config(&Body::new(body)).unwrap_err();
    }

    #[test]
    fn test_parse_patch_machine_config_request() {
        // 1. Test cases for invalid payload.
        parse_patch_machine_config(&Body::new("invalid_payload")).unwrap_err();

        // 2. Check currently supported fields that can be patched.
        let body = r#"{
            "track_dirty_pages": true
        }"#;
        parse_patch_machine_config(&Body::new(body)).unwrap();

        // On aarch64, CPU template is also not patch compatible.
        let body = r#"{
            "cpu_template": "T2"
        }"#;
        #[cfg(target_arch = "aarch64")]
        parse_patch_machine_config(&Body::new(body)).unwrap_err();
        #[cfg(target_arch = "x86_64")]
        parse_patch_machine_config(&Body::new(body)).unwrap();

        let body = r#"{
            "vcpu_count": 8,
            "mem_size_mib": 1024
        }"#;
        parse_patch_machine_config(&Body::new(body)).unwrap();

        // On aarch64, we allow `smt` to be configured to `false` but not `true`.
        let body = r#"{
            "vcpu_count": 8,
            "mem_size_mib": 1024,
            "smt": false
        }"#;
        parse_patch_machine_config(&Body::new(body)).unwrap();

        // 3. Check to see if an empty body returns an error.
        let body = r#"{}"#;
        parse_patch_machine_config(&Body::new(body)).unwrap_err();
    }

    #[test]
    fn test_depr_cpu_template_in_put_req() {
        // Test that the deprecation message is shown when `cpu_template` is specified.
        let body = r#"{
            "vcpu_count": 8,
            "mem_size_mib": 1024,
            "cpu_template": "None"
        }"#;
        depr_action_from_req(
            parse_put_machine_config(&Body::new(body)).unwrap(),
            Some("PUT /machine-config: cpu_template field is deprecated.".to_string()),
        );

        // Test that the deprecation message is not shown when `cpu_template` is not specified.
        let body = r#"{
            "vcpu_count": 8,
            "mem_size_mib": 1024
        }"#;
        let (_, mut parsing_info) = parse_put_machine_config(&Body::new(body))
            .unwrap()
            .into_parts();
        assert!(parsing_info.take_deprecation_message().is_none());
    }

    #[test]
    fn test_depr_cpu_template_in_patch_req() {
        // Test that the deprecation message is shown when `cpu_template` is specified.
        let body = r#"{
            "vcpu_count": 8,
            "cpu_template": "None"
        }"#;
        depr_action_from_req(
            parse_patch_machine_config(&Body::new(body)).unwrap(),
            Some("PATCH /machine-config: cpu_template field is deprecated.".to_string()),
        );

        // Test that the deprecation message is not shown when `cpu_template` is not specified.
        let body = r#"{
            "vcpu_count": 8
        }"#;
        let (_, mut parsing_info) = parse_patch_machine_config(&Body::new(body))
            .unwrap()
            .into_parts();
        assert!(parsing_info.take_deprecation_message().is_none());
    }
}
