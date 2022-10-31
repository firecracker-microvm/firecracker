// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use guest_config::CustomCpuConfiguration;
use logger::{log_dev_preview_warning, IncMetric, METRICS};

use super::super::VmmAction;
use crate::parsed_request;
use crate::parsed_request::{Error, ParsedRequest};
use crate::request::Body;

pub(crate) fn parse_put_cpu_config(body: &Body) -> Result<ParsedRequest, Error> {
    METRICS.put_api_requests.cpu_cfg_count.inc();
    log_dev_preview_warning("User-defined CPU configuration", Option::None);

    // Convert the API request into a a deserialized/binary format
    let cpu_config =
        serde_json::from_slice::<CustomCpuConfiguration>(body.raw()).map_err(|err| {
            METRICS.put_api_requests.cpu_cfg_fails.inc();
            parsed_request::Error::SerdeJson(err)
        })?;

    Ok(ParsedRequest::new_sync(VmmAction::PutCpuConfiguration(
        cpu_config,
    )))
}

#[cfg(test)]
mod tests {
    use cpuid::{Cpuid, RawCpuid};
    use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
    use kvm_ioctls::Kvm;
    use logger::{IncMetric, METRICS};
    use micro_http::Body;
    use vmm::rpc_interface::VmmAction;

    use super::*;
    use crate::parsed_request::tests::vmm_action_from_request;

    #[test]
    fn test_parse_put_cpu_config_request() {
        let cpu_config = supported_cpu_config();
        let cpu_config_json_result = serde_json::to_string(&cpu_config);
        assert!(
            &cpu_config_json_result.is_ok(),
            "Unable to serialize CustomCpuConfiguration to JSON"
        );
        let cpu_config_json = cpu_config_json_result.unwrap();

        // Test that applying a CPU config is successful on x86_64 while on aarch64, it is not.
        {
            match vmm_action_from_request(
                parse_put_cpu_config(&Body::new(cpu_config_json.as_bytes())).unwrap(),
            ) {
                VmmAction::PutCpuConfiguration(received_cpu_config) => {
                    // Test that the CPU config to be used for KVM config is the
                    // the same that was read in from a test file.
                    assert_eq!(cpu_config, received_cpu_config);
                }
                _ => panic!("Test failed - Expected VmmAction::PutCpuConfiguration() call"),
            }
        }
    }

    /// Test basic API server validations like JSON sanity/legibility
    /// Any testing or validation done involving KVM or OS specific context
    /// need to be done in integration testing (api_cpu_configuration_integ_tests)
    #[test]
    fn test_parse_put_cpu_config_request_errors() {
        let mut expected_err_count = METRICS.put_api_requests.cpu_cfg_fails.count() + 1;

        // Test case for invalid payload
        let cpu_config_result = parse_put_cpu_config(&Body::new("<invalid_payload>"));
        assert!(cpu_config_result.is_err());
        assert_eq!(
            METRICS.put_api_requests.cpu_cfg_fails.count(),
            expected_err_count
        );
        expected_err_count += 1;

        // Test empty request fails
        assert!(parse_put_cpu_config(&Body::new(r#"{ }"#)).is_err());
        assert_eq!(
            METRICS.put_api_requests.cpu_cfg_fails.count(),
            expected_err_count
        );
    }

    fn supported_cpu_config() -> CustomCpuConfiguration {
        let kvm_result = Kvm::new();
        assert!(kvm_result.is_ok(), "Unable to access KVM");

        // Create descriptor KVM resource's file descriptor
        let vm_fd_result = kvm_result.as_ref().unwrap().create_vm();
        assert!(vm_fd_result.is_ok(), "{}", vm_fd_result.unwrap_err());

        let kvm_cpuid_result = kvm_result
            .unwrap()
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES);
        assert!(
            kvm_cpuid_result.is_ok(),
            "{}",
            kvm_cpuid_result.unwrap_err()
        );
        let kvm_cpuid = kvm_cpuid_result.unwrap();
        let raw_cpuid = RawCpuid::from(kvm_cpuid);
        let cpuid_result = Cpuid::try_from(raw_cpuid);
        assert!(cpuid_result.is_ok(), "{}", cpuid_result.unwrap_err());
        CustomCpuConfiguration {
            base_arch_config: cpuid_result.unwrap(),
        }
    }
}
