// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use guest_config::cpu::cpu_config::CustomCpuConfigurationApiRequest;
use guest_config::{deserialize_configuration_request, GuestConfigurationError};
use logger::{IncMetric, METRICS};
use micro_http::StatusCode;

use super::super::VmmAction;
use crate::parsed_request::{Error, ParsedRequest};
use crate::request::Body;

pub(crate) fn parse_put_cpu_config(body: &Body) -> Result<ParsedRequest, Error> {
    METRICS.put_api_requests.cpu_cfg_count.inc();
    let cpu_config_request = serde_json::from_slice::<CustomCpuConfigurationApiRequest>(body.raw())
        .map_err(|err| {
            METRICS.put_api_requests.cpu_cfg_fails.inc();
            err
        })?;

    // TODO check file extensions in API request before compiling. If already binary, do nothing.
    let cpu_configuration =
        deserialize_configuration_request(&cpu_config_request).map_err(|err| match err {
            GuestConfigurationError::JsonError(err) => crate::parsed_request::Error::SerdeJson(err),
            _ => {
                crate::parsed_request::Error::Generic(StatusCode::BadRequest, format!("{:?}", err))
            }
        })?;
    Ok(ParsedRequest::new_sync(VmmAction::PutCpuConfiguration(
        cpu_configuration,
    )))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use guest_config::cpu::cpu_config::{CpuConfigurationAttribute, CustomCpuConfiguration};
    use logger::{IncMetric, METRICS};
    use micro_http::Body;
    use tempfile::Builder;
    use vmm::rpc_interface::VmmAction;

    use super::*;
    use crate::parsed_request::tests::vmm_action_from_request;

    #[test]
    fn test_parse_put_cpu_config_request_errors() {
        // Test case for invalid payload
        let cpu_config_result = parse_put_cpu_config(&Body::new("<invalid_payload>"));
        assert!(cpu_config_result.is_err());
        assert!(METRICS.put_api_requests.cpu_cfg_fails.count() > 0);

        // Test empty request fails
        assert!(parse_put_cpu_config(&Body::new(r#"{ }"#)).is_err());
    }

    #[test]
    fn test_parse_put_cpu_config_request() {
        // Write test cpuid snapshot
        let cpuid_tempfile = Builder::new()
            .prefix("cpuid-test")
            .suffix(".bin")
            .tempfile()
            .expect("Failed to create temporary file for testing CPUID");
        let cpuid_file_path =
            fs::canonicalize(cpuid_tempfile.path()).expect("Retrieving tempfile path required.");
        let path_str = cpuid_file_path
            .to_str()
            .expect("Error retrieving file path.");

        let write_snapshot_result = guest_config::snapshot_local_cpu_features(path_str);
        assert!(write_snapshot_result.is_ok());

        // Test basic request is successful
        let config_request_string = get_correct_json_input(Some(String::from(path_str)));
        let expected_config = CustomCpuConfiguration {
            base_arch_features_configuration: write_snapshot_result.unwrap(),
            cpu_feature_overrides: vec![
                CpuConfigurationAttribute {
                    name: String::from("ssbd"),
                    is_enabled: false,
                },
                CpuConfigurationAttribute {
                    name: String::from("ibrs"),
                    is_enabled: true,
                },
            ],
        };

        match vmm_action_from_request(
            parse_put_cpu_config(&Body::new(config_request_string.as_str())).unwrap(),
        ) {
            VmmAction::PutCpuConfiguration(config) => assert_eq!(config, expected_config),
            _ => panic!("Test failed - Expected VmmAction::PutCpuConfiguration() call"),
        }

        // Test that applying a CPU config is successful on x86_64 while on aarch64, it is not.
        #[cfg(target_arch = "x86_64")]
        {
            match vmm_action_from_request(
                parse_put_cpu_config(&Body::new(config_request_string.as_str())).unwrap(),
            ) {
                VmmAction::PutCpuConfiguration(config) => assert_eq!(config, expected_config),
                _ => panic!("Test failed - Expected VmmAction::PutCpuConfiguration() call"),
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            assert!(parse_put_cpu_config(&Body::new(body)).is_err());
        }
    }

    // test helper for generating correct JSON input data
    fn get_correct_json_input(arch_features_file_path: Option<String>) -> String {
        format!(
            r#"
        {{
          "base_arch_features_template_path": "{}",
          "cpu_feature_overrides": [
            {{
              "name" : "ssbd",
              "is_enabled" : false
            }},
            {{
              "name" : "ibrs",
              "is_enabled" : true
            }}
          ]
        }}
        "#,
            arch_features_file_path.unwrap_or(String::from("/tmp/cpuid-test.json"))
        )
    }
}
