// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use logger::{IncMetric, METRICS};
use vm_guest_config::cpu::cpu_config::CpuConfigurationSet;

use super::super::VmmAction;
use crate::parsed_request::{Error, ParsedRequest};
use crate::request::Body;

pub(crate) fn parse_put_cpu_config(body: &Body) -> Result<ParsedRequest, Error> {
    METRICS.put_api_requests.cpu_cfg_count.inc();
    let cpu_config_json =
        serde_json::from_slice::<CpuConfigurationSet>(body.raw()).map_err(|err| {
            METRICS.put_api_requests.cpu_cfg_fails.inc();
            err
        })?;

    let cpu_config = CpuConfigurationSet::from(cpu_config_json);

    Ok(ParsedRequest::new_sync(VmmAction::PutCpuConfiguration(
        cpu_config,
    )))
}

pub(crate) fn parse_get_cpu_config() -> Result<ParsedRequest, Error> {
    METRICS.get_api_requests.cpu_cfg_count.inc();
    Ok(ParsedRequest::new_sync(VmmAction::GetCpuConfiguration))
}

#[cfg(test)]
mod tests {
    use cpuid::cpu_config::{CpuConfigurationAttribute, CpuConfigurationSet};

    use super::*;
    use crate::parsed_request::tests::vmm_action_from_request;

    #[test]
    fn test_parse_get_cpu_config_request() {
        assert!(parse_get_cpu_config().is_ok());
    }

    #[test]
    fn test_parse_put_cpu_config_request() {
        // Test case for invalid payload.
        assert!(parse_put_cpu_config(&Body::new("invalid_payload")).is_err());
        assert!(METRICS.put_api_requests.cpu_cfg_fails.count() > 0);

        // Test empty request is successful
        // let body = r#"{ }"#;
        // let expected_config = CpuConfiguration {
        //     cpu_features: vec![],
        // };
        //
        // match vmm_action_from_request(parse_put_cpu_config(&Body::new(body)).unwrap()) {
        //     VmmAction::PutCpuConfiguration(config) => assert_eq!(config, expected_config),
        //     _ => panic!("Test failed."),
        // }

        // Test basic request is successful
        let body = r#"{
              "cpu_features": [
                  {
                    "name": "ssbd",
                    "is_enabled": true
                  },
                  {
                    "name": "ibrs",
                    "is_enabled": true
                  }
                ]
            }"#;
        let expected_config = CpuConfigurationSet {
            cpu_features: vec![
                CpuConfigurationAttribute {
                    name: String::from("ssbd"),
                    is_enabled: true,
                },
                CpuConfigurationAttribute {
                    name: String::from("ibrs"),
                    is_enabled: true,
                },
            ],
        };

        match vmm_action_from_request(parse_put_cpu_config(&Body::new(body)).unwrap()) {
            VmmAction::PutCpuConfiguration(config) => assert_eq!(config, expected_config),
            _ => panic!("Test failed."),
        }

        // Test that applying a CPU config is successful on x86_64 while on aarch64, it is not.
        #[cfg(target_arch = "x86_64")]
        {
            match vmm_action_from_request(parse_put_cpu_config(&Body::new(body)).unwrap()) {
                VmmAction::PutCpuConfiguration(config) => assert_eq!(config, expected_config),
                _ => panic!("Test failed."),
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            assert!(parse_put_cpu_config(&Body::new(body)).is_err());
        }
    }
}
