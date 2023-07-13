// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use logger::{IncMetric, METRICS};
use vmm::cpu_config::templates::CustomCpuTemplate;

use super::super::VmmAction;
use crate::parsed_request::{Error, ParsedRequest};

pub(crate) fn parse_put_cpu_config(body: serde_json::Value) -> Result<ParsedRequest, Error> {
    METRICS.put_api_requests.cpu_cfg_count.inc();

    // Convert the API request into a a deserialized/binary format
    Ok(ParsedRequest::new_sync(VmmAction::PutCpuConfiguration(
        CustomCpuTemplate::try_from(body.to_string().as_str()).map_err(|err| {
            METRICS.put_api_requests.cpu_cfg_fails.inc();
            Error::SerdeJson(err)
        })?,
    )))
}

#[cfg(test)]
mod tests {
    use logger::{IncMetric, METRICS};
    use serde_json::json;
    use vmm::cpu_config::templates::test_utils::{build_test_template, TEST_INVALID_TEMPLATE_JSON};
    use vmm::rpc_interface::VmmAction;

    use super::*;
    use crate::parsed_request::tests::vmm_action_from_request;

    #[test]
    fn test_parse_put_cpu_config_request() {
        let cpu_template = build_test_template();
        let cpu_template_json =
            serde_json::to_value(&cpu_template).expect("Unable to serialize CPU template to JSON");

        {
            match vmm_action_from_request(parse_put_cpu_config(cpu_template_json).unwrap()) {
                VmmAction::PutCpuConfiguration(received_cpu_template) => {
                    // Test that the CPU config to be used for KVM config is the
                    // the same that was read in from a test file.
                    assert_eq!(cpu_template, received_cpu_template);
                }
                _ => panic!("Test failed - Expected VmmAction::PutCpuConfiguration() call"),
            }
        }

        // Test empty request succeeds
        let parse_cpu_config_result = parse_put_cpu_config(json!({}));
        assert!(
            parse_cpu_config_result.is_ok(),
            "Failed to parse cpu-config: [{}]",
            parse_cpu_config_result.unwrap_err()
        );
    }

    /// Test basic API server validations like JSON sanity/legibility
    /// Any testing or validation done involving KVM or OS specific context
    /// need to be done in integration testing (api_cpu_configuration_integ_tests)
    #[test]
    fn test_parse_put_cpu_config_request_errors() {
        let mut expected_err_count = METRICS.put_api_requests.cpu_cfg_fails.count() + 1;

        // Test case for invalid payload
        let unparsable_cpu_config_result = parse_put_cpu_config(serde_json::Value::Null);
        assert!(unparsable_cpu_config_result.is_err());
        assert_eq!(
            METRICS.put_api_requests.cpu_cfg_fails.count(),
            expected_err_count
        );

        // Test request with invalid fields
        let body = serde_json::to_value(TEST_INVALID_TEMPLATE_JSON).unwrap();
        let invalid_put_result = parse_put_cpu_config(body);
        expected_err_count += 1;

        assert!(invalid_put_result.is_err());
        assert_eq!(
            METRICS.put_api_requests.cpu_cfg_fails.count(),
            expected_err_count
        );
        assert!(matches!(invalid_put_result, Err(Error::SerdeJson(_))));
    }
}
