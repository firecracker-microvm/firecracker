// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::cpu_config::templates::CustomCpuTemplate;
use vmm::logger::{IncMetric, METRICS};

use super::super::VmmAction;
use crate::parsed_request::{Error, ParsedRequest};
use crate::request::Body;

pub(crate) fn parse_put_cpu_config(body: &Body) -> Result<ParsedRequest, Error> {
    METRICS.put_api_requests.cpu_cfg_count.inc();

    // Convert the API request into a a deserialized/binary format
    Ok(ParsedRequest::new_sync(VmmAction::PutCpuConfiguration(
        CustomCpuTemplate::try_from(body.raw()).map_err(|err| {
            METRICS.put_api_requests.cpu_cfg_fails.inc();
            Error::SerdeJson(err)
        })?,
    )))
}

#[cfg(test)]
mod tests {
    use micro_http::Body;
    use vmm::cpu_config::templates::test_utils::{build_test_template, TEST_INVALID_TEMPLATE_JSON};
    use vmm::logger::{IncMetric, METRICS};
    use vmm::rpc_interface::VmmAction;

    use super::*;
    use crate::parsed_request::tests::vmm_action_from_request;

    #[test]
    fn test_parse_put_cpu_config_request() {
        let cpu_template = build_test_template();
        let cpu_config_json_result = serde_json::to_string(&cpu_template);
        assert!(
            &cpu_config_json_result.is_ok(),
            "Unable to serialize CPU template to JSON"
        );
        let cpu_template_json = cpu_config_json_result.unwrap();

        // Test that the CPU config to be used for KVM config is the same that
        // was read in from a test file.
        assert_eq!(
            vmm_action_from_request(
                parse_put_cpu_config(&Body::new(cpu_template_json.as_bytes())).unwrap()
            ),
            VmmAction::PutCpuConfiguration(cpu_template)
        );

        // Test empty request succeeds
        let parse_cpu_config_result = parse_put_cpu_config(&Body::new(r#"{ }"#));
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
        let unparsable_cpu_config_result =
            parse_put_cpu_config(&Body::new("<unparseable_payload>"));
        assert!(unparsable_cpu_config_result.is_err());
        assert_eq!(
            METRICS.put_api_requests.cpu_cfg_fails.count(),
            expected_err_count
        );

        // Test request with invalid fields
        let invalid_put_result = parse_put_cpu_config(&Body::new(TEST_INVALID_TEMPLATE_JSON));
        expected_err_count += 1;

        assert!(invalid_put_result.is_err());
        assert_eq!(
            METRICS.put_api_requests.cpu_cfg_fails.count(),
            expected_err_count
        );
        assert!(matches!(invalid_put_result, Err(Error::SerdeJson(_))));
    }
}
