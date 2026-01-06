// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::logger::{IncMetric, METRICS};
use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::metrics::MetricsSpec;

use super::super::parsed_request::{ParsedRequest, RequestError};
use super::Body;

pub(crate) fn parse_put_metrics(body: &Body) -> Result<ParsedRequest, RequestError> {
    METRICS.put_api_requests.metrics_count.inc();
    Ok(ParsedRequest::new_stateless(
        VmmAction::ConfigureMetrics,
        serde_json::from_slice::<MetricsSpec>(body.raw()).inspect_err(|_| {
            METRICS.put_api_requests.metrics_fails.inc();
        })?,
    ))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::api_server::parsed_request::tests::vmm_action_from_request;

    #[test]
    fn test_parse_put_metrics_request() {
        let body = r#"{
            "metrics_path": "metrics"
        }"#;
        let expected_spec = MetricsSpec {
            metrics_path: PathBuf::from("metrics"),
        };
        assert_eq!(
            vmm_action_from_request(parse_put_metrics(&Body::new(body)).unwrap()),
            VmmAction::ConfigureMetrics(expected_spec)
        );

        let invalid_body = r#"{
            "invalid_field": "metrics"
        }"#;
        parse_put_metrics(&Body::new(invalid_body)).unwrap_err();
    }
}
