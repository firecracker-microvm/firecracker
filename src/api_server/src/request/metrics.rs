// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::logger::{IncMetric, METRICS};
use vmm::vmm_config::metrics::MetricsConfig;

use super::super::VmmAction;
use crate::parsed_request::{Error, ParsedRequest};
use crate::request::Body;

pub(crate) fn parse_put_metrics(body: &Body) -> Result<ParsedRequest, Error> {
    METRICS.put_api_requests.metrics_count.inc();
    Ok(ParsedRequest::new_sync(VmmAction::ConfigureMetrics(
        serde_json::from_slice::<MetricsConfig>(body.raw()).map_err(|err| {
            METRICS.put_api_requests.metrics_fails.inc();
            err
        })?,
    )))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::parsed_request::tests::vmm_action_from_request;

    #[test]
    fn test_parse_put_metrics_request() {
        let body = r#"{
            "metrics_path": "metrics"
        }"#;
        let expected_config = MetricsConfig {
            metrics_path: PathBuf::from("metrics"),
        };
        assert_eq!(
            vmm_action_from_request(parse_put_metrics(&Body::new(body)).unwrap()),
            VmmAction::ConfigureMetrics(expected_config)
        );

        let invalid_body = r#"{
            "invalid_field": "metrics"
        }"#;
        assert!(parse_put_metrics(&Body::new(invalid_body)).is_err());
    }
}
