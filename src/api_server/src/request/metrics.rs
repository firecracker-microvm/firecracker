// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::VmmAction;
use logger::{Metric, METRICS};
use request::{Body, Error, ParsedRequest};
use vmm::vmm_config::metrics::MetricsConfig;

pub fn parse_put_metrics(body: &Body) -> Result<ParsedRequest, Error> {
    METRICS.put_api_requests.metrics_count.inc();
    Ok(ParsedRequest::Sync(VmmAction::ConfigureMetrics(
        serde_json::from_slice::<MetricsConfig>(body.raw()).map_err(|e| {
            METRICS.put_api_requests.metrics_fails.inc();
            Error::SerdeJson(e)
        })?,
    )))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn test_parse_put_metrics_request() {
        let body = r#"{
                "metrics_path": "metrics"
              }"#;

        let expected_cfg = MetricsConfig {
            metrics_path: PathBuf::from("metrics"),
        };
        match parse_put_metrics(&Body::new(body)) {
            Ok(ParsedRequest::Sync(VmmAction::ConfigureMetrics(cfg))) => {
                assert_eq!(cfg, expected_cfg)
            }
            _ => panic!("Test failed."),
        }

        let invalid_body = r#"{
                "invalid_field": "metrics"
              }"#;

        assert!(parse_put_metrics(&Body::new(invalid_body)).is_err());
    }
}
