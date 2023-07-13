// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use logger::{IncMetric, METRICS};
use vmm::vmm_config::metrics::MetricsConfig;

use super::super::VmmAction;
use crate::parsed_request::{Error, ParsedRequest};

pub(crate) fn parse_put_metrics(body: serde_json::Value) -> Result<ParsedRequest, Error> {
    METRICS.put_api_requests.metrics_count.inc();
    Ok(ParsedRequest::new_sync(VmmAction::ConfigureMetrics(
        serde_json::from_value::<MetricsConfig>(body).map_err(|err| {
            METRICS.put_api_requests.metrics_fails.inc();
            err
        })?,
    )))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde_json::json;

    use super::*;
    use crate::parsed_request::tests::vmm_action_from_request;

    #[test]
    fn test_parse_put_metrics_request() {
        let body = json!({
          "metrics_path": "metrics"
        });

        let expected_cfg = MetricsConfig {
            metrics_path: PathBuf::from("metrics"),
        };
        match vmm_action_from_request(parse_put_metrics(body).unwrap()) {
            VmmAction::ConfigureMetrics(cfg) => assert_eq!(cfg, expected_cfg),
            _ => panic!("Test failed."),
        }

        let invalid_body = json!({
          "invalid_field": "metrics"
        });

        assert!(parse_put_metrics(invalid_body).is_err());
    }
}
