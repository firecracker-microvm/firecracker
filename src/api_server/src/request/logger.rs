// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::VmmAction;
use logger::{Metric, METRICS};
use request::{Body, Error, ParsedRequest};
use vmm::vmm_config::logger::LoggerConfig;

pub fn parse_put_logger(body: &Body) -> Result<ParsedRequest, Error> {
    METRICS.put_api_requests.logger_count.inc();
    Ok(ParsedRequest::Sync(VmmAction::ConfigureLogger(
        serde_json::from_slice::<LoggerConfig>(body.raw()).map_err(|e| {
            METRICS.put_api_requests.logger_fails.inc();
            Error::SerdeJson(e)
        })?,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vmm::vmm_config::logger::LoggerLevel;

    #[test]
    fn test_parse_logger_request() {
        let body = r#"{
                "log_fifo": "log",
                "metrics_fifo": "metrics",
                "level": "Warning",
                "show_level": false,
                "show_log_origin": false
              }"#;

        let desc_clone = LoggerConfig {
            log_fifo: String::from("log"),
            metrics_fifo: String::from("metrics"),
            level: LoggerLevel::Warning,
            show_level: false,
            show_log_origin: false,
        };
        match parse_put_logger(&Body::new(body)) {
            Ok(ParsedRequest::Sync(VmmAction::ConfigureLogger(desc))) => {
                assert_eq!(desc, desc_clone)
            }
            _ => panic!("Test failed."),
        }
    }
}
