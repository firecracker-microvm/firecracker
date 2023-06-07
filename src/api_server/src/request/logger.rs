// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use logger::{IncMetric, METRICS};
use vmm::vmm_config::LoggerConfig;

use super::super::VmmAction;
use crate::parsed_request::{Error, ParsedRequest};
use crate::request::Body;

pub(crate) fn parse_put_logger(body: &Body) -> Result<ParsedRequest, Error> {
    METRICS.put_api_requests.logger_count.inc();
    Ok(ParsedRequest::new_sync(VmmAction::ConfigureLogger(
        serde_json::from_slice::<LoggerConfig>(body.raw()).map_err(|err| {
            METRICS.put_api_requests.logger_fails.inc();
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
    fn test_parse_put_logger_request() {
        let mut body = r#"{
                "log_path": "log",
                "level": "Warn",
                "show_level": false,
                "show_log_origin": false
              }"#;

        let mut expected_cfg = LoggerConfig {
            log_path: Some(PathBuf::from("log")),
            level: Some(log::Level::Warn),
            show_level: Some(false),
            show_log_origin: Some(false),
            profile_file: None,
        };
        match vmm_action_from_request(parse_put_logger(&Body::new(body)).unwrap()) {
            VmmAction::ConfigureLogger(cfg) => assert_eq!(cfg, expected_cfg),
            _ => panic!("Test failed."),
        }

        body = r#"{
                "log_path": "log",
                "level": "Debug",
                "show_level": false,
                "show_log_origin": false
              }"#;

        expected_cfg = LoggerConfig {
            log_path: Some(PathBuf::from("log")),
            level: Some(log::Level::Debug),
            show_level: Some(false),
            show_log_origin: Some(false),
            profile_file: None,
        };
        match vmm_action_from_request(parse_put_logger(&Body::new(body)).unwrap()) {
            VmmAction::ConfigureLogger(cfg) => assert_eq!(cfg, expected_cfg),
            _ => panic!("Test failed."),
        }

        let invalid_body = r#"{
                "invalid_field": "log",
                "level": "Warn",
                "show_level": false,
                "show_log_origin": false
              }"#;

        assert!(parse_put_logger(&Body::new(invalid_body)).is_err());
    }
}
