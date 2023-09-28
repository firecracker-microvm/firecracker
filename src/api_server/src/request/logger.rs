// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::logger::{IncMetric, METRICS};
use vmm::vmm_config::logger_config::LoggerConfig;

use super::super::VmmAction;
use crate::parsed_request::{Error, ParsedRequest};
use crate::request::Body;

pub(crate) fn parse_put_logger(body: &Body) -> Result<ParsedRequest, Error> {
    METRICS.put_api_requests.logger_count.inc();
    let res = serde_json::from_slice::<LoggerConfig>(body.raw());
    let config = res.map_err(|err| {
        METRICS.put_api_requests.logger_fails.inc();
        err
    })?;
    Ok(ParsedRequest::new_sync(VmmAction::ConfigureLogger(config)))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use vmm::vmm_config::logger_config::LoggerLevel;

    use super::*;
    use crate::parsed_request::tests::vmm_action_from_request;

    #[test]
    fn test_parse_put_logger_request() {
        let body = r#"{
            "log_path": "log",
            "level": "Warning",
            "show_level": false,
            "show_log_origin": false
        }"#;
        let expected_config = LoggerConfig {
            log_path: PathBuf::from("log"),
            level: LoggerLevel::Warning,
            show_level: false,
            show_log_origin: false,
        };
        assert_eq!(
            vmm_action_from_request(parse_put_logger(&Body::new(body)).unwrap()),
            VmmAction::ConfigureLogger(expected_config)
        );

        let body = r#"{
            "log_path": "log",
            "level": "DEBUG",
            "show_level": false,
            "show_log_origin": false
        }"#;
        let expected_config = LoggerConfig {
            log_path: PathBuf::from("log"),
            level: LoggerLevel::Debug,
            show_level: false,
            show_log_origin: false,
        };
        assert_eq!(
            vmm_action_from_request(parse_put_logger(&Body::new(body)).unwrap()),
            VmmAction::ConfigureLogger(expected_config)
        );

        let invalid_body = r#"{
            "invalid_field": "log",
            "level": "Warning",
            "show_level": false,
            "show_log_origin": false
        }"#;
        assert!(parse_put_logger(&Body::new(invalid_body)).is_err());
    }
}
