// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::logger::{IncMetric, METRICS};
use vmm::rpc_interface::VmmAction;

use super::super::parsed_request::{ParsedRequest, RequestError};
use super::Body;

pub(crate) fn parse_put_logger(body: &Body) -> Result<ParsedRequest, RequestError> {
    METRICS.put_api_requests.logger_count.inc();
    let res = serde_json::from_slice::<vmm::logger::LoggerConfig>(body.raw());
    let config = res.inspect_err(|_| {
        METRICS.put_api_requests.logger_fails.inc();
    })?;
    Ok(ParsedRequest::new_sync(VmmAction::ConfigureLogger(config)))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use vmm::logger::{LevelFilter, LoggerConfig};

    use super::*;
    use crate::api_server::parsed_request::tests::vmm_action_from_request;

    #[test]
    fn test_parse_put_logger_request() {
        let body = r#"{
                "log_path": "log",
                "level": "Warning",
                "show_level": false,
                "show_log_origin": false
              }"#;

        let expected_config = LoggerConfig {
            log_path: Some(PathBuf::from("log")),
            level: Some(LevelFilter::Warn),
            show_level: Some(false),
            show_log_origin: Some(false),
            module: None,
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
            log_path: Some(PathBuf::from("log")),
            level: Some(LevelFilter::Debug),
            show_level: Some(false),
            show_log_origin: Some(false),
            module: None,
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
        parse_put_logger(&Body::new(invalid_body)).unwrap_err();
    }
}
