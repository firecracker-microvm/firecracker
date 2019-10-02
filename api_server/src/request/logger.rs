// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::result;

use futures::sync::oneshot;
use hyper::Method;

use request::{IntoParsedRequest, ParsedRequest};
use vmm::vmm_config::logger::LoggerConfig;
use vmm::{VmmAction, VmmRequest};

impl IntoParsedRequest for LoggerConfig {
    fn into_parsed_request(
        self,
        _: Option<String>,
        _: Method,
    ) -> result::Result<ParsedRequest, String> {
        let (sender, receiver) = oneshot::channel();
        Ok(ParsedRequest::Sync(
            VmmRequest::new(VmmAction::ConfigureLogger(self), sender),
            receiver,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_arch = "x86_64")]
    use serde_json::Value;
    use vmm::vmm_config::logger::LoggerLevel;

    #[test]
    fn test_into_parsed_request() {
        let desc = LoggerConfig {
            log_fifo: String::from("log"),
            metrics_fifo: String::from("metrics"),
            level: LoggerLevel::Warning,
            show_level: false,
            show_log_origin: false,
            #[cfg(target_arch = "x86_64")]
            options: Value::Array(vec![]),
        };
        format!("{:?}", desc);
        assert!(&desc.clone().into_parsed_request(None, Method::Put).is_ok());
        let (sender, receiver) = oneshot::channel();
        assert!(&desc
            .clone()
            .into_parsed_request(None, Method::Put)
            .eq(&Ok(ParsedRequest::Sync(
                VmmRequest::new(VmmAction::ConfigureLogger(desc), sender),
                receiver
            ))));
    }
}
