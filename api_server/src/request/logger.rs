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
