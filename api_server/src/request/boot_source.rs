// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::VmmAction;
use logger::{Metric, METRICS};
use request::{Body, Error, ParsedRequest};
use vmm::vmm_config::boot_source::BootSourceConfig;

pub fn parse_put_boot_source(body: &Body) -> Result<ParsedRequest, Error> {
    METRICS.put_api_requests.boot_source_count.inc();
    Ok(ParsedRequest::Sync(VmmAction::ConfigureBootSource(
        serde_json::from_slice::<BootSourceConfig>(body.raw()).map_err(|e| {
            METRICS.put_api_requests.boot_source_fails.inc();
            Error::SerdeJson(e)
        })?,
    )))
}
