// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::parsed_request::{Error, ParsedRequest};
use logger::{IncMetric, METRICS};

pub(crate) fn parse_get_config_changes() -> Result<ParsedRequest, Error> {
    METRICS.get_api_requests.config_changes_count.inc();
    Ok(ParsedRequest::GetConfigChanges)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_get_instance_info_request() {
        match parse_get_config_changes() {
            Ok(ParsedRequest::GetConfigChanges) => {}
            _ => panic!("Test failed."),
        }
    }
}
