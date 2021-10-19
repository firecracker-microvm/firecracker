// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::parsed_request::{Error, ParsedRequest};
use logger::{IncMetric, METRICS};
use vmm::rpc_interface::VmmAction;

pub(crate) fn parse_get_version() -> Result<ParsedRequest, Error> {
    METRICS.get_api_requests.vmm_version_count.inc();
    Ok(ParsedRequest::new_sync(VmmAction::GetVmmVersion))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_get_version_request() {
        match parse_get_version() {
            Ok(ParsedRequest::Sync(action)) if *action == VmmAction::GetVmmVersion => {}
            _ => panic!("Test failed."),
        }
    }
}
