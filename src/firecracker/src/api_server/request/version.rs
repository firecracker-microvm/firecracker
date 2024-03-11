// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::logger::{IncMetric, METRICS};
use vmm::rpc_interface::VmmAction;

use super::super::parsed_request::{ParsedRequest, RequestError};

pub(crate) fn parse_get_version() -> Result<ParsedRequest, RequestError> {
    METRICS.get_api_requests.vmm_version_count.inc();
    Ok(ParsedRequest::new_sync(VmmAction::GetVmmVersion))
}

#[cfg(test)]
mod tests {
    use super::super::super::parsed_request::RequestAction;
    use super::*;

    #[test]
    fn test_parse_get_version_request() {
        match parse_get_version().unwrap().into_parts() {
            (RequestAction::Sync(action), _) if *action == VmmAction::GetVmmVersion => {}
            _ => panic!("Test failed."),
        }
    }
}
