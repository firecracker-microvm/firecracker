// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::api_server::parsed_request::{Error, ParsedRequest};
use crate::logger::{IncMetric, METRICS};
use crate::vmm::rpc_interface::VmmAction;

pub(crate) fn parse_get_version() -> Result<ParsedRequest, Error> {
    METRICS.get_api_requests.vmm_version_count.inc();
    Ok(ParsedRequest::new_sync(VmmAction::GetVmmVersion))
}

#[cfg(test)]
mod tests {
    use super::super::super::RequestAction;
    use super::*;

    #[test]
    fn test_parse_get_version_request() {
        match parse_get_version().unwrap().into_parts() {
            (RequestAction::Sync(action), _) if *action == VmmAction::GetVmmVersion => {}
            _ => panic!("Test failed."),
        }
    }
}
