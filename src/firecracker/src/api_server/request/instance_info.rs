// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::logger::{IncMetric, METRICS};
use vmm::rpc_interface::VmmAction;

use super::super::parsed_request::{ParsedRequest, RequestError};

pub(crate) fn parse_get_instance_info() -> Result<ParsedRequest, RequestError> {
    METRICS.get_api_requests.instance_info_count.inc();
    Ok(ParsedRequest::new_sync(VmmAction::GetVmInstanceInfo))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_server::parsed_request::RequestAction;

    #[test]
    fn test_parse_get_instance_info_request() {
        match parse_get_instance_info().unwrap().into_parts() {
            (RequestAction::Sync(action), _) if *action == VmmAction::GetVmInstanceInfo => {}
            _ => panic!("Test failed."),
        }
    }
}
