// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use vmm::logger::{IncMetric, METRICS};
use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::hotplug::HotplugRequestConfig;

use super::super::parsed_request::{ParsedRequest, RequestError};
use super::Body;

pub(crate) fn parse_put_hotplug(body: &Body) -> Result<ParsedRequest, RequestError> {
    METRICS.put_api_requests.hotplug.inc();
    METRICS.hotplug.hotplug_request_count.inc();
    let config = serde_json::from_slice::<HotplugRequestConfig>(body.raw()).map_err(|err| {
        METRICS.hotplug.hotplug_request_fails.inc();
        err
    })?;
    Ok(ParsedRequest::new_sync(VmmAction::HotplugRequest(config)))
}

#[cfg(test)]
mod tests {

    use hotplug::parse_put_hotplug;
    use vmm::rpc_interface::VmmAction;
    use vmm::vmm_config::hotplug::{HotplugRequestConfig, HotplugVcpuConfig};

    use super::super::*;
    use crate::api_server::parsed_request::tests::vmm_action_from_request;

    #[test]
    fn test_parse_put_hotplug() {
        // Case 1. Invalid body
        parse_put_hotplug(&Body::new("invalid body")).unwrap_err();

        // Case 2. vCPU Resource
        let body = r#"{
            "Vcpu" : { "add": 4 }
        }"#;

        let expected_config = HotplugVcpuConfig { add: 4 };

        assert_eq!(
            vmm_action_from_request(parse_put_hotplug(&Body::new(body)).unwrap()),
            VmmAction::HotplugRequest(HotplugRequestConfig::Vcpu(expected_config))
        );
    }
}
