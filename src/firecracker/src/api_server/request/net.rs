// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::logger::{IncMetric, METRICS};
use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::net::{NetworkInterfaceConfig, NetworkInterfaceUpdateConfig};

use super::super::parsed_request::{ParsedRequest, RequestError, checked_id};
use super::{Body, StatusCode};

pub(crate) fn parse_put_net(
    body: &Body,
    id_from_path: Option<&str>,
) -> Result<ParsedRequest, RequestError> {
    METRICS.put_api_requests.network_count.inc();
    let id = if let Some(id) = id_from_path {
        checked_id(id)?
    } else {
        METRICS.put_api_requests.network_fails.inc();
        return Err(RequestError::EmptyID);
    };

    let netif = serde_json::from_slice::<NetworkInterfaceConfig>(body.raw()).inspect_err(|_| {
        METRICS.put_api_requests.network_fails.inc();
    })?;
    if id != netif.iface_id.as_str() {
        METRICS.put_api_requests.network_fails.inc();
        return Err(RequestError::Generic(
            StatusCode::BadRequest,
            format!(
                "The id from the path [{}] does not match the id from the body [{}]!",
                id,
                netif.iface_id.as_str()
            ),
        ));
    }
    Ok(ParsedRequest::new_sync(VmmAction::InsertNetworkDevice(
        netif,
    )))
}

pub(crate) fn parse_patch_net(
    body: &Body,
    id_from_path: Option<&str>,
) -> Result<ParsedRequest, RequestError> {
    METRICS.patch_api_requests.network_count.inc();
    let id = if let Some(id) = id_from_path {
        checked_id(id)?
    } else {
        METRICS.patch_api_requests.network_count.inc();
        return Err(RequestError::EmptyID);
    };

    let netif =
        serde_json::from_slice::<NetworkInterfaceUpdateConfig>(body.raw()).inspect_err(|_| {
            METRICS.patch_api_requests.network_fails.inc();
        })?;
    if id != netif.iface_id {
        METRICS.patch_api_requests.network_count.inc();
        return Err(RequestError::Generic(
            StatusCode::BadRequest,
            format!(
                "The id from the path [{}] does not match the id from the body [{}]!",
                id,
                netif.iface_id.as_str()
            ),
        ));
    }
    Ok(ParsedRequest::new_sync(VmmAction::UpdateNetworkInterface(
        netif,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_server::parsed_request::tests::vmm_action_from_request;

    #[test]
    fn test_parse_put_net_request() {
        let body = r#"{
            "iface_id": "foo",
            "host_dev_name": "bar",
            "guest_mac": "12:34:56:78:9A:BC"
        }"#;
        // 1. Exercise infamous "The id from the path does not match id from the body!".
        parse_put_net(&Body::new(body), Some("bar")).unwrap_err();
        // 2. The `id_from_path` cannot be None.
        parse_put_net(&Body::new(body), None).unwrap_err();

        // 3. Success case.
        let expected_config = serde_json::from_str::<NetworkInterfaceConfig>(body).unwrap();
        assert_eq!(
            vmm_action_from_request(parse_put_net(&Body::new(body), Some("foo")).unwrap()),
            VmmAction::InsertNetworkDevice(expected_config)
        );

        // 4. Serde error for invalid field (bytes instead of bandwidth).
        let body = r#"{
            "iface_id": "foo",
            "rx_rate_limiter": {
                "bytes": {
                    "size": 62500,
                    "refill_time": 1000
                }
            },
            "tx_rate_limiter": {
                "bytes": {
                    "size": 62500,
                    "refill_time": 1000
                }
            }
        }"#;
        parse_put_net(&Body::new(body), Some("foo")).unwrap_err();
    }

    #[test]
    fn test_parse_patch_net_request() {
        let body = r#"{
            "iface_id": "foo",
            "rx_rate_limiter": {},
            "tx_rate_limiter": {}
        }"#;
        // 1. Exercise infamous "The id from the path does not match id from the body!".
        parse_patch_net(&Body::new(body), Some("bar")).unwrap_err();
        // 2. The `id_from_path` cannot be None.
        parse_patch_net(&Body::new(body), None).unwrap_err();

        // 3. Success case.
        let expected_config = serde_json::from_str::<NetworkInterfaceUpdateConfig>(body).unwrap();
        assert_eq!(
            vmm_action_from_request(parse_patch_net(&Body::new(body), Some("foo")).unwrap()),
            VmmAction::UpdateNetworkInterface(expected_config)
        );

        // 4. Serde error for invalid field (bytes instead of bandwidth).
        let body = r#"{
            "iface_id": "foo",
            "rx_rate_limiter": {
                "bytes": {
                    "size": 62500,
                    "refill_time": 1000
                }
            },
            "tx_rate_limiter": {
                "bytes": {
                    "size": 62500,
                    "refill_time": 1000
                }
            }
        }"#;
        parse_patch_net(&Body::new(body), Some("foo")).unwrap_err();
    }
}
