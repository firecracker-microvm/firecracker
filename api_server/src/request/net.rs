// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::VmmAction;
use logger::{Metric, METRICS};
use request::Body;
use request::Error;
use request::StatusCode;

use request::checked_id;
use request::ParsedRequest;
use vmm::vmm_config::net::{NetworkInterfaceConfig, NetworkInterfaceUpdateConfig};

pub fn parse_put_net(
    maybe_body: Option<&Body>,
    id_from_path: Option<&&str>,
) -> Result<ParsedRequest, Error> {
    METRICS.patch_api_requests.network_count.inc();
    let id = match id_from_path {
        Some(&id) => checked_id(id)?,
        None => {
            return Err(Error::EmptyID);
        }
    };

    if let Some(body) = maybe_body {
        let netif = serde_json::from_slice::<NetworkInterfaceConfig>(body.raw()).map_err(|e| {
            METRICS.put_api_requests.network_fails.inc();
            Error::SerdeJson(e)
        })?;
        if id != netif.iface_id.as_str() {
            return Err(Error::Generic(
                StatusCode::BadRequest,
                "The id from the path does not match the id from the body!".to_string(),
            ));
        }
        Ok(ParsedRequest::Sync(VmmAction::InsertNetworkDevice(netif)))
    } else {
        Err(Error::Generic(
            StatusCode::BadRequest,
            "Empty PUT request.".to_string(),
        ))
    }
}

pub fn parse_patch_net(
    maybe_body: Option<&Body>,
    id_from_path: Option<&&str>,
) -> Result<ParsedRequest, Error> {
    METRICS.put_api_requests.network_count.inc();
    let id = match id_from_path {
        Some(&id) => checked_id(id)?,
        None => {
            return Err(Error::EmptyID);
        }
    };

    if let Some(body) = maybe_body {
        let netif =
            serde_json::from_slice::<NetworkInterfaceUpdateConfig>(body.raw()).map_err(|e| {
                METRICS.patch_api_requests.network_fails.inc();
                Error::SerdeJson(e)
            })?;
        if id != netif.iface_id {
            return Err(Error::Generic(
                StatusCode::BadRequest,
                "The id from the path does not match the id from the body!".to_string(),
            ));
        }
        Ok(ParsedRequest::Sync(VmmAction::UpdateNetworkInterface(
            netif,
        )))
    } else {
        Err(Error::Generic(
            StatusCode::BadRequest,
            "Empty PATCH request.".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    extern crate net_util;
    extern crate vmm;

    use self::net_util::MacAddr;
    use super::*;

    use serde_json;

    use self::vmm::vmm_config::RateLimiterConfig;

    fn get_dummy_netif(
        iface_id: String,
        host_dev_name: String,
        mac: &str,
    ) -> NetworkInterfaceConfig {
        NetworkInterfaceConfig {
            iface_id,
            host_dev_name,
            guest_mac: Some(MacAddr::parse_str(mac).unwrap()),
            rx_rate_limiter: None,
            tx_rate_limiter: None,
            allow_mmds_requests: false,
        }
    }

    #[test]
    fn test_parse_netif_request() {
        let body = r#"{
                "iface_id": "foo",
                "host_dev_name": "bar",
                "guest_mac": "12:34:56:78:9A:BC",
                "allow_mmds_requests": false
              }"#;
        assert!(parse_put_net(Some(&Body::new(body)), Some(&"bar")).is_err());
        assert!(parse_put_net(Some(&Body::new(body)), Some(&"foo")).is_ok());

        let netif_clone = get_dummy_netif(
            String::from("foo"),
            String::from("bar"),
            "12:34:56:78:9A:BC",
        );
        match parse_put_net(Some(&Body::new(body)), Some(&"foo")) {
            Ok(ParsedRequest::Sync(VmmAction::InsertNetworkDevice(netif))) => {
                assert_eq!(netif, netif_clone)
            }
            _ => panic!("Test failed."),
        }
    }

    #[test]
    fn test_network_interface_body_serialization_and_deserialization() {
        let netif_clone = NetworkInterfaceConfig {
            iface_id: String::from("foo"),
            host_dev_name: String::from("bar"),
            guest_mac: Some(MacAddr::parse_str("12:34:56:78:9A:BC").unwrap()),
            rx_rate_limiter: Some(RateLimiterConfig::default()),
            tx_rate_limiter: Some(RateLimiterConfig::default()),
            allow_mmds_requests: true,
        };

        // This is the json encoding of the netif variable.
        let body = r#"{
            "iface_id": "foo",
            "host_dev_name": "bar",
            "guest_mac": "12:34:56:78:9A:bc",
            "rx_rate_limiter": {
            },
            "tx_rate_limiter": {
            },
            "allow_mmds_requests": true
        }"#;

        match parse_put_net(Some(&Body::new(body)), Some(&"foo")) {
            Ok(ParsedRequest::Sync(VmmAction::InsertNetworkDevice(netif))) => {
                assert_eq!(netif, netif_clone)
            }
            _ => panic!("Test failed."),
        }

        // Check that guest_mac and rate limiters are truly optional.
        let body_no_mac = r#"{
            "iface_id": "foo",
            "host_dev_name": "bar"
        }"#;

        assert!(serde_json::from_str::<NetworkInterfaceConfig>(body_no_mac).is_ok());

        assert!(parse_put_net(None, Some(&"foo")).is_err());
        assert!(parse_patch_net(None, Some(&"foo")).is_err());

        assert!(parse_put_net(Some(&Body::new(body)), Some(&"bar")).is_err());
        assert!(parse_patch_net(Some(&Body::new(body)), Some(&"bar")).is_err());
    }
}
