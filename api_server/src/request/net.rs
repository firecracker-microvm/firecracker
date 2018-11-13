use std::result;

use futures::sync::oneshot;
use hyper::Method;

use request::{IntoParsedRequest, ParsedRequest};
use vmm::vmm_config::net::NetworkInterfaceConfig;
use vmm::VmmAction;

impl IntoParsedRequest for NetworkInterfaceConfig {
    fn into_parsed_request(
        self,
        id_from_path: Option<String>,
        _: Method,
    ) -> result::Result<ParsedRequest, String> {
        let id_from_path = id_from_path.unwrap_or(String::new());
        if id_from_path != self.iface_id {
            return Err(String::from(
                "The id from the path does not match the id from the body!",
            ));
        }

        let (sender, receiver) = oneshot::channel();
        Ok(ParsedRequest::Sync(
            VmmAction::InsertNetworkDevice(self, sender),
            receiver,
        ))
    }
}

#[cfg(test)]
mod tests {
    extern crate net_util;
    extern crate rate_limiter;

    use self::net_util::MacAddr;
    use super::*;

    use serde_json;

    use self::rate_limiter::RateLimiter;
    use vmm::vmm_config::DeviceState;

    fn get_dummy_netif(
        iface_id: String,
        host_dev_name: String,
        mac: &str,
    ) -> NetworkInterfaceConfig {
        NetworkInterfaceConfig {
            iface_id,
            state: DeviceState::Attached,
            host_dev_name,
            guest_mac: Some(MacAddr::parse_str(mac).unwrap()),
            rx_rate_limiter: None,
            tx_rate_limiter: None,
            allow_mmds_requests: false,
            tap: None,
        }
    }

    #[test]
    fn test_netif_into_parsed_request() {
        let netif = get_dummy_netif(
            String::from("foo"),
            String::from("bar"),
            "12:34:56:78:9A:BC",
        );
        assert!(
            netif
                .into_parsed_request(Some(String::from("bar")), Method::Put)
                .is_err()
        );

        let (sender, receiver) = oneshot::channel();
        let netif = get_dummy_netif(
            String::from("foo"),
            String::from("bar"),
            "12:34:56:78:9A:BC",
        );
        // NetworkInterfaceConfig does not implement clone, let's create the same object again.
        let netif_clone = get_dummy_netif(
            String::from("foo"),
            String::from("bar"),
            "12:34:56:78:9A:BC",
        );
        assert!(
            netif
                .into_parsed_request(Some(String::from("foo")), Method::Put)
                .eq(&Ok(ParsedRequest::Sync(
                    VmmAction::InsertNetworkDevice(netif_clone, sender),
                    receiver
                )))
        );
    }

    #[test]
    fn test_network_interface_body_serialization_and_deserialization() {
        let netif = NetworkInterfaceConfig {
            iface_id: String::from("foo"),
            state: DeviceState::Attached,
            host_dev_name: String::from("bar"),
            guest_mac: Some(MacAddr::parse_str("12:34:56:78:9A:BC").unwrap()),
            rx_rate_limiter: Some(RateLimiter::default()),
            tx_rate_limiter: Some(RateLimiter::default()),
            allow_mmds_requests: true,
            tap: None,
        };

        // This is the json encoding of the netif variable.
        let jstr = r#"{
            "iface_id": "foo",
            "host_dev_name": "bar",
            "state": "Attached",
            "guest_mac": "12:34:56:78:9A:bc",
            "rx_rate_limiter": {
            },
            "tx_rate_limiter": {
            },
            "allow_mmds_requests": true
        }"#;

        let x = serde_json::from_str(jstr).expect("deserialization failed.");
        assert_eq!(netif, x);

        // Check that guest_mac and rate limiters are truly optional.
        let jstr_no_mac = r#"{
            "iface_id": "foo",
            "host_dev_name": "bar",
            "state": "Attached"
        }"#;

        assert!(serde_json::from_str::<NetworkInterfaceConfig>(jstr_no_mac).is_ok())
    }
}
