use std::result;

use futures::sync::oneshot;
use hyper::Method;

use request::{IntoParsedRequest, ParsedRequest};
use vmm::vmm_config::net::NetworkInterfaceBody;
use vmm::VmmAction;

impl IntoParsedRequest for NetworkInterfaceBody {
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

    use self::net_util::MacAddr;
    use super::*;

    use serde_json;

    use data_model::vm::RateLimiterDescription;
    use vmm::vmm_config::DeviceState;

    #[test]
    fn test_netif_into_parsed_request() {
        let netif = NetworkInterfaceBody {
            iface_id: String::from("foo"),
            state: DeviceState::Attached,
            host_dev_name: String::from("bar"),
            guest_mac: Some(MacAddr::parse_str("12:34:56:78:9A:BC").unwrap()),
            rx_rate_limiter: None,
            tx_rate_limiter: None,
            allow_mmds_requests: false,
        };

        assert!(
            netif
                .clone()
                .into_parsed_request(Some(String::from("bar")), Method::Put)
                .is_err()
        );
        let (sender, receiver) = oneshot::channel();
        assert!(
            netif
                .clone()
                .into_parsed_request(Some(String::from("foo")), Method::Put)
                .eq(&Ok(ParsedRequest::Sync(
                    VmmAction::InsertNetworkDevice(netif, sender),
                    receiver
                )))
        );
    }

    #[test]
    fn test_network_interface_body_serialization_and_deserialization() {
        let netif = NetworkInterfaceBody {
            iface_id: String::from("foo"),
            state: DeviceState::Attached,
            host_dev_name: String::from("bar"),
            guest_mac: Some(MacAddr::parse_str("12:34:56:78:9A:BC").unwrap()),
            rx_rate_limiter: Some(RateLimiterDescription::default()),
            tx_rate_limiter: Some(RateLimiterDescription::default()),
            allow_mmds_requests: true,
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

        let y = serde_json::to_string(&netif).expect("serialization failed.");
        let z = serde_json::from_str(y.as_ref()).expect("deserialization (2) failed.");
        assert_eq!(x, z);

        // Check that guest_mac and rate limiters are truly optional.
        let jstr_no_mac = r#"{
            "iface_id": "foo",
            "host_dev_name": "bar",
            "state": "Attached"
        }"#;

        assert!(serde_json::from_str::<NetworkInterfaceBody>(jstr_no_mac).is_ok())
    }
}
