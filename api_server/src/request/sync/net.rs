use std::result;

use futures::sync::oneshot;
use hyper::Method;

use data_model::device_config::NetworkInterfaceConfig;
use request::{IntoParsedRequest, ParsedRequest, SyncRequest};

impl IntoParsedRequest for NetworkInterfaceConfig {
    fn into_parsed_request(
        self,
        _method: Method,
        id_from_path: Option<&str>,
    ) -> result::Result<ParsedRequest, String> {
        if id_from_path.is_some() && id_from_path.unwrap() != self.get_id() {
            return Err(String::from(
                "The id from the path does not match the id from the body!",
            ));
        }
        let (sender, receiver) = oneshot::channel();
        Ok(ParsedRequest::Sync(
            SyncRequest::PutNetworkInterface(self, sender),
            receiver,
        ))
    }
}

#[cfg(test)]
mod tests {
    extern crate serde_json;

    use super::*;

    #[test]
    fn test_network_config_into_parsed_request() {
        let j = r#"{
                "iface_id": "foo",
                "state": "Attached",
                "host_dev_name": "bar",
                "guest_mac": "12:34:56:78:9A:BC"
              }"#;
        let netif: NetworkInterfaceConfig = serde_json::from_str(j).unwrap();
        let netif2: NetworkInterfaceConfig = serde_json::from_str(j).unwrap();

        let (sender, receiver) = oneshot::channel();
        assert!(
            netif
                .into_parsed_request(Method::Put, Some("foo"))
                .eq(&Ok(ParsedRequest::Sync(
                    SyncRequest::PutNetworkInterface(netif2, sender),
                    receiver
                )))
        );
    }

    #[test]
    fn test_network_config_serde() {
        let jstr = r#"{
            "iface_id": "foo",
            "state": "Attached",
            "host_dev_name": "bar",
            "guest_mac": "12:34:56:78:9a:bc",
            "rx_rate_limiter": {
                "bandwidth": { "size": 0, "refill_time": 0 },
                "ops": { "size": 0, "refill_time": 0 }
            },
            "tx_rate_limiter": {
                "bandwidth": { "size": 0, "refill_time": 0 },
                "ops": { "size": 0, "refill_time": 0 }
            }
        }"#;

        let x: NetworkInterfaceConfig =
            serde_json::from_str(jstr).expect("deserialization failed.");
        let y = serde_json::to_string(&x).expect("serialization failed.");
        assert_eq!(y, String::from(jstr).replace("\n", "").replace(" ", ""));

        // Check that guest_mac and rate limiters are truly optional.
        let jstr_no_mac = r#"{
            "iface_id": "foo",
            "host_dev_name": "bar",
            "state": "Attached"
        }"#;

        assert!(serde_json::from_str::<NetworkInterfaceConfig>(jstr_no_mac).is_ok())
    }
}
