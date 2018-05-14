use std::result;

use futures::sync::oneshot;

use super::{DeviceState, SyncRequest};
use net_util::MacAddr;
use request::ParsedRequest;

// This struct represents the strongly typed equivalent of the json body from net iface
// related requests.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct NetworkInterfaceBody {
    pub iface_id: String,
    pub state: DeviceState,
    pub host_dev_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest_mac: Option<MacAddr>,
}

impl NetworkInterfaceBody {
    pub fn into_parsed_request(self, id_from_path: &str) -> result::Result<ParsedRequest, String> {
        if id_from_path != self.iface_id {
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
    use super::*;
    use serde_json;

    #[test]
    fn test_netif_into_parsed_request() {
        let netif = NetworkInterfaceBody {
            iface_id: String::from("foo"),
            state: DeviceState::Attached,
            host_dev_name: String::from("bar"),
            guest_mac: Some(MacAddr::parse_str("12:34:56:78:9A:BC").unwrap()),
        };

        assert!(netif.clone().into_parsed_request("bar").is_err());
        let (sender, receiver) = oneshot::channel();
        assert!(
            netif
                .clone()
                .into_parsed_request("foo")
                .eq(&Ok(ParsedRequest::Sync(
                    SyncRequest::PutNetworkInterface(netif, sender),
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
        };

        // This is the json encoding of the netif variable.
        let jstr = r#"{
            "iface_id": "foo",
            "host_dev_name": "bar",
            "state": "Attached",
            "guest_mac": "12:34:56:78:9A:bc"
        }"#;

        let x = serde_json::from_str(jstr).expect("deserialization failed.");
        assert_eq!(netif, x);

        let y = serde_json::to_string(&netif).expect("serialization failed.");
        let z = serde_json::from_str(y.as_ref()).expect("deserialization (2) failed.");
        assert_eq!(x, z);

        // Check that guest_mac is truly optional.
        let jstr_no_mac = r#"{
            "iface_id": "foo",
            "host_dev_name": "bar",
            "state": "Attached"
        }"#;

        assert!(serde_json::from_str::<NetworkInterfaceBody>(jstr_no_mac).is_ok())
    }
}
