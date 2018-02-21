use std::net::Ipv4Addr;
use std::result;

use futures::sync::oneshot;

use request::ParsedRequest;
use super::{DeviceState, SyncRequest};

fn default_host_netmask() -> Ipv4Addr {
    // this is as valid as they come
    "255.255.255.0".parse().unwrap()
}

// This struct represents the strongly typed equivalent of the json body from net iface
// related requests.
// TODO: change swagger API description to reflect the changes.
#[derive(Debug, Deserialize, Serialize)]
pub struct NetworkInterfaceBody {
    pub iface_id: String,
    pub state: DeviceState,
    pub host_dev_name: String,
    pub host_ipv4_address: Ipv4Addr,
    #[serde(default = "default_host_netmask")] pub host_netmask: Ipv4Addr,
    #[serde(skip_serializing_if = "Option::is_none")] pub guest_mac: Option<String>,
}

impl NetworkInterfaceBody {
    pub fn into_parsed_request(self, _id_from_path: &str) -> result::Result<ParsedRequest, String> {
        // todo: any validation?
        let (sender, receiver) = oneshot::channel();
        Ok(ParsedRequest::Sync(
            SyncRequest::PutNetworkInterface(self, sender),
            receiver,
        ))
    }
}
