use std::result;

use futures::sync::oneshot;

use request::ParsedRequest;
use serde::de::{self, Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};

use net_util::MacAddr;
use super::{DeviceState, SyncRequest};

// used to serialize an Option<MacAddr>
fn mac_serialize_with<S>(what: &Option<MacAddr>, serializer: S) -> result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if let Some(ref mac) = *what {
        mac.to_string().serialize(serializer)
    } else {
        "".serialize(serializer)
    }
}

// used to deserialize an Option<MacAddr>
fn mac_deserialize_with<'de, D>(deserializer: D) -> result::Result<Option<MacAddr>, D::Error>
where
    D: Deserializer<'de>,
{
    // TODO: is there a more efficient way around this? (i.e. deserialize to a slice
    // instead of a String?!)
    if let Some(ref s) = Option::<String>::deserialize(deserializer)? {
        MacAddr::parse_str(s)
            .map(|mac_addr| Some(mac_addr))
            .map_err(|_| de::Error::custom("invalid MAC address."))
    } else {
        Ok(None)
    }
}

// This struct represents the strongly typed equivalent of the json body from net iface
// related requests.
#[derive(Debug, Deserialize, Serialize)]
pub struct NetworkInterfaceBody {
    pub iface_id: String,
    pub state: DeviceState,
    pub host_dev_name: String,
    #[serde(serialize_with = "self::mac_serialize_with",
            deserialize_with = "self::mac_deserialize_with")]
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
