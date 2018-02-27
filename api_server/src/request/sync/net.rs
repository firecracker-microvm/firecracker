use std::result;

use futures::sync::oneshot;

use request::ParsedRequest;
use super::{DeviceState, SyncRequest};

// This struct represents the strongly typed equivalent of the json body from net iface
// related requests.
// TODO: change swagger API description to reflect the changes.
#[derive(Debug, Deserialize, Serialize)]
pub struct NetworkInterfaceBody {
    pub iface_id: String,
    pub state: DeviceState,
    pub host_dev_name: String,
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
