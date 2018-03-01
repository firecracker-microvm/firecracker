use std::result;

use futures::sync::oneshot;

use request::ParsedRequest;
use super::{DeviceState, SyncRequest};

// This struct represents the strongly typed equivalent of the json body
// from vsock related requests.
#[derive(Debug, Deserialize, Serialize)]
pub struct VsockJsonBody {
    pub vsock_id: String,
    pub guest_cid: u32,
    pub state: DeviceState,
}

impl VsockJsonBody {
    pub fn into_parsed_request(self, id_from_path: &str) -> result::Result<ParsedRequest, String> {
        if id_from_path != self.vsock_id {
            return Err(String::from(
                "The id from the path does not match the id from the body!",
            ));
        }

        let (sender, receiver) = oneshot::channel();
        Ok(ParsedRequest::Sync(
            SyncRequest::PutVsock(self, sender),
            receiver,
        ))
    }
}
