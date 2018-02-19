use std::result;

use futures::sync::oneshot;

use request::ParsedRequest;
use super::{DeviceState, SyncRequest};

// This struct represents the strongly typed equivalent of the json body from drive
// related requests.
#[derive(Debug, Deserialize, Serialize)]
pub struct DriveDescription {
    drive_id: String,
    path_on_host: String,
    state: DeviceState,
}

impl DriveDescription {
    pub fn into_parsed_request(self, _id_from_path: &str) -> result::Result<ParsedRequest, String> {
        // todo: any validation?
        let (sender, receiver) = oneshot::channel();
        Ok(ParsedRequest::Sync(
            SyncRequest::PutDrive(self, sender),
            receiver,
        ))
    }
}
