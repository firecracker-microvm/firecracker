pub mod actions;
pub mod instance_info;
pub mod sync;

use serde_json::Value;
use std::result;

use data_model::vm::PatchDrivePayload;
use futures::sync::oneshot;
use hyper::Method;

pub use self::actions::{ActionBody, ActionType};
pub use self::sync::{
    APILoggerDescription, BootSourceBody, NetworkInterfaceBody, SyncOutcomeReceiver,
    SyncOutcomeSender, SyncRequest,
};

pub enum ParsedRequest {
    Dummy,
    GetInstanceInfo,
    GetMMDS,
    PatchMMDS(Value),
    PutMMDS(Value),
    Sync(SyncRequest, SyncOutcomeReceiver),
}

pub trait IntoParsedRequest {
    fn into_parsed_request(self, method: Method) -> result::Result<ParsedRequest, String>;
}

impl IntoParsedRequest for PatchDrivePayload {
    fn into_parsed_request(self, method: Method) -> result::Result<ParsedRequest, String> {
        match method {
            Method::Patch => {
                let (sender, receiver) = oneshot::channel();
                Ok(ParsedRequest::Sync(
                    SyncRequest::PatchDrive(self.fields, sender),
                    receiver,
                ))
            }
            _ => Err(format!("Invalid method {}!", method)),
        }
    }
}

#[cfg(test)]
impl PartialEq for ParsedRequest {
    fn eq(&self, other: &ParsedRequest) -> bool {
        match (self, other) {
            (
                &ParsedRequest::Sync(ref sync_req, _),
                &ParsedRequest::Sync(ref other_sync_req, _),
            ) => sync_req == other_sync_req,
            (&ParsedRequest::Dummy, &ParsedRequest::Dummy) => true,
            (&ParsedRequest::GetInstanceInfo, &ParsedRequest::GetInstanceInfo) => true,
            (&ParsedRequest::GetMMDS, &ParsedRequest::GetMMDS) => true,
            (&ParsedRequest::PutMMDS(ref val), &ParsedRequest::PutMMDS(ref other_val)) => {
                val == other_val
            }
            (&ParsedRequest::PatchMMDS(ref val), &ParsedRequest::PatchMMDS(ref other_val)) => {
                val == other_val
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::Map;

    #[test]
    fn test_into_parsed_request() {
        let mut fields = Map::<String, Value>::new();
        fields.insert(String::from("drive_id"), Value::String(String::from("foo")));
        fields.insert(String::from("is_read_only"), Value::Bool(true));
        let pdp = PatchDrivePayload {
            fields: Value::Object(fields),
        };
        let (sender, receiver) = oneshot::channel();

        assert!(
            pdp.clone()
                .into_parsed_request(Method::Patch)
                .eq(&Ok(ParsedRequest::Sync(
                    SyncRequest::PatchDrive(pdp.fields.clone(), sender),
                    receiver
                )))
        );

        assert!(pdp.into_parsed_request(Method::Put).is_err());
    }
}
