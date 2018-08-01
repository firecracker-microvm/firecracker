pub mod async;
pub mod sync;

use serde_json::Value;
use std::result;

pub use self::async::{AsyncOutcome, AsyncOutcomeReceiver, AsyncOutcomeSender, AsyncRequest};
pub use self::sync::{
    APILoggerDescription, BootSourceBody, NetworkInterfaceBody, SyncOutcomeReceiver,
    SyncOutcomeSender, SyncRequest,
};
pub use data_model::vm::DriveDescription;
use hyper::Method;

pub mod actions;
pub mod instance_info;

pub enum ParsedRequest {
    Dummy,
    GetInstanceInfo,
    GetActions,
    GetAction(String),
    GetMMDS,
    PatchMMDS(Value),
    PutMMDS(Value),
    // the first String is the id
    Async(String, AsyncRequest, AsyncOutcomeReceiver),
    Sync(SyncRequest, SyncOutcomeReceiver),
}

// This enum represents a message which is passed to the VMM to request the execution
// of a certain action.
#[derive(Debug)]
pub enum ApiRequest {
    Async(AsyncRequest),
    Sync(SyncRequest),
}

pub trait IntoParsedRequest {
    fn into_parsed_request(self, method: Method) -> result::Result<ParsedRequest, String>;
}

#[cfg(test)]
impl PartialEq for ParsedRequest {
    fn eq(&self, other: &ParsedRequest) -> bool {
        match (self, other) {
            (
                &ParsedRequest::Async(ref id, ref request, _),
                &ParsedRequest::Async(ref other_id, ref other_request, _),
            ) => id == other_id && request == other_request,
            (
                &ParsedRequest::Sync(ref sync_req, _),
                &ParsedRequest::Sync(ref other_sync_req, _),
            ) => sync_req == other_sync_req,
            (&ParsedRequest::Dummy, &ParsedRequest::Dummy) => true,
            (&ParsedRequest::GetInstanceInfo, &ParsedRequest::GetInstanceInfo) => true,
            (&ParsedRequest::GetActions, &ParsedRequest::GetActions) => true,
            (&ParsedRequest::GetAction(ref id), &ParsedRequest::GetAction(ref other_id)) => {
                id == other_id
            }
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
