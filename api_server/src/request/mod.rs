pub mod async;
pub mod sync;

use serde_json::Value;
use std::result;

pub use self::async::{
    AsyncOutcome, AsyncOutcomeReceiver, AsyncOutcomeSender, AsyncRequest, AsyncRequestBody,
};
pub use self::sync::{
    APILoggerDescription, BootSourceBody, DriveDescription, NetworkInterfaceBody,
    SyncOutcomeReceiver, SyncOutcomeSender, SyncRequest,
};
use hyper::Method;

pub mod instance_info;

pub enum ParsedRequest {
    Dummy,
    GetInstanceInfo,
    GetActions,
    GetAction(String),
    GetMMDS,
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
