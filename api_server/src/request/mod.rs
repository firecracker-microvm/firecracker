pub mod async;
pub mod sync;

pub use self::async::{AsyncOutcome, AsyncOutcomeReceiver, AsyncOutcomeSender, AsyncRequest,
                      AsyncRequestBody};
pub use self::sync::{BootSourceBody, DriveDescription, MachineConfigurationBody,
                     NetworkInterfaceBody, SyncOutcomeReceiver, SyncOutcomeSender, SyncRequest,
                     VsockJsonBody};

pub enum ParsedRequest {
    Dummy,
    GetActions,
    GetAction(String),
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
