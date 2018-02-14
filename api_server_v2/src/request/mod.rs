pub mod async;
pub mod sync;

pub use self::async::{AsyncOutcome, AsyncOutcomeReceiver, AsyncOutcomeSender, AsyncRequest,
                      AsyncRequestBody};
pub use self::sync::{DriveDescription, SyncOutcomeReceiver, SyncOutcomeSender, SyncRequest};

pub enum ParsedRequest {
    Dummy,
    GetActions,
    GetAction(String),
    // the first String is the id
    Async(String, AsyncRequest, AsyncOutcomeReceiver),
    Sync(SyncRequest, SyncOutcomeReceiver),
}
