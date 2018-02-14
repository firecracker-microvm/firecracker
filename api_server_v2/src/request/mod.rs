pub mod async;

pub use self::async::{AsyncOutcome, AsyncOutcomeReceiver, AsyncOutcomeSender, AsyncRequest,
                      AsyncRequestBody};

pub enum ParsedRequest {
    Dummy,
    GetActions,
    GetAction(String),
    // the first String is the id
    Async(String, AsyncRequest, AsyncOutcomeReceiver),
}
