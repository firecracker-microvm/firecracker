use std::fmt;
use std::result;

use futures::sync::oneshot;
use hyper::{self, StatusCode};

use http_service::{empty_response, json_fault_message, json_response};
use net_util::TapError;

pub mod boot_source;
mod drive;
pub mod machine_configuration;
mod net;

pub use self::drive::{DriveDescription, DriveError, PutDriveOutcome};
pub use self::boot_source::BootSourceBody;
pub use self::machine_configuration::MachineConfigurationBody;
pub use self::net::NetworkInterfaceBody;

// Unlike async requests, sync request have outcomes which implement this trait. The idea is for
// each outcome to be a struct which is cheaply and quickly instantiated by the VMM thread, then
// passed back the the API thread, and then unpacked into a http response using the implementation
// of the generate_response() method.
pub trait GenerateResponse {
    fn generate_response(&self) -> hyper::Response;
}

// This allows us to return a boxed Result directly as a SyncOutcome, if both the ok and the error
// types implement the GenerateResponse trait.
impl<T, U> GenerateResponse for result::Result<T, U>
where
    T: GenerateResponse,
    U: GenerateResponse,
{
    fn generate_response(&self) -> hyper::Response {
        match *self {
            Ok(ref v) => v.generate_response(),
            Err(ref e) => e.generate_response(),
        }
    }
}

pub type SyncOutcomeSender = oneshot::Sender<Box<GenerateResponse + Send>>;
pub type SyncOutcomeReceiver = oneshot::Receiver<Box<GenerateResponse + Send>>;

#[derive(Debug, Deserialize, Serialize)]
pub enum DeviceState {
    Attached,
}

// This enum contains messages for the VMM which represent sync requests. They each contain various
// bits of information (ids, paths, etc.), together with an OutcomeSender, which is always present.
pub enum SyncRequest {
    PutBootSource(BootSourceBody, SyncOutcomeSender),
    PutDrive(DriveDescription, SyncOutcomeSender),
    PutMachineConfiguration(MachineConfigurationBody, SyncOutcomeSender),
    PutNetworkInterface(NetworkInterfaceBody, SyncOutcomeSender),
}

// TODO: do we still need this?
impl fmt::Debug for SyncRequest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SyncRequest")
    }
}

// TODO: we should move toward having both the ok status and various possible sync request errors
// in this file, because there are many common sync outcomes.

pub enum OkStatus {
    Created,
}

impl GenerateResponse for OkStatus {
    fn generate_response(&self) -> hyper::Response {
        use self::OkStatus::*;
        match *self {
            Created => empty_response(StatusCode::Created),
        }
    }
}

// Potential errors associated with sync requests.
pub enum Error {
    OpenTap(TapError),
    UpdateNotImplemented,
}

impl GenerateResponse for Error {
    fn generate_response(&self) -> hyper::Response {
        use self::Error::*;
        match *self {
            OpenTap(_) => json_response(
                StatusCode::BadRequest,
                json_fault_message("Could not open TAP device."),
            ),
            UpdateNotImplemented => json_response(
                StatusCode::InternalServerError,
                json_fault_message("Update operation is not implemented yet."),
            ),
        }
    }
}

pub type Result<T> = result::Result<T, Error>;
