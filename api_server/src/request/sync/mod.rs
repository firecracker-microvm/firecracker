use futures::sync::oneshot;
use hyper;

pub mod boot_source;
mod drive;
pub mod machine_configuration;
mod net;

use std::fmt;

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

impl fmt::Debug for SyncRequest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SyncRequest")
    }
}
