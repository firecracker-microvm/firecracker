use std::fmt;
use std::result;

use futures::sync::oneshot;
use hyper::{self, StatusCode};

use data_model::vm::MachineConfiguration;
use http_service::{empty_response, json_fault_message, json_response};
use net_util::TapError;

pub mod boot_source;
mod drive;
pub mod machine_configuration;
mod net;
mod vsock;

pub use self::drive::{DriveDescription, DriveError, DrivePermissions, PutDriveOutcome};
pub use self::boot_source::{BootSourceBody, BootSourceType, LocalImage};
pub use self::net::NetworkInterfaceBody;
pub use self::vsock::VsockJsonBody;

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

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum DeviceState {
    Attached,
}

// This enum contains messages for the VMM which represent sync requests. They each contain various
// bits of information (ids, paths, etc.), together with an OutcomeSender, which is always present.
pub enum SyncRequest {
    PutBootSource(BootSourceBody, SyncOutcomeSender),
    PutDrive(DriveDescription, SyncOutcomeSender),
    PutMachineConfiguration(MachineConfiguration, SyncOutcomeSender),
    PutNetworkInterface(NetworkInterfaceBody, SyncOutcomeSender),
    PutVsock(VsockJsonBody, SyncOutcomeSender),
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
#[derive(Debug)]
pub enum Error {
    GuestCIDAlreadyInUse,
    GuestMacAddressInUse,
    OpenTap(TapError),
    UpdateNotImplemented,
}

impl GenerateResponse for Error {
    fn generate_response(&self) -> hyper::Response {
        use self::Error::*;
        match *self {
            GuestCIDAlreadyInUse => json_response(
                StatusCode::BadRequest,
                json_fault_message("The specified guest CID is already in use."),
            ),
            GuestMacAddressInUse => json_response(
                StatusCode::BadRequest,
                json_fault_message("The specified guest MAC address is already in use."),
            ),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std;

    // Implementation for the "==" operator.
    // Can't derive PartialEq directly because the sender members can't be compared.
    impl PartialEq for SyncRequest {
        fn eq(&self, other: &SyncRequest) -> bool {
            match (self, other) {
                (
                    &SyncRequest::PutBootSource(ref bsb, _),
                    &SyncRequest::PutBootSource(ref other_bsb, _),
                ) => bsb == other_bsb,
                (
                    &SyncRequest::PutDrive(ref ddesc, _),
                    &SyncRequest::PutDrive(ref other_ddesc, _),
                ) => ddesc == other_ddesc,
                (
                    &SyncRequest::PutMachineConfiguration(ref mcb, _),
                    &SyncRequest::PutMachineConfiguration(ref other_mcb, _),
                ) => mcb == other_mcb,
                (
                    &SyncRequest::PutNetworkInterface(ref netif, _),
                    &SyncRequest::PutNetworkInterface(ref other_netif, _),
                ) => netif == other_netif,
                (&SyncRequest::PutVsock(ref vjb, _), &SyncRequest::PutVsock(ref other_vjb, _)) => {
                    vjb == other_vjb
                }
                _ => false,
            }
        }
    }

    #[test]
    fn test_generate_response_okstatus() {
        let ret = OkStatus::Created.generate_response();
        assert_eq!(ret.status(), StatusCode::Created);
    }

    #[test]
    fn test_generate_response_error() {
        let mut ret = Error::GuestCIDAlreadyInUse.generate_response();
        assert_eq!(ret.status(), StatusCode::BadRequest);

        ret = Error::GuestMacAddressInUse.generate_response();
        assert_eq!(ret.status(), StatusCode::BadRequest);

        ret = Error::OpenTap(TapError::OpenTun(std::io::Error::from_raw_os_error(22)))
            .generate_response();
        assert_eq!(ret.status(), StatusCode::BadRequest);

        ret = Error::UpdateNotImplemented.generate_response();
        assert_eq!(ret.status(), StatusCode::InternalServerError);
    }
}
