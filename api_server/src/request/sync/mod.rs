use std::fmt;
use std::result;

use futures::sync::oneshot;
use hyper::{self, StatusCode};

use data_model::vm::{BlockDeviceConfig, DriveError, MachineConfiguration};
use http_service::{empty_response, json_fault_message, json_response};
use net_util::TapError;
use request::actions::ActionBody;

mod boot_source;
mod drive;
mod logger;
pub mod machine_configuration;
mod net;

pub use self::boot_source::{
    BootSourceBody, BootSourceType, LocalImage, PutBootSourceConfigError, PutBootSourceOutcome,
};
pub use self::drive::PutDriveOutcome;
pub use self::logger::{APILoggerDescription, APILoggerError, APILoggerLevel, PutLoggerOutcome};
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

// This enum contains messages for the VMM which represent sync requests. They each contain various
// bits of information (ids, paths, etc.), together with an OutcomeSender, which is always present.
pub enum SyncRequest {
    GetMachineConfiguration(SyncOutcomeSender),
    PutBootSource(BootSourceBody, SyncOutcomeSender),
    PutDrive(BlockDeviceConfig, SyncOutcomeSender),
    PutLogger(APILoggerDescription, SyncOutcomeSender),
    PutMachineConfiguration(MachineConfiguration, SyncOutcomeSender),
    PutNetworkInterface(NetworkInterfaceBody, SyncOutcomeSender),
    RescanBlockDevice(ActionBody, SyncOutcomeSender),
}

impl fmt::Debug for SyncRequest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SyncRequest")
    }
}

// TODO: we should move toward having both the ok status and various possible sync request errors
// in this file, because there are many common sync outcomes.

#[derive(PartialEq)]
pub enum OkStatus {
    Created,
    Updated,
}

impl GenerateResponse for OkStatus {
    fn generate_response(&self) -> hyper::Response {
        use self::OkStatus::*;
        match *self {
            Created => empty_response(StatusCode::Created),
            Updated => empty_response(StatusCode::NoContent),
        }
    }
}

// Potential errors associated with sync requests.
#[derive(Debug)]
pub enum Error {
    DriveOperationFailed(DriveError),
    GuestCIDAlreadyInUse,
    GuestMacAddressInUse,
    InvalidPayload,
    OpenTap(TapError),
    OperationFailed,
    OperationNotAllowedPreBoot,
    UpdateNotAllowedPostBoot,
    UpdateNotImplemented,
}

impl GenerateResponse for Error {
    fn generate_response(&self) -> hyper::Response {
        use self::Error::*;
        match *self {
            DriveOperationFailed(ref e) => e.generate_response(),
            GuestCIDAlreadyInUse => json_response(
                StatusCode::BadRequest,
                json_fault_message("The specified guest CID is already in use."),
            ),
            GuestMacAddressInUse => json_response(
                StatusCode::BadRequest,
                json_fault_message("The specified guest MAC address is already in use."),
            ),
            InvalidPayload => json_response(
                StatusCode::BadRequest,
                json_fault_message("The request payload is invalid."),
            ),
            OpenTap(ref e) => json_response(
                StatusCode::BadRequest,
                json_fault_message(format!("Could not open TAP device. {:?}", e)),
            ),
            OperationFailed => json_response(
                StatusCode::BadRequest,
                json_fault_message(format!("The operation failed.")),
            ),
            OperationNotAllowedPreBoot => json_response(
                StatusCode::Forbidden,
                json_fault_message(format!("The operation is now allowed before boot.")),
            ),
            UpdateNotAllowedPostBoot => json_response(
                StatusCode::Forbidden,
                json_fault_message("The update operation is not allowed after boot."),
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
                    &SyncRequest::PutLogger(ref logdesc, _),
                    &SyncRequest::PutLogger(ref other_logdesc, _),
                ) => logdesc == other_logdesc,
                (
                    &SyncRequest::PutMachineConfiguration(ref mcb, _),
                    &SyncRequest::PutMachineConfiguration(ref other_mcb, _),
                ) => mcb == other_mcb,
                (
                    &SyncRequest::PutNetworkInterface(ref netif, _),
                    &SyncRequest::PutNetworkInterface(ref other_netif, _),
                ) => netif == other_netif,
                (
                    &SyncRequest::RescanBlockDevice(ref req, _),
                    &SyncRequest::RescanBlockDevice(ref other_req, _),
                ) => req == other_req,
                _ => false,
            }
        }
    }

    #[test]
    fn test_generate_response_okstatus() {
        let mut ret = OkStatus::Created.generate_response();
        assert_eq!(ret.status(), StatusCode::Created);

        ret = OkStatus::Updated.generate_response();
        assert_eq!(ret.status(), StatusCode::NoContent);
    }

    #[test]
    fn test_generate_response_error() {
        let mut ret =
            Error::DriveOperationFailed(DriveError::InvalidBlockDeviceID).generate_response();
        assert_eq!(ret.status(), StatusCode::BadRequest);

        ret = Error::GuestCIDAlreadyInUse.generate_response();
        assert_eq!(ret.status(), StatusCode::BadRequest);

        ret = Error::GuestMacAddressInUse.generate_response();
        assert_eq!(ret.status(), StatusCode::BadRequest);

        ret = Error::InvalidPayload.generate_response();
        assert_eq!(ret.status(), StatusCode::BadRequest);

        ret = Error::OpenTap(TapError::OpenTun(std::io::Error::from_raw_os_error(22)))
            .generate_response();
        assert_eq!(ret.status(), StatusCode::BadRequest);

        ret = Error::OperationFailed.generate_response();
        assert_eq!(ret.status(), StatusCode::BadRequest);

        ret = Error::OperationNotAllowedPreBoot.generate_response();
        assert_eq!(ret.status(), StatusCode::Forbidden);

        ret = Error::UpdateNotAllowedPostBoot.generate_response();
        assert_eq!(ret.status(), StatusCode::Forbidden);

        ret = Error::UpdateNotImplemented.generate_response();
        assert_eq!(ret.status(), StatusCode::InternalServerError);
    }
}
