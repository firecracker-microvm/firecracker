use std::result;

use futures::sync::oneshot;
use hyper::{self, StatusCode};

use data_model::device_config::{DriveConfig, NetworkInterfaceConfig};
use data_model::vm::boot_source::BootSource;
use data_model::vm::LoggerDescription;
use data_model::vm::MachineConfiguration;
use http_service::{empty_response, json_fault_message, json_response};
use net_util::TapError;

pub mod boot_source;
mod drive;
mod logger;
pub mod machine_configuration;
mod net;

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
    PutBootSource(BootSource, SyncOutcomeSender),
    PutDrive(DriveConfig, SyncOutcomeSender),
    PutLogger(LoggerDescription, SyncOutcomeSender),
    PutMachineConfiguration(MachineConfiguration, SyncOutcomeSender),
    PutNetworkInterface(NetworkInterfaceConfig, SyncOutcomeSender),
}

// TODO: we should move toward having both the ok status and various possible sync request errors
// in this file, because there are many common sync outcomes.
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
    GuestMacAddressInUse,
    OpenTap(TapError),
    UpdateNotAllowedPostBoot,
    UpdateNotImplemented,
}

impl GenerateResponse for Error {
    fn generate_response(&self) -> hyper::Response {
        use self::Error::*;
        match *self {
            GuestMacAddressInUse => json_response(
                StatusCode::BadRequest,
                json_fault_message("The specified guest MAC address is already in use."),
            ),
            OpenTap(ref e) => json_response(
                StatusCode::BadRequest,
                json_fault_message(format!("Could not open TAP device. {:?}", e)),
            ),
            UpdateNotAllowedPostBoot => json_response(
                StatusCode::Forbidden,
                json_fault_message("The update operation is not allowed"),
            ),
            UpdateNotImplemented => json_response(
                StatusCode::InternalServerError,
                json_fault_message("Update operation is not implemented yet."),
            ),
        }
    }
}

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
        let ret = Error::GuestMacAddressInUse.generate_response();
        assert_eq!(
            format!("{:?}", Error::GuestMacAddressInUse),
            "GuestMacAddressInUse"
        );
        assert_eq!(ret.status(), StatusCode::BadRequest);

        let ret = Error::OpenTap(TapError::OpenTun(std::io::Error::from_raw_os_error(22)))
            .generate_response();
        assert!(
            format!(
                "{:?}",
                Error::OpenTap(TapError::OpenTun(std::io::Error::from_raw_os_error(22)))
            ).contains("OpenTap(OpenTun(Os { code: 22"),
            "OpenTap"
        );
        assert_eq!(ret.status(), StatusCode::BadRequest);

        let ret = Error::UpdateNotImplemented.generate_response();
        assert_eq!(
            format!("{:?}", Error::UpdateNotImplemented),
            "UpdateNotImplemented"
        );
        assert_eq!(ret.status(), StatusCode::InternalServerError);
    }
}
