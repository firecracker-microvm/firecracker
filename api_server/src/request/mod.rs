pub mod actions;
pub mod boot_source;
pub mod drive;
pub mod instance_info;
pub mod logger;
pub mod machine_configuration;
pub mod net;

use serde_json::Value;
use std::{fmt, result};

use futures::sync::oneshot;
use http_service::{empty_response, json_fault_message, json_response};
use hyper;
use hyper::{Method, StatusCode};

use data_model::vm::{BlockDeviceConfig, DriveError, MachineConfiguration, PatchDrivePayload};
use net_util::TapError;

use self::actions::ActionBody;
use self::boot_source::BootSourceBody;
use self::logger::APILoggerDescription;
use self::net::NetworkInterfaceBody;

pub type SyncOutcomeSender = oneshot::Sender<Box<GenerateResponse + Send>>;
pub type SyncOutcomeReceiver = oneshot::Receiver<Box<GenerateResponse + Send>>;

pub enum ParsedRequest {
    Dummy,
    GetInstanceInfo,
    GetMMDS,
    PatchMMDS(Value),
    PutMMDS(Value),
    Sync(SyncRequest, SyncOutcomeReceiver),
}

pub trait IntoParsedRequest {
    fn into_parsed_request(self, method: Method) -> result::Result<ParsedRequest, String>;
}

// Sync requests have outcomes which implement this trait. The idea is for each outcome to be a
// struct which is cheaply and quickly instantiated by the VMM thread, then passed back the the API
// thread, and then unpacked into a http response using the implementation of
// the generate_response() method.
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

// This enum contains messages for the VMM which represent sync requests. They each contain various
// bits of information (ids, paths, etc.), together with an OutcomeSender, which is always present.
pub enum SyncRequest {
    GetMachineConfiguration(SyncOutcomeSender),
    PatchDrive(Value, SyncOutcomeSender),
    PutBootSource(BootSourceBody, SyncOutcomeSender),
    PutDrive(BlockDeviceConfig, SyncOutcomeSender),
    PutLogger(APILoggerDescription, SyncOutcomeSender),
    PutMachineConfiguration(MachineConfiguration, SyncOutcomeSender),
    PutNetworkInterface(NetworkInterfaceBody, SyncOutcomeSender),
    RescanBlockDevice(ActionBody, SyncOutcomeSender),
    StartInstance(SyncOutcomeSender),
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
    Ok,
    NoContent,
}

impl GenerateResponse for OkStatus {
    fn generate_response(&self) -> hyper::Response {
        use self::OkStatus::*;
        match *self {
            Created => empty_response(StatusCode::Created),
            Ok => empty_response(StatusCode::Ok),
            NoContent => empty_response(StatusCode::NoContent),
        }
    }
}

// Potential errors associated with sync requests.
#[derive(Debug)]
pub enum Error {
    DriveOperationFailed(DriveError),
    GuestCIDAlreadyInUse,
    GuestMacAddressInUse,
    InstanceStartFailed(ErrorType, String),
    InvalidPayload,
    MicroVMAlreadyRunning,
    OpenTap(TapError),
    OperationFailed,
    OperationNotAllowedPreBoot,
    UpdateNotAllowedPostBoot,
    UpdateNotImplemented,
}

/// We need to implement to string because we are sending the errors to the clients by
/// using json_fault_message function that expects a type which implements AsRef<str>.
/// When using the default Debug formatting, we end up with invalid jsons because we don't
/// escape the quotes in the error message.
impl ToString for Error {
    fn to_string(&self) -> String {
        match self {
            Error::InstanceStartFailed(_, ref err_msg) => err_msg.replace("\"", ""),
            _ => {
                let err_msg = format!("{:?}", self);
                err_msg.replace("\"", "")
            }
        }
    }
}

#[derive(Debug)]
pub enum ErrorType {
    UserError,
    InternalError,
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
            InstanceStartFailed(ref error_type, _) => {
                let status_code = match error_type {
                    ErrorType::InternalError => StatusCode::InternalServerError,
                    ErrorType::UserError => StatusCode::BadRequest,
                };

                json_response(status_code, json_fault_message(self.to_string()))
            }
            InvalidPayload => json_response(
                StatusCode::BadRequest,
                json_fault_message("The request payload is invalid."),
            ),
            MicroVMAlreadyRunning => json_response(
                StatusCode::Forbidden,
                json_fault_message("The microVM is already running."),
            ),
            OpenTap(_) => json_response(
                StatusCode::BadRequest,
                json_fault_message(format!("Could not open TAP device. {}", self.to_string())),
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

impl IntoParsedRequest for PatchDrivePayload {
    fn into_parsed_request(self, method: Method) -> result::Result<ParsedRequest, String> {
        match method {
            Method::Patch => {
                let (sender, receiver) = oneshot::channel();
                Ok(ParsedRequest::Sync(
                    SyncRequest::PatchDrive(self.fields, sender),
                    receiver,
                ))
            }
            _ => Err(format!("Invalid method {}!", method)),
        }
    }
}

#[cfg(test)]
impl PartialEq for ParsedRequest {
    fn eq(&self, other: &ParsedRequest) -> bool {
        match (self, other) {
            (
                &ParsedRequest::Sync(ref sync_req, _),
                &ParsedRequest::Sync(ref other_sync_req, _),
            ) => sync_req == other_sync_req,
            (&ParsedRequest::Dummy, &ParsedRequest::Dummy) => true,
            (&ParsedRequest::GetInstanceInfo, &ParsedRequest::GetInstanceInfo) => true,
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

#[cfg(test)]
mod tests {
    use super::*;

    use futures::{Future, Stream};
    use hyper::{Body, Response};
    use serde_json::{self, Map};
    use std;

    // Implementation for the "==" operator.
    // Can't derive PartialEq directly because the sender members can't be compared.
    impl PartialEq for SyncRequest {
        fn eq(&self, other: &SyncRequest) -> bool {
            match (self, other) {
                (
                    &SyncRequest::PatchDrive(ref payload, _),
                    &SyncRequest::PatchDrive(ref other_payload, _),
                ) => payload == other_payload,
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
                (&SyncRequest::StartInstance(_), &SyncRequest::StartInstance(_)) => true,
                _ => false,
            }
        }
    }

    #[test]
    fn test_into_parsed_request() {
        let mut fields = Map::<String, Value>::new();
        fields.insert(String::from("drive_id"), Value::String(String::from("foo")));
        fields.insert(String::from("is_read_only"), Value::Bool(true));
        let pdp = PatchDrivePayload {
            fields: Value::Object(fields),
        };
        let (sender, receiver) = oneshot::channel();

        assert!(
            pdp.clone()
                .into_parsed_request(Method::Patch)
                .eq(&Ok(ParsedRequest::Sync(
                    SyncRequest::PatchDrive(pdp.fields.clone(), sender),
                    receiver
                )))
        );

        assert!(pdp.into_parsed_request(Method::Put).is_err());
    }

    #[test]
    fn test_generate_response_okstatus() {
        let mut ret = OkStatus::Created.generate_response();
        assert_eq!(ret.status(), StatusCode::Created);

        ret = OkStatus::NoContent.generate_response();
        assert_eq!(ret.status(), StatusCode::NoContent);
    }

    fn get_body(
        response: Response<Body>,
    ) -> std::result::Result<serde_json::Value, serde_json::Error> {
        let body = response
            .body()
            .map_err(|_| ())
            .fold(vec![], |mut acc, chunk| {
                acc.extend_from_slice(&chunk);
                Ok(acc)
            }).and_then(|v| String::from_utf8(v).map_err(|_| ()));
        serde_json::from_str::<Value>(body.wait().unwrap().as_ref())
    }

    #[test]
    fn test_generate_response_error() {
        let mut ret =
            Error::DriveOperationFailed(DriveError::InvalidBlockDeviceID).generate_response();
        assert_eq!(ret.status(), StatusCode::BadRequest);
        assert!(get_body(ret).is_ok());

        ret = Error::GuestCIDAlreadyInUse.generate_response();
        assert_eq!(ret.status(), StatusCode::BadRequest);
        assert!(get_body(ret).is_ok());

        ret = Error::GuestMacAddressInUse.generate_response();
        assert_eq!(ret.status(), StatusCode::BadRequest);
        assert!(get_body(ret).is_ok());

        ret = Error::InstanceStartFailed(
            ErrorType::InternalError,
            "Dummy error message.".to_string(),
        ).generate_response();
        assert_eq!(ret.status(), StatusCode::InternalServerError);
        assert!(get_body(ret).is_ok());

        ret = Error::InstanceStartFailed(ErrorType::UserError, "Dummy error message.".to_string())
            .generate_response();
        assert_eq!(ret.status(), StatusCode::BadRequest);
        assert!(get_body(ret).is_ok());

        ret = Error::InvalidPayload.generate_response();
        assert_eq!(ret.status(), StatusCode::BadRequest);
        assert!(get_body(ret).is_ok());

        ret = Error::MicroVMAlreadyRunning.generate_response();
        assert_eq!(ret.status(), StatusCode::Forbidden);
        assert!(get_body(ret).is_ok());

        ret = Error::OpenTap(TapError::OpenTun(std::io::Error::from_raw_os_error(22)))
            .generate_response();
        assert_eq!(ret.status(), StatusCode::BadRequest);
        assert!(get_body(ret).is_ok());

        ret = Error::OperationFailed.generate_response();
        assert_eq!(ret.status(), StatusCode::BadRequest);
        assert!(get_body(ret).is_ok());

        ret = Error::OperationNotAllowedPreBoot.generate_response();
        assert_eq!(ret.status(), StatusCode::Forbidden);
        assert!(get_body(ret).is_ok());

        ret = Error::UpdateNotAllowedPostBoot.generate_response();
        assert_eq!(ret.status(), StatusCode::Forbidden);
        assert!(get_body(ret).is_ok());

        ret = Error::UpdateNotImplemented.generate_response();
        assert_eq!(ret.status(), StatusCode::InternalServerError);
        assert!(get_body(ret).is_ok());
    }
}
