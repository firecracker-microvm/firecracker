use std::result;

use futures::sync::oneshot;
use hyper::{Response, StatusCode};

use http_service::{empty_response, json_fault_message, json_response};
use request::{ParsedRequest, SyncRequest};
use request::sync::GenerateResponse;

#[derive(Debug, Deserialize, Serialize)]
pub struct MachineConfigurationBody {
    #[serde(skip_serializing_if = "Option::is_none")] pub vcpu_count: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")] pub mem_size_mib: Option<usize>,
}

#[derive(Debug)]
pub enum PutMachineConfigurationError {
    InvalidVcpuCount,
    InvalidMemorySize,
}

impl GenerateResponse for PutMachineConfigurationError {
    fn generate_response(&self) -> Response {
        use self::PutMachineConfigurationError::*;

        match *self {
            InvalidVcpuCount => json_response(
                StatusCode::BadRequest,
                json_fault_message("The vCPU number is invalid!"),
            ),
            InvalidMemorySize => json_response(
                StatusCode::BadRequest,
                json_fault_message("The memory size (MiB) is invalid!"),
            ),
        }
    }
}

pub enum PutMachineConfigurationOutcome {
    Created,
    Updated,
    Error(PutMachineConfigurationError),
}

impl GenerateResponse for PutMachineConfigurationOutcome {
    fn generate_response(&self) -> Response {
        use self::PutMachineConfigurationOutcome::*;
        match *self {
            Created => empty_response(StatusCode::Created),
            Updated => empty_response(StatusCode::NoContent),
            Error(ref e) => e.generate_response(),
        }
    }
}

impl MachineConfigurationBody {
    pub fn into_parsed_request(self) -> result::Result<ParsedRequest, String> {
        let (sender, receiver) = oneshot::channel();
        Ok(ParsedRequest::Sync(
            SyncRequest::PutMachineConfiguration(self, sender),
            receiver,
        ))
    }
}
