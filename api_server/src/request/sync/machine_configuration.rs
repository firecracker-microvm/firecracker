use std::result;

use futures::sync::oneshot;
use hyper::{Method, Response, StatusCode};

use http_service::{empty_response, json_fault_message, json_response};
use request::{IntoParsedRequest, ParsedRequest, SyncRequest};
use request::sync::GenerateResponse;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MachineConfigurationBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vcpu_count: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_size_mib: Option<usize>,
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

impl IntoParsedRequest for MachineConfigurationBody {
    fn into_parsed_request(self, _method: Method) -> result::Result<ParsedRequest, String> {
        let (sender, receiver) = oneshot::channel();
        Ok(ParsedRequest::Sync(
            SyncRequest::PutMachineConfiguration(self, sender),
            receiver,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_response_put_machine_configuration_error() {
        assert_eq!(
            PutMachineConfigurationError::InvalidVcpuCount
                .generate_response()
                .status(),
            StatusCode::BadRequest
        );
        assert_eq!(
            PutMachineConfigurationError::InvalidMemorySize
                .generate_response()
                .status(),
            StatusCode::BadRequest
        );
    }

    #[test]
    fn test_generate_response_put_machine_configuration_outcome() {
        assert_eq!(
            PutMachineConfigurationOutcome::Created
                .generate_response()
                .status(),
            StatusCode::Created
        );
        assert_eq!(
            PutMachineConfigurationOutcome::Updated
                .generate_response()
                .status(),
            StatusCode::NoContent
        );
        assert_eq!(
            PutMachineConfigurationOutcome::Error(PutMachineConfigurationError::InvalidVcpuCount)
                .generate_response()
                .status(),
            StatusCode::BadRequest
        );
    }

    #[test]
    fn test_into_parsed_request() {
        let body = MachineConfigurationBody {
            vcpu_count: Some(8),
            mem_size_mib: Some(1024),
        };
        let (sender, receiver) = oneshot::channel();
        assert!(
            body.clone()
                .into_parsed_request(Method::Put)
                .eq(&Ok(ParsedRequest::Sync(
                    SyncRequest::PutMachineConfiguration(body, sender),
                    receiver
                )))
        );
    }
}
