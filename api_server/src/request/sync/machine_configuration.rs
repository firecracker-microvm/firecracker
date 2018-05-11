use std::result;

use futures::sync::oneshot;
use hyper::{Method, Response, StatusCode};

use data_model::vm::MachineConfiguration;
use http_service::{empty_response, json_fault_message, json_response};
use request::sync::GenerateResponse;
use request::{IntoParsedRequest, ParsedRequest, SyncRequest};

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
                json_fault_message(
                    "The vCPU number is invalid! The vCPU number can only \
                     be 1 or an even number.",
                ),
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

impl GenerateResponse for MachineConfiguration {
    fn generate_response(&self) -> Response {
        let vcpu_count = match self.vcpu_count {
            Some(v) => v.to_string(),
            None => String::from("Uninitialized"),
        };
        let mem_size = match self.mem_size_mib {
            Some(v) => v.to_string(),
            None => String::from("Uninitialized"),
        };

        json_response(
            StatusCode::Ok,
            format!(
                "{{ \"vcpu_count\": {:?}, \"mem_size_mib\": {:?} }}",
                vcpu_count, mem_size
            ),
        )
    }
}

impl IntoParsedRequest for MachineConfiguration {
    fn into_parsed_request(self, method: Method) -> result::Result<ParsedRequest, String> {
        let (sender, receiver) = oneshot::channel();
        match method {
            Method::Get => Ok(ParsedRequest::Sync(
                SyncRequest::GetMachineConfiguration(sender),
                receiver,
            )),
            Method::Put => Ok(ParsedRequest::Sync(
                SyncRequest::PutMachineConfiguration(self, sender),
                receiver,
            )),
            _ => Ok(ParsedRequest::Dummy),
        }
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
        let body = MachineConfiguration {
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
        let uninitialized = MachineConfiguration {
            vcpu_count: None,
            mem_size_mib: None,
        };
        assert!(
            uninitialized
                .clone()
                .into_parsed_request(Method::Get)
                .is_ok()
        );
        assert!(
            uninitialized
                .into_parsed_request(Method::Patch)
                .eq(&Ok(ParsedRequest::Dummy))
        );
    }
}
