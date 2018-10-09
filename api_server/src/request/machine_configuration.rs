use std::result;

use futures::sync::oneshot;
use hyper::{Method, Response, StatusCode};

use data_model::vm::MachineConfiguration;
use http_service::{json_fault_message, json_response};
use request::{GenerateResponse, IntoParsedRequest, ParsedRequest, VmmAction};

#[derive(Debug, PartialEq)]
pub enum PutMachineConfigurationError {
    InvalidVcpuCount,
    InvalidMemorySize,
    UpdateNotAllowPostBoot,
}

impl GenerateResponse for PutMachineConfigurationError {
    fn generate_response(&self) -> Response {
        use self::PutMachineConfigurationError::*;

        match self {
            InvalidVcpuCount => json_response(
                StatusCode::BadRequest,
                json_fault_message(
                    "The vCPU number is invalid! The vCPU number can only \
                     be 1 or an even number when hyperthreading is enabled.",
                ),
            ),
            InvalidMemorySize => json_response(
                StatusCode::BadRequest,
                json_fault_message("The memory size (MiB) is invalid."),
            ),
            UpdateNotAllowPostBoot => json_response(
                StatusCode::BadRequest,
                json_fault_message("The update operation is not allowed after boot."),
            ),
        }
    }
}

impl GenerateResponse for MachineConfiguration {
    fn generate_response(&self) -> Response {
        let vcpu_count = self.vcpu_count.unwrap_or(1);
        let mem_size = self.mem_size_mib.unwrap_or(128);
        let ht_enabled = self.ht_enabled.unwrap_or(false);
        let cpu_template = self
            .cpu_template
            .map_or("Uninitialized".to_string(), |c| c.to_string());

        json_response(
            StatusCode::Ok,
            format!(
                "{{ \"vcpu_count\": {:?}, \"mem_size_mib\": {:?},  \"ht_enabled\": {:?},  \"cpu_template\": {:?} }}",
                vcpu_count, mem_size, ht_enabled, cpu_template
            ),
        )
    }
}

impl IntoParsedRequest for MachineConfiguration {
    fn into_parsed_request(self, method: Method) -> result::Result<ParsedRequest, String> {
        let (sender, receiver) = oneshot::channel();
        match method {
            Method::Get => Ok(ParsedRequest::Sync(
                VmmAction::GetMachineConfiguration(sender),
                receiver,
            )),
            Method::Put => {
                if self.vcpu_count.is_none()
                    && self.mem_size_mib.is_none()
                    && self.cpu_template.is_none()
                    && self.ht_enabled.is_none()
                {
                    return Err(String::from("Empty request."));
                }
                Ok(ParsedRequest::Sync(
                    VmmAction::SetVmConfiguration(self, sender),
                    receiver,
                ))
            }
            _ => Ok(ParsedRequest::Dummy),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_model::vm::CpuFeaturesTemplate;

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
        assert_eq!(
            PutMachineConfigurationError::UpdateNotAllowPostBoot
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
            ht_enabled: Some(true),
            cpu_template: Some(CpuFeaturesTemplate::T2),
        };
        let (sender, receiver) = oneshot::channel();
        assert!(
            body.clone()
                .into_parsed_request(Method::Put)
                .eq(&Ok(ParsedRequest::Sync(
                    VmmAction::SetVmConfiguration(body, sender),
                    receiver
                )))
        );
        let uninitialized = MachineConfiguration {
            vcpu_count: None,
            mem_size_mib: None,
            ht_enabled: None,
            cpu_template: None,
        };
        assert!(
            uninitialized
                .clone()
                .into_parsed_request(Method::Get)
                .is_ok()
        );
        assert!(
            uninitialized
                .clone()
                .into_parsed_request(Method::Patch)
                .eq(&Ok(ParsedRequest::Dummy))
        );

        match uninitialized.into_parsed_request(Method::Put) {
            Ok(_) => assert!(false),
            Err(e) => assert_eq!(e, String::from("Empty request.")),
        };
    }
}
