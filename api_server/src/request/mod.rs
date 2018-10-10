pub mod actions;
pub mod boot_source;
pub mod drive;
pub mod logger;
pub mod machine_configuration;
pub mod net;

use serde_json::Value;
use std::result;

use hyper;
use hyper::{Method, StatusCode};

use http_service::{empty_response, json_fault_message, json_response};
use vmm::{ErrorKind, OutcomeReceiver, VmmAction, VmmActionError, VmmData};

pub enum ParsedRequest {
    Dummy,
    GetInstanceInfo,
    GetMMDS,
    PatchMMDS(Value),
    PutMMDS(Value),
    Sync(VmmAction, OutcomeReceiver),
}

pub trait IntoParsedRequest {
    fn into_parsed_request(
        self,
        resource_id: Option<String>,
        method: Method,
    ) -> result::Result<ParsedRequest, String>;
}

// Sync requests have outcomes which implement this trait. The idea is for each outcome to be a
// struct which is cheaply and quickly instantiated by the VMM thread, then passed back the the API
// thread, and then unpacked into a http response using the implementation of
// the generate_response() method.
pub trait GenerateHyperResponse {
    fn generate_response(&self) -> hyper::Response;
}

impl GenerateHyperResponse for result::Result<VmmData, VmmActionError> {
    fn generate_response(&self) -> hyper::Response {
        match *self {
            Ok(ref data) => data.generate_response(),
            Err(ref error) => error.generate_response(),
        }
    }
}

impl GenerateHyperResponse for VmmData {
    fn generate_response(&self) -> hyper::Response {
        match *self {
            VmmData::MachineConfiguration(ref machine_config) => machine_config.generate_response(),
            VmmData::Empty => empty_response(StatusCode::NoContent),
        }
    }
}

impl GenerateHyperResponse for VmmActionError {
    fn generate_response(&self) -> hyper::Response {
        use self::ErrorKind::*;

        let status_code = match self.get_kind() {
            User => StatusCode::BadRequest,
            Internal => StatusCode::InternalServerError,
        };

        json_response(status_code, json_fault_message(self.to_string()))
    }
}

impl GenerateHyperResponse for () {
    fn generate_response(&self) -> hyper::Response {
        empty_response(StatusCode::NoContent)
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
