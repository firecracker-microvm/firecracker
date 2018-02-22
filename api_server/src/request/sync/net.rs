use std::net::Ipv4Addr;
use std::result;

use futures::sync::oneshot;
use hyper::{self, StatusCode};

use request::ParsedRequest;
use http_service::{empty_response, json_fault_message, json_response};
use super::{DeviceState, GenerateResponse, SyncRequest};

fn default_host_netmask() -> Ipv4Addr {
    // this is as valid as they come
    "255.255.255.0".parse().unwrap()
}

// This struct represents the strongly typed equivalent of the json body from net iface
// related requests.
// TODO: change swagger API description to reflect the changes.
#[derive(Debug, Deserialize, Serialize)]
pub struct NetworkInterfaceBody {
    pub iface_id: String,
    pub state: DeviceState,
    pub host_dev_name: String,
    pub host_ipv4_address: Ipv4Addr,
    #[serde(default = "default_host_netmask")] pub host_netmask: Ipv4Addr,
    #[serde(skip_serializing_if = "Option::is_none")] pub guest_mac: Option<String>,
}

impl NetworkInterfaceBody {
    pub fn into_parsed_request(self, _id_from_path: &str) -> result::Result<ParsedRequest, String> {
        // todo: any validation?
        let (sender, receiver) = oneshot::channel();
        Ok(ParsedRequest::Sync(
            SyncRequest::PutNetworkInterface(self, sender),
            receiver,
        ))
    }
}

// This enum contains errors that can occur when the VMM processes a network interface
// related sync request.
#[derive(Debug)]
pub enum NetworkInterfaceError {
    TapError,
}

impl GenerateResponse for NetworkInterfaceError {
    fn generate_response(&self) -> hyper::Response {
        use self::NetworkInterfaceError::*;
        match *self {
            TapError => json_response(
                StatusCode::BadRequest,
                json_fault_message("Could not create TAP device."),
            ),
        }
    }
}

pub enum PutIfaceOutcome {
    Created,
    Error(NetworkInterfaceError),
}

impl GenerateResponse for PutIfaceOutcome {
    fn generate_response(&self) -> hyper::Response {
        use self::PutIfaceOutcome::*;
        match *self {
            Created => empty_response(StatusCode::Created),
            Error(ref error) => error.generate_response(),
        }
    }
}
