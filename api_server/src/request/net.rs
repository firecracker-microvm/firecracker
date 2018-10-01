use std::result;

use futures::sync::oneshot;
use hyper::{Response, StatusCode};

use super::SyncRequest;

use data_model::vm::{DeviceState, RateLimiterDescription};
use http_service::{json_fault_message, json_response};
use net_util::{MacAddr, TapError};
use request::{GenerateResponse, ParsedRequest};

// This struct represents the strongly typed equivalent of the json body from net iface
// related requests.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkInterfaceBody {
    pub iface_id: String,
    pub state: DeviceState,
    pub host_dev_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest_mac: Option<MacAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_rate_limiter: Option<RateLimiterDescription>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_rate_limiter: Option<RateLimiterDescription>,
    #[serde(default = "default_allow_mmds_requests")]
    pub allow_mmds_requests: bool,
}

// Serde does not allow specifying a default value for a field
// that is not required. The workaround is to specify a function
// that returns the value.
fn default_allow_mmds_requests() -> bool {
    false
}

pub enum NetworkInterfaceError {
    OpenTap(TapError),
    GuestMacAddressInUse(String),
    UpdateNotAllowPostBoot,
}

impl GenerateResponse for NetworkInterfaceError {
    fn generate_response(&self) -> Response {
        use self::NetworkInterfaceError::*;

        match self {
            OpenTap(e) => {
                // We are propagating the Tap Error. This error can contain
                // imbricated quotes which would result in an invalid json.
                let mut tap_err = format!("{:?}", e);
                tap_err = tap_err.replace("\"", "");

                json_response(
                    StatusCode::BadRequest,
                    json_fault_message(format!(
                        "Cannot open TAP device. Invalid name/permissions. {}",
                        tap_err
                    )),
                )
            }
            GuestMacAddressInUse(mac_addr) => json_response(
                StatusCode::BadRequest,
                json_fault_message(format!(
                    "The guest MAC address {} is already in use.",
                    mac_addr
                )),
            ),
            UpdateNotAllowPostBoot => json_response(
                StatusCode::BadRequest,
                json_fault_message("The update operation is not allowed after boot."),
            ),
        }
    }
}

impl NetworkInterfaceBody {
    pub fn into_parsed_request(self, id_from_path: &str) -> result::Result<ParsedRequest, String> {
        if id_from_path != self.iface_id {
            return Err(String::from(
                "The id from the path does not match the id from the body!",
            ));
        }

        let (sender, receiver) = oneshot::channel();
        Ok(ParsedRequest::Sync(
            SyncRequest::PutNetworkInterface(self, sender),
            receiver,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use futures::{Future, Stream};
    use hyper::{Body, Response};
    use serde_json;
    use std;

    #[test]
    fn test_netif_into_parsed_request() {
        let netif = NetworkInterfaceBody {
            iface_id: String::from("foo"),
            state: DeviceState::Attached,
            host_dev_name: String::from("bar"),
            guest_mac: Some(MacAddr::parse_str("12:34:56:78:9A:BC").unwrap()),
            rx_rate_limiter: None,
            tx_rate_limiter: None,
            allow_mmds_requests: false,
        };

        assert!(netif.clone().into_parsed_request("bar").is_err());
        let (sender, receiver) = oneshot::channel();
        assert!(
            netif
                .clone()
                .into_parsed_request("foo")
                .eq(&Ok(ParsedRequest::Sync(
                    SyncRequest::PutNetworkInterface(netif, sender),
                    receiver
                )))
        );
    }

    #[test]
    fn test_network_interface_body_serialization_and_deserialization() {
        let netif = NetworkInterfaceBody {
            iface_id: String::from("foo"),
            state: DeviceState::Attached,
            host_dev_name: String::from("bar"),
            guest_mac: Some(MacAddr::parse_str("12:34:56:78:9A:BC").unwrap()),
            rx_rate_limiter: Some(RateLimiterDescription::default()),
            tx_rate_limiter: Some(RateLimiterDescription::default()),
            allow_mmds_requests: true,
        };

        // This is the json encoding of the netif variable.
        let jstr = r#"{
            "iface_id": "foo",
            "host_dev_name": "bar",
            "state": "Attached",
            "guest_mac": "12:34:56:78:9A:bc",
            "rx_rate_limiter": {
            },
            "tx_rate_limiter": {
            },
            "allow_mmds_requests": true
        }"#;

        let x = serde_json::from_str(jstr).expect("deserialization failed.");
        assert_eq!(netif, x);

        let y = serde_json::to_string(&netif).expect("serialization failed.");
        let z = serde_json::from_str(y.as_ref()).expect("deserialization (2) failed.");
        assert_eq!(x, z);

        // Check that guest_mac and rate limiters are truly optional.
        let jstr_no_mac = r#"{
            "iface_id": "foo",
            "host_dev_name": "bar",
            "state": "Attached"
        }"#;

        assert!(serde_json::from_str::<NetworkInterfaceBody>(jstr_no_mac).is_ok())
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
        serde_json::from_str::<serde_json::Value>(body.wait().unwrap().as_ref())
    }

    #[test]
    fn test_generate_response_error() {
        let ret = NetworkInterfaceError::OpenTap(TapError::OpenTun(
            std::io::Error::from_raw_os_error(22),
        )).generate_response();
        assert_eq!(ret.status(), StatusCode::BadRequest);
        assert!(get_body(ret).is_ok());

        let mac_addr = MacAddr::parse_str("12:34:56:78:9a:bc").unwrap();
        let ret =
            NetworkInterfaceError::GuestMacAddressInUse(mac_addr.to_string()).generate_response();
        assert_eq!(ret.status(), StatusCode::BadRequest);
        let body = get_body(ret).unwrap();
        let expected_body = r#"{
            "fault_message": "The guest MAC address 12:34:56:78:9a:bc is already in use."
        }"#;
        let expected_body: serde_json::Value = serde_json::from_str(expected_body).unwrap();
        assert_eq!(body, expected_body);

        let ret = NetworkInterfaceError::UpdateNotAllowPostBoot.generate_response();
        assert_eq!(ret.status(), StatusCode::BadRequest);
        assert!(get_body(ret).is_ok());
    }
}
