use std::result;

use super::{DeviceState, RateLimiterConfig};
use net_util::{MacAddr, Tap, TapError};

// This struct represents the strongly typed equivalent of the json body from net iface
// related requests.
#[derive(Debug, Deserialize, Serialize)]
pub struct NetworkInterfaceConfig {
    iface_id: String,
    state: DeviceState,
    host_dev_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    guest_mac: Option<MacAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rx_rate_limiter: Option<RateLimiterConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_rate_limiter: Option<RateLimiterConfig>,
    #[serde(skip_serializing)]
    #[serde(skip_deserializing)]
    tap: Option<Tap>,
}

impl NetworkInterfaceConfig {
    pub fn get_id(&self) -> &String {
        &self.iface_id
    }

    pub fn open_tap(&mut self) -> result::Result<(), TapError> {
        match Tap::open_named(&self.host_dev_name) {
            Ok(t) => {
                self.tap = Some(t);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub fn take_tap(&mut self) -> Option<Tap> {
        self.tap.take()
    }

    pub fn guest_mac(&self) -> Option<&MacAddr> {
        self.guest_mac.as_ref()
    }

    pub fn get_rx_rate_limiter(&self) -> Option<&RateLimiterConfig> {
        self.rx_rate_limiter.as_ref()
    }

    pub fn get_tx_rate_limiter(&self) -> Option<&RateLimiterConfig> {
        self.tx_rate_limiter.as_ref()
    }
}

impl PartialEq for NetworkInterfaceConfig {
    fn eq(&self, other: &NetworkInterfaceConfig) -> bool {
        let mut is_mac_equal = false;
        if self.guest_mac.is_some() && other.guest_mac.is_some() {
            is_mac_equal = self.guest_mac == other.guest_mac;
        } else if self.guest_mac.is_none() && other.guest_mac.is_none() {
            is_mac_equal = true;
        }
        self.iface_id == other.iface_id && self.state == other.state
            && self.host_dev_name == other.host_dev_name && is_mac_equal
    }
}

#[cfg(test)]
mod tests {
    extern crate serde_json;

    use super::*;

    #[test]
    fn test_mac_deserialize() {
        let j = r#"{
                "iface_id": "bar",
                "state": "Attached",
                "host_dev_name": "foo",
                "guest_mac": "12:34:56:78:9a:bc"
              }"#;
        let result: NetworkInterfaceConfig = serde_json::from_str(j).unwrap();

        assert_eq!(
            format!("{:?}", result), "NetworkInterfaceConfig { iface_id: \"bar\", state: Attached, \
            host_dev_name: \"foo\", guest_mac: Some(MacAddr { bytes: [18, 52, 86, 120, 154, 188] }), rx_rate_limiter: None, tx_rate_limiter: None, tap: None }",
        );

        let result = serde_json::to_string(&result);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            String::from(j).replace("\n", "").replace(" ", "")
        );

        let j = r#"{
                "iface_id": "bar",
                "state\": "Attached",
                "host_dev_name": "foo",
                "guest_mac": "12:34:56:78:9A:B"
              }"#;
        let result: Result<NetworkInterfaceConfig, serde_json::Error> = serde_json::from_str(j);
        assert!(result.is_err());

        let j = r#"{
                "iface_id": "bar",
                "state": "Attached",
                "host_dev_name": \"foo",
                "guest_mac": "12:34:56:78:9A-BC"
              }"#;
        let result: Result<NetworkInterfaceConfig, serde_json::Error> = serde_json::from_str(j);
        assert!(result.is_err());

        let j = r#"{
                "iface_id": "bar",
                "state": "Attached",
                "host_dev_name": "foo",
                "guest_mac": "12:34:56:78:9A"
              }"#;
        let result: Result<NetworkInterfaceConfig, serde_json::Error> = serde_json::from_str(j);
        assert!(result.is_err());

        let j = r#"{
                "iface_id": "bar",
                "state": "Attached",
                "host_dev_name": "foo",
                "guest_mac": "12:34:56:78:9a:bc"
              }"#;
        let result: Result<NetworkInterfaceConfig, serde_json::Error> = serde_json::from_str(j);
        assert!(result.is_ok());

        // test serialization
        let y = serde_json::to_string(&result.unwrap()).expect("serialization failed.");
        assert_eq!(String::from(j).replace("\n", "").replace(" ", ""), y);

        // Check that guest_mac is truly optional.
        let jstr_no_mac = r#"{
            "iface_id": "foo",
            "host_dev_name": "bar",
            "state": "Attached"
        }"#;

        assert!(serde_json::from_str::<NetworkInterfaceConfig>(jstr_no_mac).is_ok())
    }
}
