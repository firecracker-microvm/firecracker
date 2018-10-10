use std::fmt::{Display, Formatter, Result};
use std::mem;
use std::rc::Rc;
use std::result;

use super::DeviceState;
use data_model::vm::RateLimiterDescription;
use net_util::{MacAddr, Tap, TapError};

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

#[derive(Debug)]
pub enum NetworkInterfaceError {
    GuestMacAddressInUse(String),
    OpenTap(TapError),
    UpdateNotAllowedPostBoot,
}

impl Display for NetworkInterfaceError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        use self::NetworkInterfaceError::*;
        match *self {
            GuestMacAddressInUse(ref mac_addr) => write!(
                f,
                "{}",
                format!("The guest MAC address {} is already in use.", mac_addr)
            ),
            OpenTap(ref e) => {
                // We are propagating the Tap Error. This error can contain
                // imbricated quotes which would result in an invalid json.
                let mut tap_err = format!("{:?}", e);
                tap_err = tap_err.replace("\"", "");

                write!(
                    f,
                    "{}{}",
                    "Cannot open TAP device. Invalid name/permissions. ".to_string(),
                    tap_err
                )
            }
            UpdateNotAllowedPostBoot => {
                write!(f, "The update operation is not allowed after boot.",)
            }
        }
    }
}

pub struct NetworkInterfaceConfig {
    // The request body received from the API side.
    body: NetworkInterfaceBody,
    // We extract the id from the body and hold it as a reference counted String. This should
    // come in handy later on, when we'll need the id to appear in a number of data structures
    // to implement efficient lookup, update, deletion, etc.
    id: Rc<String>,
    // We open the tap that will be associated with the virtual device as soon as the PUT request
    // arrives from the API. We want to see if there are any errors associated with the operation,
    // and if so, we want to report the failure back to the API caller immediately. This is an
    // option, because the inner value will be moved to the actual virtio net device before boot.
    pub tap: Option<Tap>,
    pub rx_rate_limiter: Option<RateLimiterDescription>,
    pub tx_rate_limiter: Option<RateLimiterDescription>,
}

impl NetworkInterfaceConfig {
    pub fn try_from_body(mut body: NetworkInterfaceBody) -> result::Result<Self, TapError> {
        let id = Rc::new(mem::replace(&mut body.iface_id, String::new()));

        // TODO: rework net_util stuff such that references would suffice here, instead
        // of having to move things around.
        let tap = Tap::open_named(body.host_dev_name.as_str())?;

        let rx_rate_limiter = body.rx_rate_limiter.take();
        let tx_rate_limiter = body.tx_rate_limiter.take();
        Ok(NetworkInterfaceConfig {
            body,
            id,
            tap: Some(tap),
            rx_rate_limiter,
            tx_rate_limiter,
        })
    }

    fn update_from_body(&mut self, mut body: NetworkInterfaceBody) {
        self.id = Rc::new(mem::replace(&mut body.iface_id, String::new()));
        self.rx_rate_limiter = body.rx_rate_limiter.take();
        self.tx_rate_limiter = body.tx_rate_limiter.take();
        self.body = body;
    }

    pub fn take_tap(&mut self) -> Option<Tap> {
        self.tap.take()
    }

    pub fn guest_mac(&self) -> Option<&MacAddr> {
        self.body.guest_mac.as_ref()
    }

    pub fn allow_mmds_requests(&self) -> bool {
        self.body.allow_mmds_requests
    }
}

pub struct NetworkInterfaceConfigs {
    if_list: Vec<NetworkInterfaceConfig>,
}

impl NetworkInterfaceConfigs {
    pub fn new() -> Self {
        NetworkInterfaceConfigs {
            if_list: Vec::new(),
        }
    }

    pub fn insert(
        &mut self,
        body: NetworkInterfaceBody,
    ) -> result::Result<(), NetworkInterfaceError> {
        match self
            .if_list
            .iter()
            .position(|netif| netif.id.as_str() == body.iface_id.as_str())
        {
            Some(index) => self.update(index, body),
            None => self.create(body),
        }
    }

    pub fn iter_mut(&mut self) -> ::std::slice::IterMut<NetworkInterfaceConfig> {
        self.if_list.iter_mut()
    }

    fn create(&mut self, body: NetworkInterfaceBody) -> result::Result<(), NetworkInterfaceError> {
        self.validate_unique_mac(&body.guest_mac)?;
        let cfg =
            NetworkInterfaceConfig::try_from_body(body).map_err(NetworkInterfaceError::OpenTap)?;
        self.if_list.push(cfg);
        Ok(())
    }

    fn update(
        &mut self,
        index: usize,
        body: NetworkInterfaceBody,
    ) -> result::Result<(), NetworkInterfaceError> {
        if self.if_list[index].body.host_dev_name != body.host_dev_name {
            // This is a new tap device which replaces the one at the specified ID.
            self.if_list.remove(index);
            self.create(body)?;
        } else {
            // The same tap device is being updated.
            self.validate_unique_mac(&body.guest_mac)?;
            self.if_list[index].update_from_body(body);
        }
        Ok(())
    }

    fn validate_unique_mac(
        &self,
        mac: &Option<MacAddr>,
    ) -> result::Result<(), NetworkInterfaceError> {
        for device_config in self.if_list.iter() {
            if mac.is_some() && mac == &device_config.body.guest_mac {
                return Err(NetworkInterfaceError::GuestMacAddressInUse(
                    mac.unwrap().to_string(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_util::MacAddr;

    fn make_netif(id: &str, name: &str, mac: MacAddr) -> NetworkInterfaceBody {
        NetworkInterfaceBody {
            iface_id: String::from(id),
            state: DeviceState::Attached,
            host_dev_name: String::from(name),
            guest_mac: Some(mac),
            rx_rate_limiter: Some(RateLimiterDescription::default()),
            tx_rate_limiter: Some(RateLimiterDescription::default()),
            allow_mmds_requests: false,
        }
    }

    fn make_netif_cfg(body: NetworkInterfaceBody, id: &str) -> NetworkInterfaceConfig {
        NetworkInterfaceConfig {
            body: body,
            id: Rc::new(String::from(id)),
            tap: None,
            tx_rate_limiter: None,
            rx_rate_limiter: None,
        }
    }

    #[test]
    fn test_put() {
        let mut netif_configs = NetworkInterfaceConfigs::new();
        assert!(netif_configs.if_list.is_empty());

        let mac1 = MacAddr::parse_str("01:23:45:67:89:0A").unwrap();
        let mac2 = MacAddr::parse_str("23:45:67:89:0A:01").unwrap();
        let mac3 = MacAddr::parse_str("45:67:89:0A:01:23").unwrap();

        // Add an interface.
        let mut netif_body = make_netif("foo", "bar", mac1);
        netif_configs
            .if_list
            .push(make_netif_cfg(netif_body.clone(), "foo"));
        assert_eq!(netif_configs.if_list.len(), 1);

        // Update MAC.
        netif_body.guest_mac = Some(mac2.clone());
        assert!(netif_configs.insert(netif_body).is_ok());
        assert_eq!(netif_configs.if_list.len(), 1);

        // Try to add another interface with the same MAC.
        let mut other_netif_body = make_netif("bar", "foo", mac2.clone());
        assert!(netif_configs.insert(other_netif_body.clone()).is_err());
        assert_eq!(netif_configs.if_list.len(), 1);

        // Add another interface.
        other_netif_body.guest_mac = Some(mac3);
        netif_configs
            .if_list
            .push(make_netif_cfg(other_netif_body.clone(), "foo"));
        assert_eq!(netif_configs.if_list.len(), 2);

        // Try to update with an unavailable name.
        other_netif_body.host_dev_name = String::from("baz");
        assert!(netif_configs.insert(other_netif_body.clone()).is_err());
        assert_eq!(netif_configs.if_list.len(), 2);

        // Try to update with an unavailable MAC.
        other_netif_body.guest_mac = Some(mac2);
        assert!(netif_configs.insert(other_netif_body).is_err());
        assert_eq!(netif_configs.if_list.len(), 2);
    }
}
