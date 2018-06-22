use std::collections::linked_list::{self, LinkedList};
use std::mem;
use std::rc::Rc;
use std::result;

use api_server::request::sync::{
    Error as SyncError, NetworkInterfaceBody, OkStatus as SyncOkStatus, RateLimiterDescription,
};
use net_util::{MacAddr, Tap, TapError};

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

    pub fn id_as_str(&self) -> &str {
        self.id.as_str()
    }

    pub fn take_tap(&mut self) -> Option<Tap> {
        self.tap.take()
    }

    pub fn guest_mac(&self) -> Option<&MacAddr> {
        self.body.guest_mac.as_ref()
    }
}

pub struct NetworkInterfaceConfigs {
    // We use just a list for now, since we only add interfaces as this point.
    if_list: LinkedList<NetworkInterfaceConfig>,
}

impl NetworkInterfaceConfigs {
    pub fn new() -> Self {
        NetworkInterfaceConfigs {
            if_list: LinkedList::new(),
        }
    }

    pub fn put(&mut self, body: NetworkInterfaceBody) -> result::Result<SyncOkStatus, SyncError> {
        let cfg = NetworkInterfaceConfig::try_from_body(body).map_err(SyncError::OpenTap)?;
        for device_config in self.if_list.iter_mut() {
            if device_config.id_as_str() == cfg.id_as_str() {
                device_config.tap = cfg.tap;
                device_config.body = cfg.body.clone();
                return Ok(SyncOkStatus::Updated);
            }

            if cfg.guest_mac().is_some() && device_config.guest_mac() == cfg.guest_mac() {
                return Err(SyncError::GuestMacAddressInUse);
            }
        }
        self.if_list.push_back(cfg);
        Ok(SyncOkStatus::Created)
    }

    pub fn iter_mut(&mut self) -> linked_list::IterMut<NetworkInterfaceConfig> {
        self.if_list.iter_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use api_server::request::sync::DeviceState;
    use net_util::MacAddr;

    #[test]
    fn test_put() {
        let mut netif_configs = NetworkInterfaceConfigs::new();
        assert!(netif_configs.if_list.is_empty());

        if let Ok(mac) = MacAddr::parse_str("01:23:45:67:89:0A") {
            let mut netif_body = NetworkInterfaceBody {
                iface_id: String::from("foo"),
                state: DeviceState::Attached,
                host_dev_name: String::from("bar"),
                guest_mac: Some(mac.clone()),
                rx_rate_limiter: Some(RateLimiterDescription::default()),
                tx_rate_limiter: Some(RateLimiterDescription::default()),
            };
            assert!(netif_configs.put(netif_body.clone()).is_ok());
            assert_eq!(netif_configs.if_list.len(), 1);

            netif_body.host_dev_name = String::from("baz");
            assert!(netif_configs.put(netif_body).is_ok());
            assert_eq!(netif_configs.if_list.len(), 1);

            let other_netif_body = NetworkInterfaceBody {
                iface_id: String::from("bar"),
                state: DeviceState::Attached,
                host_dev_name: String::from("foo"),
                guest_mac: Some(mac.clone()),
                rx_rate_limiter: None,
                tx_rate_limiter: None,
            };
            assert!(netif_configs.put(other_netif_body).is_err());
            assert_eq!(netif_configs.if_list.len(), 1);
        }
    }
}
