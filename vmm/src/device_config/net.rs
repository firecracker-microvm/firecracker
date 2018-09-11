use std::mem;
use std::rc::Rc;
use std::result;

use api_server::request::sync::{
    Error as SyncError, NetworkInterfaceBody, OkStatus as SyncOkStatus,
};
use data_model::vm::RateLimiterDescription;
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

    pub fn put(&mut self, body: NetworkInterfaceBody) -> result::Result<SyncOkStatus, SyncError> {
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

    fn create(&mut self, body: NetworkInterfaceBody) -> result::Result<SyncOkStatus, SyncError> {
        self.validate_unique_mac(&body.guest_mac)?;
        let cfg = NetworkInterfaceConfig::try_from_body(body).map_err(SyncError::OpenTap)?;
        self.if_list.push(cfg);
        Ok(SyncOkStatus::Created)
    }

    fn update(
        &mut self,
        index: usize,
        body: NetworkInterfaceBody,
    ) -> result::Result<SyncOkStatus, SyncError> {
        if self.if_list[index].body.host_dev_name != body.host_dev_name {
            // This is a new tap device which replaces the one at the specified ID.
            self.if_list.remove(index);
            self.create(body)?;
        } else {
            // The same tap device is being updated.
            self.validate_unique_mac(&body.guest_mac)?;
            self.if_list[index].update_from_body(body);
        }
        Ok(SyncOkStatus::Updated)
    }

    fn validate_unique_mac(&self, mac: &Option<MacAddr>) -> result::Result<(), SyncError> {
        for device_config in self.if_list.iter() {
            if mac.is_some() && mac == &device_config.body.guest_mac {
                return Err(SyncError::GuestMacAddressInUse);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_model::vm::DeviceState;
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
        assert!(netif_configs.put(netif_body).is_ok());
        assert_eq!(netif_configs.if_list.len(), 1);

        // Try to add another interface with the same MAC.
        let mut other_netif_body = make_netif("bar", "foo", mac2.clone());
        assert!(netif_configs.put(other_netif_body.clone()).is_err());
        assert_eq!(netif_configs.if_list.len(), 1);

        // Add another interface.
        other_netif_body.guest_mac = Some(mac3);
        netif_configs
            .if_list
            .push(make_netif_cfg(other_netif_body.clone(), "foo"));
        assert_eq!(netif_configs.if_list.len(), 2);

        // Try to update with an unavailable name.
        other_netif_body.host_dev_name = String::from("baz");
        assert!(netif_configs.put(other_netif_body.clone()).is_err());
        assert_eq!(netif_configs.if_list.len(), 2);

        // Try to update with an unavailable MAC.
        other_netif_body.guest_mac = Some(mac2);
        assert!(netif_configs.put(other_netif_body).is_err());
        assert_eq!(netif_configs.if_list.len(), 2);
    }
}
