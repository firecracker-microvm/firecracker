use std::collections::linked_list::{self, LinkedList};
use std::result;

use api_server::request::sync::{Error as SyncError, OkStatus as SyncOkStatus};
use data_model::device_config::NetworkInterfaceConfig;

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

    pub fn put(
        &mut self,
        mut body: NetworkInterfaceConfig,
    ) -> result::Result<SyncOkStatus, SyncError> {
        body.open_tap().map_err(SyncError::OpenTap)?;

        for x in self.if_list.iter() {
            if x.get_id() == body.get_id() {
                return Err(SyncError::UpdateNotImplemented);
            }
            if x.guest_mac() == body.guest_mac() {
                return Err(SyncError::GuestMacAddressInUse);
            }
        }
        self.if_list.push_back(body);
        Ok(SyncOkStatus::Created)
    }

    pub fn iter_mut(&mut self) -> linked_list::IterMut<NetworkInterfaceConfig> {
        self.if_list.iter_mut()
    }
}

#[cfg(test)]
mod tests {
    extern crate serde_json;

    use super::*;

    #[test]
    fn test_network_interface_configs() {
        let mut net_cfgs = NetworkInterfaceConfigs::new();

        let j = r#"{
                "iface_id": "foo",
                "state": "Attached",
                "host_dev_name": "bar",
                "guest_mac": "12:34:56:78:9A:BC"
              }"#;
        let netif: NetworkInterfaceConfig = serde_json::from_str(j).unwrap();
        assert_eq!(netif.get_id(), &String::from("foo"));
        assert_eq!(netif.guest_mac().unwrap().to_string(), "12:34:56:78:9a:bc");

        assert!(net_cfgs.put(netif).is_ok());

        let j = r#"{
                "iface_id": "foo",
                "state": "Attached",
                "host_dev_name": "bar1",
                "guest_mac": "12:34:56:78:9A:BC"
              }"#;
        let netif: NetworkInterfaceConfig = serde_json::from_str(j).unwrap();

        assert_eq!(
            format!("{:?}", net_cfgs.put(netif).err().unwrap()),
            "UpdateNotImplemented"
        );

        let j = r#"{
                "iface_id": "foo1",
                "state": "Attached",
                "host_dev_name": "bar2",
                "guest_mac": "12:34:56:78:9A:BC"
              }"#;
        let netif: NetworkInterfaceConfig = serde_json::from_str(j).unwrap();
        assert_eq!(
            format!("{:?}", net_cfgs.put(netif).err().unwrap()),
            "GuestMacAddressInUse"
        );

        //testing iter mut and take_tap
        assert_eq!(net_cfgs.iter_mut().len(), 1);
        for cfg in net_cfgs.iter_mut() {
            assert!(cfg.take_tap().is_some());
            assert_eq!(cfg.take_tap().is_some(), false);
        }
    }
}
