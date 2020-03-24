// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{Display, Formatter, Result};
use std::result;

use super::RateLimiterConfig;
use dumbo::MacAddr;
use utils::net::{Tap, TapError};

/// This struct represents the strongly typed equivalent of the json body from net iface
/// related requests.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NetworkInterfaceConfig {
    /// ID of the guest network interface.
    pub iface_id: String,
    /// Host level path for the guest network interface.
    pub host_dev_name: String,
    /// Guest MAC address.
    pub guest_mac: Option<MacAddr>,
    /// Rate Limiter for received packages.
    pub rx_rate_limiter: Option<RateLimiterConfig>,
    /// Rate Limiter for transmitted packages.
    pub tx_rate_limiter: Option<RateLimiterConfig>,
    #[serde(default = "default_allow_mmds_requests")]
    /// If this field is set, the device model will reply to HTTP GET
    /// requests sent to the MMDS address via this interface. In this case,
    /// both ARP requests for `169.254.169.254` and TCP segments heading to the
    /// same address are intercepted by the device model, and do not reach
    /// the associated TAP device.
    pub allow_mmds_requests: bool,
}

// Serde does not allow specifying a default value for a field
// that is not required. The workaround is to specify a function
// that returns the value.
fn default_allow_mmds_requests() -> bool {
    false
}

impl NetworkInterfaceConfig {
    /// Returns the tap device that `host_dev_name` refers to.
    pub fn open_tap(&self) -> result::Result<Tap, NetworkInterfaceError> {
        Tap::open_named(self.host_dev_name.as_str()).map_err(NetworkInterfaceError::OpenTap)
    }
}

/// The data fed into a network iface update request. Currently, only the RX and TX rate limiters
/// can be updated.
#[derive(Debug, Deserialize, PartialEq, Clone)]
#[serde(deny_unknown_fields)]
pub struct NetworkInterfaceUpdateConfig {
    /// The net iface ID, as provided by the user at iface creation time.
    pub iface_id: String,
    /// New RX rate limiter config. Only provided data will be updated. I.e. if any optional data
    /// is missing, it will not be nullified, but left unchanged.
    pub rx_rate_limiter: Option<RateLimiterConfig>,
    /// New TX rate limiter config. Only provided data will be updated. I.e. if any optional data
    /// is missing, it will not be nullified, but left unchanged.
    pub tx_rate_limiter: Option<RateLimiterConfig>,
}

/// Errors associated with `NetworkInterfaceConfig`.
#[derive(Debug)]
pub enum NetworkInterfaceError {
    /// The MAC address is already in use.
    GuestMacAddressInUse(String),
    /// The host device name is already in use.
    HostDeviceNameInUse(String),
    /// Couldn't find the interface to update (patch).
    DeviceIdNotFound,
    /// Cannot open/create tap device.
    OpenTap(TapError),
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
            HostDeviceNameInUse(ref host_dev_name) => write!(
                f,
                "{}",
                format!("The host device name {} is already in use.", host_dev_name)
            ),
            DeviceIdNotFound => write!(f, "Invalid interface ID - not found."),
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
        }
    }
}

/// A wrapper over the list of the `NetworkInterfaceConfig` that the microvm has configured.
#[derive(Default)]
pub struct NetworkInterfaceConfigs {
    if_list: Vec<NetworkInterfaceConfig>,
}

impl NetworkInterfaceConfigs {
    /// Creates an empty list of NetworkInterfaceConfig.
    pub fn new() -> Self {
        NetworkInterfaceConfigs {
            if_list: Vec::new(),
        }
    }

    /// Returns a immutable iterator over the network interfaces.
    pub fn iter(&self) -> ::std::slice::Iter<NetworkInterfaceConfig> {
        self.if_list.iter()
    }

    /// Returns a mutable iterator over the network interfaces.
    pub fn iter_mut(&mut self) -> ::std::slice::IterMut<NetworkInterfaceConfig> {
        self.if_list.iter_mut()
    }

    /// Inserts `netif_config` in the network interface configuration list.
    /// If an entry with the same id already exists, it will update the existing
    /// entry.
    pub fn insert(
        &mut self,
        netif_config: NetworkInterfaceConfig,
    ) -> result::Result<(), NetworkInterfaceError> {
        // Validate there is no Mac or HostDevName conflict.
        if let Some(cfg) = self.if_list.iter().find(|&cfg| {
            // Check that no other config has same MAC or host_dev_name.
            cfg.iface_id != netif_config.iface_id
                && (cfg.host_dev_name == netif_config.host_dev_name
                    || (cfg.guest_mac.is_some() && cfg.guest_mac == netif_config.guest_mac))
        }) {
            // MAC or HostDevName conflict found.
            return if cfg.host_dev_name == netif_config.host_dev_name {
                Err(NetworkInterfaceError::HostDeviceNameInUse(
                    netif_config.host_dev_name,
                ))
            } else {
                Err(NetworkInterfaceError::GuestMacAddressInUse(
                    netif_config.guest_mac.unwrap().to_string(),
                ))
            };
        }

        match self
            .if_list
            .iter()
            .position(|netif_from_list| netif_from_list.iface_id == netif_config.iface_id)
        {
            Some(index) => self.if_list[index] = netif_config,
            None => self.if_list.push(netif_config),
        };
        Ok(())
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.if_list.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.if_list.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use std::str;

    use super::*;

    fn create_netif(id: &str, name: &str, mac: &str) -> NetworkInterfaceConfig {
        NetworkInterfaceConfig {
            iface_id: String::from(id),
            host_dev_name: String::from(name),
            guest_mac: Some(MacAddr::parse_str(mac).unwrap()),
            rx_rate_limiter: Some(RateLimiterConfig::default()),
            tx_rate_limiter: Some(RateLimiterConfig::default()),
            allow_mmds_requests: false,
        }
    }

    impl Clone for NetworkInterfaceConfig {
        fn clone(&self) -> Self {
            NetworkInterfaceConfig {
                iface_id: self.iface_id.clone(),
                host_dev_name: self.host_dev_name.clone(),
                guest_mac: self.guest_mac,
                rx_rate_limiter: None,
                tx_rate_limiter: None,
                allow_mmds_requests: self.allow_mmds_requests,
            }
        }
    }

    #[test]
    fn test_insert() {
        let mut netif_configs = NetworkInterfaceConfigs::new();

        let id_1 = "id_1";
        let mut host_dev_name_1 = "dev1";
        let mut guest_mac_1 = "01:23:45:67:89:0a";

        // Test create.
        let netif_1 = create_netif(id_1, host_dev_name_1, guest_mac_1);
        assert!(netif_configs.insert(netif_1).is_ok());
        assert_eq!(netif_configs.if_list.len(), 1);

        // Test update mac address (this test does not modify the tap).
        guest_mac_1 = "01:23:45:67:89:0b";
        let netif_1 = create_netif(id_1, host_dev_name_1, guest_mac_1);

        assert!(netif_configs.insert(netif_1.clone()).is_ok());
        assert_eq!(netif_configs.if_list.len(), 1);

        // Test update host_dev_name (the tap will be updated).
        host_dev_name_1 = "dev2";
        let netif_1 = create_netif(id_1, host_dev_name_1, guest_mac_1);
        assert!(netif_configs.insert(netif_1.clone()).is_ok());
        assert_eq!(netif_configs.if_list.len(), 1);
    }

    #[test]
    fn test_insert_error_cases() {
        let mut netif_configs = NetworkInterfaceConfigs::new();

        let id_1 = "id_1";
        let host_dev_name_1 = "dev3";
        let guest_mac_1 = "01:23:45:67:89:0a";

        // Adding the first valid network config.
        let netif_1 = create_netif(id_1, host_dev_name_1, guest_mac_1);
        assert!(netif_configs.insert(netif_1.clone()).is_ok());

        // Error Cases for CREATE
        // Error Case: Add new network config with the same mac as netif_1.
        let id_2 = "id_2";
        let host_dev_name_2 = "dev4";
        let guest_mac_2 = "01:23:45:67:89:0b";

        let netif_2 = create_netif(id_2, host_dev_name_2, guest_mac_1);
        let expected_error = format!(
            "The guest MAC address {} is already in use.",
            guest_mac_1.to_string()
        );
        assert_eq!(
            netif_configs
                .insert(netif_2.clone())
                .unwrap_err()
                .to_string(),
            expected_error
        );
        assert_eq!(netif_configs.if_list.len(), 1);

        // Error Case: Add new network config with the same dev_host_name as netif_1.
        let netif_2 = create_netif(id_2, host_dev_name_1, guest_mac_2);
        let expected_error = format!(
            "The host device name {} is already in use.",
            netif_2.host_dev_name
        );
        assert_eq!(
            netif_configs
                .insert(netif_2.clone())
                .unwrap_err()
                .to_string(),
            expected_error
        );
        assert_eq!(netif_configs.if_list.len(), 1);

        // Adding the second valid network config.
        let netif_2 = create_netif(id_2, host_dev_name_2, guest_mac_2);
        assert!(netif_configs.insert(netif_2.clone()).is_ok());

        // Error Cases for UPDATE
        // Error Case: Update netif_2 mac using the same mac as netif_1.
        let netif_2 = create_netif(id_2, host_dev_name_2, guest_mac_1);
        let expected_error = format!(
            "The guest MAC address {} is already in use.",
            guest_mac_1.to_string()
        );
        assert_eq!(
            netif_configs
                .insert(netif_2.clone())
                .unwrap_err()
                .to_string(),
            expected_error
        );

        // Error Case: Update netif_2 dev_host_name using the same dev_host_name as netif_1.
        let netif_2 = create_netif(id_2, host_dev_name_1, guest_mac_2);
        let expected_error = format!(
            "The host device name {} is already in use.",
            netif_2.host_dev_name
        );
        assert_eq!(
            netif_configs
                .insert(netif_2.clone())
                .unwrap_err()
                .to_string(),
            expected_error
        );
    }

    #[test]
    fn test_error_display() {
        let _ = format!(
            "{}{:?}",
            NetworkInterfaceError::GuestMacAddressInUse("00:00:00:00:00:00".to_string()),
            NetworkInterfaceError::GuestMacAddressInUse("00:00:00:00:00:00".to_string())
        );
        let _ = format!(
            "{}{:?}",
            NetworkInterfaceError::HostDeviceNameInUse("hostdev".to_string()),
            NetworkInterfaceError::HostDeviceNameInUse("hostdev".to_string())
        );
        let _ = format!(
            "{}{:?}",
            NetworkInterfaceError::DeviceIdNotFound,
            NetworkInterfaceError::DeviceIdNotFound
        );
        let _ = format!(
            "{}{:?}",
            NetworkInterfaceError::OpenTap(TapError::InvalidIfname),
            NetworkInterfaceError::OpenTap(TapError::InvalidIfname)
        );
    }

    #[test]
    fn test_net_config() {
        let net_id = "id";
        let host_dev_name = "dev";
        let guest_mac = "01:23:45:67:89:0b";

        let net_if = create_netif(net_id, host_dev_name, guest_mac);
        assert_eq!(
            net_if.guest_mac.unwrap(),
            MacAddr::parse_str(guest_mac).unwrap()
        );
        assert_eq!(net_if.allow_mmds_requests, false);
    }
}
