// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use mmds::data_store;
use mmds::data_store::MmdsVersion;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter, Result};
use std::net::Ipv4Addr;

/// Keeps the MMDS configuration.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MmdsConfig {
    /// MMDS version.
    #[serde(default)]
    pub version: MmdsVersion,
    /// Network interfaces that allow forwarding packets to MMDS.
    pub network_interfaces: Vec<String>,
    /// MMDS IPv4 configured address.
    pub ipv4_address: Option<Ipv4Addr>,
}

impl MmdsConfig {
    /// Returns the MMDS version configured.
    pub fn version(&self) -> MmdsVersion {
        self.version
    }

    /// Returns the network interfaces that accept MMDS requests.
    pub fn network_interfaces(&self) -> Vec<String> {
        self.network_interfaces.clone()
    }

    /// Returns the MMDS IPv4 address if one was configured.
    /// Otherwise returns None.
    pub fn ipv4_addr(&self) -> Option<Ipv4Addr> {
        self.ipv4_address
    }
}

/// MMDS configuration related errors.
#[derive(Debug)]
pub enum MmdsConfigError {
    /// The network interfaces list provided is empty.
    EmptyNetworkIfaceList,
    /// The provided IPv4 address is not link-local valid.
    InvalidIpv4Addr,
    /// The network interfaces list provided contains IDs that
    /// does not correspond to any existing network interface.
    InvalidNetworkInterfaceId,
    /// MMDS version could not be configured.
    MmdsVersion(MmdsVersion, data_store::Error),
}

impl Display for MmdsConfigError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            MmdsConfigError::EmptyNetworkIfaceList => {
                write!(
                    f,
                    "The list of network interface IDs that allow \
                    forwarding MMDS requests is empty."
                )
            }
            MmdsConfigError::InvalidIpv4Addr => {
                write!(f, "The MMDS IPv4 address is not link local.")
            }
            MmdsConfigError::InvalidNetworkInterfaceId => {
                write!(
                    f,
                    "The list of network interface IDs provided contains at least one ID \
                    that does not correspond to any existing network interface."
                )
            }
            MmdsConfigError::MmdsVersion(version, err) => {
                write!(
                    f,
                    "The MMDS could not be configured to version {}: {}",
                    version, err
                )
            }
        }
    }
}
