// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::mmds::data_store;
use crate::mmds::data_store::MmdsVersion;

/// Keeps the MMDS configuration.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MmdsConfig {
    /// MMDS version.
    #[serde(default)]
    pub version: MmdsVersion,
    /// Network interfaces that allow forwarding packets to MMDS.
    pub network_interfaces: Vec<String>,
    /// MMDS IPv4 configured address.
    pub ipv4_address: Option<Ipv4Addr>,
    /// Compatibility with EC2 IMDS.
    #[serde(default)]
    pub imds_compat: bool,
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
#[rustfmt::skip]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum MmdsConfigError {
    /// The list of network interface IDs that allow forwarding MMDS requests is empty.
    EmptyNetworkIfaceList,
    /// The MMDS IPv4 address is not link local.
    InvalidIpv4Addr,
    /// The list of network interface IDs provided contains at least one ID that does not correspond to any existing network interface.
    InvalidNetworkInterfaceId,
    /// Failed to initialize MMDS data store: {0}
    InitMmdsDatastore(#[from] data_store::MmdsDatastoreError),
}
