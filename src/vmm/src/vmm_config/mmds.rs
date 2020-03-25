// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::net::Ipv4Addr;

/// Keeps the MMDS configuration.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MmdsConfig {
    /// MMDS IPv4 configured address.
    ipv4_address: Option<Ipv4Addr>,
}

impl MmdsConfig {
    /// Returns the MMDS IPv4 address if one was configured.
    /// Otherwise returns None.
    pub fn ipv4_addr(&self) -> Option<Ipv4Addr> {
        self.ipv4_address
    }
}
