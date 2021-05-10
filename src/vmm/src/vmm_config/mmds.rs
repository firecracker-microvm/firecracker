// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{export::Formatter, Deserialize};
use std::fmt::{Display, Result};
use std::net::Ipv4Addr;

/// Keeps the MMDS configuration.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MmdsConfig {
    /// MMDS IPv4 configured address.
    pub ipv4_address: Option<Ipv4Addr>,
}

impl MmdsConfig {
    /// Returns the MMDS IPv4 address if one was configured.
    /// Otherwise returns None.
    pub fn ipv4_addr(&self) -> Option<Ipv4Addr> {
        self.ipv4_address
    }
}

/// MMDS configuration related errors.
#[derive(Debug)]
pub enum MmdsConfigError {
    /// The provided IPv4 address is not link-local valid.
    InvalidIpv4Addr,
}

impl Display for MmdsConfigError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            MmdsConfigError::InvalidIpv4Addr => {
                write!(f, "The MMDS IPv4 address is not link local.")
            }
        }
    }
}
