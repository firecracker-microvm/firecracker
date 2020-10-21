// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Configurations used in the migration context.

use serde::{de, Deserialize, Serialize};
use std::net::SocketAddr;
use std::str::FromStr;

/// Stores the configuration that will be used for starting a migration.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StartMigrationParams {
    /// The address of the destination host.
    #[serde(deserialize_with = "deserialize_ip")]
    pub destination: SocketAddr,
}

/// Stores the configuration that will be used for starting a migration.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptMigrationParams {
    /// The address of the destination host.
    #[serde(deserialize_with = "deserialize_ip")]
    pub destination: SocketAddr,
}

fn deserialize_ip<'de, D>(d: D) -> std::result::Result<SocketAddr, D::Error>
where
    D: de::Deserializer<'de>,
{
    let val = String::deserialize(d)?;

    Ok(SocketAddr::from_str(val.as_str()).map_err(|_| {
        de::Error::invalid_value(
            de::Unexpected::Other(val.as_str()),
            &"Invalid IP Address provided",
        )
    })?)
}
