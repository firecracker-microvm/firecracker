// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{de, Deserialize};
use std::fmt;

/// Configure a custom list of whitelisted syscalls for a specific architecture and toolchain.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SyscallWhitelistConfig {
    /// Architecture to whitelist syscalls for.
    #[serde(
        skip_serializing_if = "Option::is_none",
        deserialize_with = "validate_arch"
    )]
    pub arch: Option<String>,

    /// Toolchain to whitelist syscalls for.
    #[serde(
        skip_serializing_if = "Option::is_none",
        deserialize_with = "validate_toolchain"
    )]
    pub toolchain: Option<String>,

    /// List of syscall numbers for given architecture and toolchain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syscalls: Option<Vec<i64>>
}

impl fmt::Display for SyscallWhitelistConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let arch = self.arch.clone().unwrap();
        let toolchain = self.toolchain.clone().unwrap();
        let syscalls = &self.syscalls;

        write!(f, "{{ \"arch\": {:?}, \"toolchain\": {:?},  \"syscalls\": {:?}",
               arch, toolchain, syscalls)
    }
}

fn validate_arch<'de, D>(d: D) -> std::result::Result<Option<String>, D::Error>
where
    D: de::Deserializer<'de>,
{
    let val = Option::<String>::deserialize(d)?;

    if let Some(ref value) = val {
        if *value != "x86_64" && *value != "aarch64" {
            return Err(de::Error::invalid_value(
                de::Unexpected::Str(&val.unwrap()),
                &"unknown architecture supplied, must be \"x86_64\" or \"aarch64\"",
            ));
        }
    }

    Ok(val)
}

fn validate_toolchain<'de, D>(d: D) -> std::result::Result<Option<String>, D::Error>
where
    D: de::Deserializer<'de>,
{
    let val = Option::<String>::deserialize(d)?;

    if let Some(ref value) = val {
        if *value != "musl" && *value != "gnu" {
            return Err(de::Error::invalid_value(
                de::Unexpected::Str(&val.unwrap()),
                &"unknown architecture supplied, must be \"musl\" or \"gnu\"",
            ));
        }
    }

    Ok(val)
}
