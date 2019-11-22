// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{de, Deserialize};
use std::fmt;
use vmm_config::machine_config::{VmConfigError};

pub use error::{VmmActionError, ErrorKind};

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
 
/// DOCUMENTATION
pub fn get_whitelist_config_for_toolchain(configs: &[SyscallWhitelistConfig]) -> std::result::Result<Vec<i64>, VmmActionError> {
    #[cfg(target_env = "musl")]
    let toolchain = "musl";
    #[cfg(target_env = "gnu")]
    let toolchain = "gnu";

    #[cfg(target_arch = "x86_64")]
    let arch = "x86_64";
    #[cfg(target_arch = "aarch64")]
    let arch = "aarch64";

    let config = configs.into_iter().find(| &config | {
        let cfg_arch = config.arch.as_ref().map(|s| String::as_str(s)).unwrap();
        let cfg_toolchain = config.toolchain.as_ref().map(|s| String::as_str(s)).unwrap();
        cfg_arch == arch && cfg_toolchain == toolchain
    });

    //TODO: Create error types for the syscall whitelist error
    let syscalls = match config {
        Some(config) => &config.syscalls,
        None => return Err(VmmActionError::MachineConfig(ErrorKind::User, VmConfigError::InvalidVcpuCount))
    };

    match syscalls {
        Some(syscalls) => Ok(syscalls.to_vec()),
        None => Err(VmmActionError::MachineConfig(ErrorKind::User, VmConfigError::InvalidVcpuCount))
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
