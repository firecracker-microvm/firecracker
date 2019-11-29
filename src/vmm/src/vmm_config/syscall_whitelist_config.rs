// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{de, Deserialize};
use std::fmt;

pub use error::{ErrorKind, VmmActionError};

/// Errors associated with configuring the syscall whitelist per architecture-toolchain tuple.
#[derive(Debug, PartialEq)]
pub enum SyscallWhitelistConfigError {
    /// Supplied architecture is not supported. Only values `aarch64` or `x86_64` are currently supported.
    InvalidArchitecture,
    /// Supplied toolchain is not supported. Only values `musl` or `gnu` are currently supported.
    InvalidToolchain,
}

impl fmt::Display for SyscallWhitelistConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::SyscallWhitelistConfigError::*;
        match *self {
            InvalidArchitecture => write!(
                f,
                "Supplied architecture for syscall whitelist config is unsupported. \
                 Only \"aarch64\" or \"x86_64\" are currently supported."
            ),
            InvalidToolchain => write!(
                f,
                "Supplied toolchain for syscall whitelist config is unsupported. \
                 Only \"musl\" or \"gnu\" are currently supported."
            ),
        }
    }
}

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
    pub syscalls: Option<Vec<i64>>,
}

impl fmt::Display for SyscallWhitelistConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let arch = self.arch.clone().unwrap();
        let toolchain = self.toolchain.clone().unwrap();
        let syscalls = &self.syscalls;

        write!(
            f,
            "{{ \"arch\": {:?}, \"toolchain\": {:?},  \"syscalls\": {:?}",
            arch, toolchain, syscalls
        )
    }
}

/// Given a list of syscalls config objects, finds the config object
/// matching target toolchain and architecture. If no matching object
/// is found, return an empty vector by default.
pub fn get_whitelist_config_for_toolchain(
    configs: &[SyscallWhitelistConfig],
) -> std::result::Result<Vec<i64>, VmmActionError> {
    #[cfg(target_env = "musl")]
    let toolchain = "musl";
    #[cfg(target_env = "gnu")]
    let toolchain = "gnu";

    #[cfg(target_arch = "x86_64")]
    let arch = "x86_64";
    #[cfg(target_arch = "aarch64")]
    let arch = "aarch64";

    let config = configs.iter().find(|&config| {
        let cfg_arch = config.arch.as_ref().map(|s| String::as_str(s)).unwrap();
        let cfg_toolchain = config
            .toolchain
            .as_ref()
            .map(|s| String::as_str(s))
            .unwrap();
        cfg_arch == arch && cfg_toolchain == toolchain
    });

    let syscalls = match config {
        Some(config) => &config.syscalls,
        None => return Ok(vec![]), // default to empty list if we don't find a matching arch-toolchain tuple
    };

    match syscalls {
        Some(syscalls) => Ok(syscalls.to_vec()),
        None => Ok(vec![]),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_whitelist_config_for_toolchain() {
        #[cfg(target_env = "musl")]
        let toolchain = "musl";
        #[cfg(target_env = "gnu")]
        let toolchain = "gnu";

        #[cfg(target_arch = "x86_64")]
        let arch = "x86_64";
        #[cfg(target_arch = "aarch64")]
        let arch = "aarch64";

        let mut test_configs = vec![SyscallWhitelistConfig {
            arch: Some(String::from(arch)),
            toolchain: Some(String::from(toolchain)),
            syscalls: Some(vec![39, 40]),
        }];

        let mut selected_config = get_whitelist_config_for_toolchain(&test_configs);
        assert!(selected_config.is_ok());
        assert_eq!(vec![39, 40], selected_config.unwrap());

        test_configs = vec![];

        selected_config = get_whitelist_config_for_toolchain(&test_configs);
        assert!(selected_config.is_ok());
        let empty_vec: Vec<i64> = vec![];
        assert_eq!(empty_vec, selected_config.unwrap());
    }

    #[test]
    fn test_display_whitelist_config_error() {
        let expected_str = "Supplied architecture for syscall whitelist config is unsupported. \
                            Only \"aarch64\" or \"x86_64\" are currently supported.";
        assert_eq!(
            SyscallWhitelistConfigError::InvalidArchitecture.to_string(),
            expected_str
        );

        let expected_str = "Supplied toolchain for syscall whitelist config is unsupported. \
                            Only \"musl\" or \"gnu\" are currently supported.";
        assert_eq!(
            SyscallWhitelistConfigError::InvalidToolchain.to_string(),
            expected_str
        );
    }
}
