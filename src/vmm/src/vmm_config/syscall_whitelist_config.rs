// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
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
    pub arch: String,

    /// Toolchain to whitelist syscalls for.
    pub toolchain: String,

    /// List of syscall numbers for given architecture and toolchain.
    pub syscalls: Vec<i64>,
}

impl fmt::Display for SyscallWhitelistConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let arch = &self.arch;
        let toolchain = &self.toolchain;
        let syscalls = &self.syscalls;

        write!(
            f,
            "{{ \"arch\": {:?}, \"toolchain\": {:?},  \"syscalls\": {:?} }}",
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
        let cfg_arch = &config.arch;
        let cfg_toolchain = &config.toolchain;

        cfg_arch == arch && cfg_toolchain == toolchain
    });

    match config {
        Some(config) => Ok(config.syscalls.to_vec()),
        None => Ok(vec![]), // default to empty list if we don't find a matching arch-toolchain tuple
    }
}

/// Validates a list of syscall whitelist configs so that user errors such as
/// configuring unsupported architectures do not fail silently.
pub fn validate_whitelist_configs(
    configs: &[SyscallWhitelistConfig],
) -> std::result::Result<(), VmmActionError> {
    for config in configs.iter() {
        let cfg_arch = &config.arch;
        let cfg_toolchain = &config.toolchain;

        if cfg_arch != "x86_64" && cfg_arch != "aarch64" {
            return Err(VmmActionError::SyscallWhitelist(
                ErrorKind::User,
                SyscallWhitelistConfigError::InvalidArchitecture,
            ));
        }

        if cfg_toolchain != "gnu" && cfg_toolchain != "musl" {
            return Err(VmmActionError::SyscallWhitelist(
                ErrorKind::User,
                SyscallWhitelistConfigError::InvalidToolchain,
            ));
        }
    }

    Ok(())
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
            arch: String::from(arch),
            toolchain: String::from(toolchain),
            syscalls: vec![39, 40],
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
    fn test_validate_whitelist_configs() {
        let mut test_configs = vec![SyscallWhitelistConfig {
            arch: String::from("unknown"),
            toolchain: String::from("musl"),
            syscalls: vec![1, 2, 3],
        }];

        match validate_whitelist_configs(&test_configs) {
            Err(VmmActionError::SyscallWhitelist(
                ErrorKind::User,
                SyscallWhitelistConfigError::InvalidArchitecture,
            )) => (),
            _ => unreachable!(),
        }

        test_configs = vec![SyscallWhitelistConfig {
            arch: String::from("x86_64"),
            toolchain: String::from("unknown"),
            syscalls: vec![1, 2, 3],
        }];

        match validate_whitelist_configs(&test_configs) {
            Err(VmmActionError::SyscallWhitelist(
                ErrorKind::User,
                SyscallWhitelistConfigError::InvalidToolchain,
            )) => (),
            _ => unreachable!(),
        }
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

    #[test]
    fn test_display_syscall_whitelist_config() {
        let expected_str =
            "{ \"arch\": \"x86_64\", \"toolchain\": \"musl\",  \"syscalls\": [1, 2, 3] }";

        let config = SyscallWhitelistConfig {
            arch: String::from("x86_64"),
            toolchain: String::from("musl"),
            syscalls: vec![1, 2, 3],
        };

        assert_eq!(config.to_string(), expected_str);
    }
}
