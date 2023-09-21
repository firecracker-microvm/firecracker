// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io;

use serde::{Deserialize, Serialize};
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;

/// Default guest kernel command line:
/// - `reboot=k` shut down the guest on reboot, instead of well... rebooting;
/// - `panic=1` on panic, reboot after 1 second;
/// - `pci=off` do not scan for PCI devices (save boot time);
/// - `nomodule` disable loadable kernel module support;
/// - `8250.nr_uarts=0` disable 8250 serial interface;
/// - `i8042.noaux` do not probe the i8042 controller for an attached mouse (save boot time);
/// - `i8042.nomux` do not probe i8042 for a multiplexing controller (save boot time);
/// - `i8042.nopnp` do not use ACPIPnP to discover KBD/AUX controllers (save boot time);
/// - `i8042.dumbkbd` do not attempt to control kbd state via the i8042 (save boot time).
pub const DEFAULT_KERNEL_CMDLINE: &str = "reboot=k panic=1 pci=off nomodule 8250.nr_uarts=0 \
                                          i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd";

/// Strongly typed data structure used to configure the boot source of the
/// microvm.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize, Versionize)]
#[serde(deny_unknown_fields)]
pub struct BootSourceConfig {
    /// Path of the kernel image.
    pub kernel_image_path: String,
    /// Path of the initrd, if there is one.
    pub initrd_path: Option<String>,
    /// The boot arguments to pass to the kernel. If this field is uninitialized,
    /// DEFAULT_KERNEL_CMDLINE is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_args: Option<String>,
}

/// Errors associated with actions on `BootSourceConfig`.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum BootSourceConfigError {
    /// The kernel file cannot be opened: {0}
    InvalidKernelPath(io::Error),
    /// The initrd file cannot be opened due to invalid path or invalid permissions. {0}
    InvalidInitrdPath(io::Error),
    /// The kernel command line is invalid: {0}
    InvalidKernelCommandLine(String),
}

/// Holds the kernel specification (both configuration as well as runtime details).
#[derive(Debug, Default)]
pub struct BootSource {
    /// The boot source configuration.
    pub config: BootSourceConfig,
    /// The boot source builder (a boot source allocated and validated).
    /// It is an option cause a resumed microVM does not need it.
    pub builder: Option<BootConfig>,
}

/// Holds the kernel builder (created and validates based on BootSourceConfig).
#[derive(Debug)]
pub struct BootConfig {
    /// The commandline validated against correctness.
    pub cmdline: linux_loader::cmdline::Cmdline,
    /// The descriptor to the kernel file.
    pub kernel_file: File,
    /// The descriptor to the initrd file, if there is one.
    pub initrd_file: Option<File>,
}

impl BootConfig {
    /// Creates the BootConfig based on a given configuration.
    pub fn new(cfg: &BootSourceConfig) -> Result<Self, BootSourceConfigError> {
        use self::BootSourceConfigError::{
            InvalidInitrdPath, InvalidKernelCommandLine, InvalidKernelPath,
        };

        // Validate boot source config.
        let kernel_file = File::open(&cfg.kernel_image_path).map_err(InvalidKernelPath)?;
        let initrd_file: Option<File> = match &cfg.initrd_path {
            Some(path) => Some(File::open(path).map_err(InvalidInitrdPath)?),
            None => None,
        };

        let cmdline_str = match cfg.boot_args.as_ref() {
            None => DEFAULT_KERNEL_CMDLINE,
            Some(str) => str.as_str(),
        };
        let cmdline =
            linux_loader::cmdline::Cmdline::try_from(cmdline_str, crate::arch::CMDLINE_MAX_SIZE)
                .map_err(|err| InvalidKernelCommandLine(err.to_string()))?;

        Ok(BootConfig {
            cmdline,
            kernel_file,
            initrd_file,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use utils::tempfile::TempFile;

    use super::*;

    #[test]
    fn test_boot_config() {
        let kernel_file = TempFile::new().unwrap();
        let kernel_path = kernel_file.as_path().to_str().unwrap().to_string();

        let boot_src_cfg = BootSourceConfig {
            boot_args: None,
            initrd_path: None,
            kernel_image_path: kernel_path,
        };

        let boot_cfg = BootConfig::new(&boot_src_cfg).unwrap();
        assert!(boot_cfg.initrd_file.is_none());
        assert_eq!(
            boot_cfg.cmdline.as_cstring().unwrap().as_bytes_with_nul(),
            [DEFAULT_KERNEL_CMDLINE.as_bytes(), &[b'\0']].concat()
        );
    }
}
