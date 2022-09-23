// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{Display, Formatter, Result};
use std::fs::File;
use std::io;

use serde::{Deserialize, Serialize};

/// Default guest kernel command line:
/// - `reboot=k` shut down the guest on reboot, instead of well... rebooting;
/// - `panic=1` on panic, reboot after 1 second;
/// - `pci=off` do not scan for PCI devices (save boot time);
/// - `nomodules` disable loadable kernel module support;
/// - `8250.nr_uarts=0` disable 8250 serial interface;
/// - `i8042.noaux` do not probe the i8042 controller for an attached mouse (save boot time);
/// - `i8042.nomux` do not probe i8042 for a multiplexing controller (save boot time);
/// - `i8042.nopnp` do not use ACPIPnP to discover KBD/AUX controllers (save boot time);
/// - `i8042.dumbkbd` do not attempt to control kbd state via the i8042 (save boot time).
pub const DEFAULT_KERNEL_CMDLINE: &str = "reboot=k panic=1 pci=off nomodules 8250.nr_uarts=0 \
                                          i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd";

/// Strongly typed data structure used to configure the boot source of the
/// microvm.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootSourceConfig {
    /// Path of the kernel image.
    pub kernel_image_path: String,
    /// Path of the initrd, if there is one.
    pub initrd_path: Option<String>,
    /// The boot arguments to pass to the kernel. If this field is uninitialized, the default
    /// kernel command line is used: `reboot=k panic=1 pci=off nomodules 8250.nr_uarts=0`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_args: Option<String>,
}

/// Errors associated with actions on `BootSourceConfig`.
#[derive(Debug)]
pub enum BootSourceConfigError {
    /// The kernel file cannot be opened.
    InvalidKernelPath(io::Error),
    /// The initrd file cannot be opened.
    InvalidInitrdPath(io::Error),
    /// The kernel command line is invalid.
    InvalidKernelCommandLine(String),
}

impl Display for BootSourceConfigError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        use self::BootSourceConfigError::*;
        match *self {
            InvalidKernelPath(ref err) => write!(f, "The kernel file cannot be opened: {}", err),
            InvalidInitrdPath(ref err) => write!(
                f,
                "The initrd file cannot be opened due to invalid path or invalid permissions. {}",
                err,
            ),
            InvalidKernelCommandLine(ref err) => {
                write!(f, "The kernel command line is invalid: {}", err.as_str())
            }
        }
    }
}

/// Holds the kernel specification (both configuration as well as runtime details).
#[derive(Default)]
pub struct BootSource {
    /// The boot source configuration.
    pub config: BootSourceConfig,
    /// The boot source builder (a boot source allocated and validated).
    /// It is an option cause a resumed microVM does not need it.
    pub builder: Option<BootConfig>,
}

/// Holds the kernel builder (created and validates based on BootSourceConfig).
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
    pub fn new(cfg: &BootSourceConfig) -> std::result::Result<Self, BootSourceConfigError> {
        use self::BootSourceConfigError::{
            InvalidInitrdPath, InvalidKernelCommandLine, InvalidKernelPath,
        };

        // Validate boot source config.
        let kernel_file = File::open(&cfg.kernel_image_path).map_err(InvalidKernelPath)?;
        let initrd_file: Option<File> = match &cfg.initrd_path {
            Some(path) => Some(File::open(path).map_err(InvalidInitrdPath)?),
            None => None,
        };
        let mut cmdline = linux_loader::cmdline::Cmdline::new(arch::CMDLINE_MAX_SIZE);
        let boot_args = match cfg.boot_args.as_ref() {
            None => DEFAULT_KERNEL_CMDLINE,
            Some(str) => str.as_str(),
        };
        cmdline
            .insert_str(boot_args)
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
        assert_eq!(boot_cfg.cmdline.as_str(), DEFAULT_KERNEL_CMDLINE);
    }
}
