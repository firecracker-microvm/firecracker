// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{Display, Formatter, Result};
use std::io;

/// Strongly typed data structure used to configure the boot source of the
/// microvm.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootSourceConfig {
    /// Path of the kernel image.
    pub kernel_image_path: String,
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
    /// The kernel command line is invalid.
    InvalidKernelCommandLine(String),
    /// The boot source cannot be update post boot.
    UpdateNotAllowedPostBoot,
}

impl Display for BootSourceConfigError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        use self::BootSourceConfigError::*;
        match *self {
            InvalidKernelPath(ref e) => write!(f, "The kernel file cannot be opened: {}", e),
            InvalidKernelCommandLine(ref e) => {
                write!(f, "The kernel command line is invalid: {}", e.as_str())
            }
            UpdateNotAllowedPostBoot => {
                write!(f, "The update operation is not allowed after boot.")
            }
        }
    }
}
