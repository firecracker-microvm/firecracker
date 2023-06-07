// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use versionize::{VersionMap, Versionize, VersionizeError, VersionizeResult};
use versionize_derive::Versionize;

/// Module with V1N1 CPU template for aarch64
pub mod v1n1;

/// Templates available for configuring the supported ARM CPU types.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Versionize)]
pub enum StaticCpuTemplate {
    // Needed for compatibility
    /// Empty0
    Empty0,
    // Needed for compatibility
    /// Empty1
    Empty1,
    /// Template to mask Neoverse-V1 as Neoverse-N1
    V1N1,
    /// No CPU template is used.
    #[default]
    None,
}

impl StaticCpuTemplate {
    /// Check if no template specified
    #[tracing::instrument(level = "trace", ret)]
    pub fn is_none(&self) -> bool {
        self == &StaticCpuTemplate::None
    }
}

impl std::fmt::Display for StaticCpuTemplate {
    #[tracing::instrument(level = "trace", ret)]
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            StaticCpuTemplate::V1N1 => write!(f, "V1N1"),
            StaticCpuTemplate::None => write!(f, "None"),
            _ => write!(f, "None"),
        }
    }
}
