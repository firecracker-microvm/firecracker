// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use versionize::{VersionMap, Versionize, VersionizeError, VersionizeResult};
use versionize_derive::Versionize;

/// Module with C3 CPU template for x86_64
pub mod c3;
/// Module with T2 CPU template for x86_64
pub mod t2;
/// Module with T2A CPU template for x86_64
pub mod t2a;
/// Module with T2CL CPU template for x86_64
pub mod t2cl;
/// Module with T2S CPU template for x86_64
pub mod t2s;

/// Template types available for configuring the x86 CPU features that map
/// to EC2 instances.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Versionize)]
pub enum StaticCpuTemplate {
    /// C3 Template.
    C3,
    /// T2 Template.
    T2,
    /// T2S Template.
    T2S,
    /// No CPU template is used.
    #[default]
    None,
    /// T2CL Template.
    T2CL,
    /// T2A Template.
    T2A,
}

impl StaticCpuTemplate {
    /// Check if no template specified
    pub fn is_none(&self) -> bool {
        self == &StaticCpuTemplate::None
    }
}

impl std::fmt::Display for StaticCpuTemplate {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            StaticCpuTemplate::C3 => write!(f, "C3"),
            StaticCpuTemplate::T2 => write!(f, "T2"),
            StaticCpuTemplate::T2S => write!(f, "T2S"),
            StaticCpuTemplate::None => write!(f, "None"),
            StaticCpuTemplate::T2CL => write!(f, "T2CL"),
            StaticCpuTemplate::T2A => write!(f, "T2A"),
        }
    }
}
