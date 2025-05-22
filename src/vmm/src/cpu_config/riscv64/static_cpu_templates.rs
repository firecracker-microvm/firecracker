// Copyright © 2025 Computing Systems Laboratory (CSLab), ECE, NTUA. All rights reserved.
//
// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

/// Templates available for configuring the supported RISCV CPU types.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StaticCpuTemplate {
    /// No CPU template is used.
    #[default]
    None,
}

impl StaticCpuTemplate {
    /// Check if no template specified.
    pub fn is_none(&self) -> bool {
        self == &StaticCpuTemplate::None
    }
}

impl std::fmt::Display for StaticCpuTemplate {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            StaticCpuTemplate::None => write!(f, "None"),
        }
    }
}
