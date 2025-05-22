// Copyright © 2025 Computing Systems Laboratory (CSLab), ECE, NTUA. All rights reserved.
//
// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Module for custom CPU templates.
pub mod custom_cpu_template;
/// Module for static CPU templates.
pub mod static_cpu_templates;

use super::templates::CustomCpuTemplate;

/// Errors thrown while configuring templates.
#[derive(Debug, PartialEq, Eq, thiserror::Error, displaydoc::Display)]
pub enum CpuConfigurationError {}

/// CPU configuration for riscv64. Just a nameholder.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CpuConfiguration;

impl CpuConfiguration {
    /// Creates new guest CPU config based on the provided template.
    /// Not actually implemented yet.
    pub fn apply_template(self, _: &CustomCpuTemplate) -> Self {
        self
    }

    /// Returns ids of registers that are changed by this template.
    pub fn register_ids(&self) -> Vec<u64> {
        unimplemented!();
    }
}
