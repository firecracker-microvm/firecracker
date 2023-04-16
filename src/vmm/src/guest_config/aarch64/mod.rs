// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Module with CPU templates for aarch64
pub mod static_cpu_templates;

pub use static_cpu_templates::*;

use super::templates::CustomCpuTemplate;
use crate::arch::regs::{Aarch64Register, Error as ArchError};

/// Errors thrown while configuring templates.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("Failed to create a guest cpu configuration: {0}")]
pub struct Error(#[from] pub ArchError);

/// CPU configuration for aarch64
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CpuConfiguration {
    /// Vector of CPU registers
    pub regs: Vec<Aarch64Register>,
}

impl CpuConfiguration {
    /// Creates new guest CPU config based on the provided template
    pub fn apply_template(mut self, template: &CustomCpuTemplate) -> Result<Self, Error> {
        for (modifier, reg) in template.reg_modifiers.iter().zip(self.regs.iter_mut()) {
            reg.value = modifier.bitmap.apply(reg.value);
        }
        Ok(self)
    }

    /// Returns ids of registers that are changed
    /// by this template
    pub fn register_ids(&self) -> Vec<u64> {
        self.regs.iter().map(|reg| reg.id).collect()
    }
}
