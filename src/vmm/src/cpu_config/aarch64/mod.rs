// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Module for custom CPU templates
pub mod custom_cpu_template;
/// Module for static CPU templates
pub mod static_cpu_templates;
/// Module with test utils for custom CPU templates
pub mod test_utils;

use super::templates::CustomCpuTemplate;
use crate::arch::aarch64::regs::{Aarch64RegisterVec, RegSize};
use crate::arch::aarch64::vcpu::VcpuError as ArchError;

/// Errors thrown while configuring templates.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("Failed to create a guest cpu configuration: {0}")]
pub struct CpuConfigurationError(#[from] pub ArchError);

/// CPU configuration for aarch64
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CpuConfiguration {
    /// Vector of CPU registers
    pub regs: Aarch64RegisterVec,
}

impl CpuConfiguration {
    /// Creates new guest CPU config based on the provided template
    pub fn apply_template(
        mut self,
        template: &CustomCpuTemplate,
    ) -> Result<Self, CpuConfigurationError> {
        for (modifier, mut reg) in template.reg_modifiers.iter().zip(self.regs.iter_mut()) {
            match reg.size() {
                RegSize::U32 => {
                    reg.set_value(modifier.bitmap.apply(u128::from(reg.value::<u32, 4>())) as u32);
                }
                RegSize::U64 => {
                    reg.set_value(modifier.bitmap.apply(u128::from(reg.value::<u64, 8>())) as u64);
                }
                RegSize::U128 => {
                    reg.set_value(modifier.bitmap.apply(reg.value::<u128, 16>()));
                }
                _ => unreachable!("Only 32, 64 and 128 bit wide registers are supported"),
            }
        }
        Ok(self)
    }

    /// Returns ids of registers that are changed
    /// by this template
    pub fn register_ids(&self) -> Vec<u64> {
        self.regs.iter().map(|reg| reg.id).collect()
    }
}
