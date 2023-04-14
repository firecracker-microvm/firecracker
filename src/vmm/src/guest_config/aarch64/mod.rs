// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Module with CPU templates for aarch64
pub mod static_cpu_templates;

use kvm_ioctls::VcpuFd;
pub use static_cpu_templates::*;

use super::templates::CustomCpuTemplate;
use crate::arch::regs::{Aarch64Register, Error as ArchError};

/// Errors thrown while configuring templates.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("Failed to create a guest cpu configuration: {0}")]
pub struct Error(#[from] ArchError);

/// CPU configuration for aarch64
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CpuConfiguration {
    /// Vector of CPU registers
    regs: Vec<Aarch64Register>,
}

impl CpuConfiguration {
    /// Creates new guest CPU with provide registers
    pub fn new(regs: Vec<Aarch64Register>) -> Self {
        Self { regs }
    }

    /// Creates new guest CPU config based on the provided template
    pub fn apply_template(mut self, template: &CustomCpuTemplate) -> Self {
        for (modifier, mut reg) in template.reg_modifiers.iter().zip(self.regs.iter_mut()) {
            reg.value = modifier.bitmap.apply(reg.value);
        }
        self
    }

    /// Returns ids of registers that are changed
    /// by this template
    pub fn register_ids(&self) -> Vec<u64> {
        self.regs.iter().map(|reg| reg.id).collect()
    }

    /// Applies cpu template to vcpu
    /// Used inside Vcpu to configure it
    pub fn apply(&self, vcpu: &VcpuFd) -> Result<(), ArchError> {
        for Aarch64Register { id, value } in self.regs.iter() {
            vcpu.set_one_reg(*id, *value)
                .map_err(|error| ArchError::SetSysRegister(*id, error))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest_config::templates::aarch64::{RegisterModifier, RegisterValueFilter};

    fn build_test_template() -> CustomCpuTemplate {
        CustomCpuTemplate {
            reg_modifiers: vec![
                RegisterModifier {
                    addr: 0,
                    bitmap: RegisterValueFilter {
                        filter: 0b1111,
                        value: 0b1001,
                    },
                },
                RegisterModifier {
                    addr: 1,
                    bitmap: RegisterValueFilter {
                        filter: 0b1111,
                        value: 0b0110,
                    },
                },
            ],
        }
    }

    fn supported_cpu_config() -> CpuConfiguration {
        let regs = [(0, 0b0000), (1, 0b0000)]
            .into_iter()
            .map(|(id, value)| Aarch64Register { id, value })
            .collect();
        CpuConfiguration { regs }
    }

    #[test]
    fn test_empty_template() {
        let host_configuration = CpuConfiguration::default();
        let guest_config = host_configuration
            .clone()
            .apply_template(&CustomCpuTemplate::default());
        assert_eq!(host_configuration.regs, guest_config.regs);
    }

    #[test]
    fn test_apply_template() {
        let guest_config = supported_cpu_config().apply_template(&build_test_template());
        assert_eq!(guest_config.regs[0].value, 0b1001);
        assert_eq!(guest_config.regs[1].value, 0b0110);
    }
}
