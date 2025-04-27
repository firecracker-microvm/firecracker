// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Module for custom CPU templates
pub mod custom_cpu_template;
/// Module for static CPU templates
pub mod static_cpu_templates;
/// Module with test utils for custom CPU templates
pub mod test_utils;

use super::templates::CustomCpuTemplate;
use crate::Vcpu;
use crate::arch::aarch64::regs::{Aarch64RegisterVec, RegSize};
use crate::arch::aarch64::vcpu::{VcpuArchError, get_registers};
use crate::vstate::vcpu::KvmVcpuError;

/// Errors thrown while configuring templates.
#[derive(Debug, PartialEq, Eq, thiserror::Error, displaydoc::Display)]
pub enum CpuConfigurationError {
    /// Error initializing the vcpu: {0}
    VcpuInit(#[from] KvmVcpuError),
    /// Error reading vcpu registers: {0}
    VcpuGetRegs(#[from] VcpuArchError),
}

/// CPU configuration for aarch64
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CpuConfiguration {
    /// Vector of CPU registers
    pub regs: Aarch64RegisterVec,
}

impl CpuConfiguration {
    /// Create new CpuConfiguration.
    pub fn new(
        cpu_template: &CustomCpuTemplate,
        vcpus: &mut [Vcpu],
    ) -> Result<Self, CpuConfigurationError> {
        for vcpu in vcpus.iter_mut() {
            vcpu.kvm_vcpu.init(&cpu_template.vcpu_features)?;
        }

        let mut regs = Aarch64RegisterVec::default();
        get_registers(&vcpus[0].kvm_vcpu.fd, &cpu_template.reg_list(), &mut regs)?;
        Ok(CpuConfiguration { regs })
    }

    /// Creates new guest CPU config based on the provided template
    pub fn apply_template(mut self, template: &CustomCpuTemplate) -> Self {
        for (modifier, mut reg) in template.reg_modifiers.iter().zip(self.regs.iter_mut()) {
            match reg.size() {
                RegSize::U32 => {
                    reg.set_value(
                        (modifier.bitmap.apply(u128::from(reg.value::<u32, 4>())) & 0xFFFF_FFFF)
                            as u32,
                    );
                }
                RegSize::U64 => {
                    reg.set_value(
                        (modifier.bitmap.apply(u128::from(reg.value::<u64, 8>()))
                            & 0xFFFF_FFFF_FFFF_FFFF) as u64,
                    );
                }
                RegSize::U128 => {
                    reg.set_value(modifier.bitmap.apply(reg.value::<u128, 16>()));
                }
                _ => unreachable!("Only 32, 64 and 128 bit wide registers are supported"),
            }
        }
        self
    }

    /// Returns ids of registers that are changed
    /// by this template
    pub fn register_ids(&self) -> Vec<u64> {
        self.regs.iter().map(|reg| reg.id).collect()
    }
}
