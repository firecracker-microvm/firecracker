// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Module with CPU templates for aarch64
pub mod static_cpu_templates;

use kvm_ioctls::VcpuFd;
pub use static_cpu_templates::*;

use super::templates::{CpuTemplateType, CustomCpuTemplate};
use crate::arch::regs::{Aarch64Register, Error as ArchError};

/// Errors thrown while configuring templates.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("Failed to create a guest cpu configuration: {0}")]
pub struct Error(#[from] ArchError);

/// CPU configuration for aarch64
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CpuConfiguration {
    /// Vector of CPU registers
    pub regs: Vec<Aarch64Register>,
}

impl CpuConfiguration {
    /// Creates new guest CPU config based on the provided template
    pub fn new(vcpu: &VcpuFd, template: &Option<CpuTemplateType>) -> Result<Self, Error> {
        match template {
            Some(ref cpu_template) => Self::with_template(vcpu, cpu_template),
            None => Ok(Self::default()),
        }
    }

    /// Creates new guest CPU config based on the provided template
    fn with_template(vcpu: &VcpuFd, template: &CpuTemplateType) -> Result<Self, Error> {
        match template {
            CpuTemplateType::Custom(template) => Self::with_applied_template(vcpu, template),
            _ => unreachable!("Options other than V1N1 are invalid"),
        }
    }

    /// Creates new guest CPU config based on the provided template
    fn with_applied_template(vcpu: &VcpuFd, template: &CustomCpuTemplate) -> Result<Self, Error> {
        let regs = template
            .reg_modifiers
            .iter()
            .map(|modifier| {
                vcpu.get_one_reg(modifier.addr)
                    .map(|value| Aarch64Register {
                        id: modifier.addr,
                        value: modifier.bitmap.apply(value),
                    })
                    .map_err(|e| Error(ArchError::GetSysRegister(modifier.addr, e)))
            })
            .collect::<Result<Vec<_>, Error>>()?;

        Ok(Self { regs })
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
