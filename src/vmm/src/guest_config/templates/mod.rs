// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// TODO: Refactor code to merge deserialize_* functions for modules x86_64 and aarch64
/// Templates module to contain sub-modules for aarch64 and x86_64 templates

/// Module with cpu templates for x86_64
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
mod common_types {
    pub use crate::guest_config::templates::x86_64::CustomCpuTemplate;
    pub use crate::guest_config::x86_64::static_cpu_templates::StaticCpuTemplate;
    pub use crate::guest_config::x86_64::{CpuConfiguration, Error as GuestConfigError};
}

/// Module with cpu templates for aarch64
#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "aarch64")]
mod common_types {
    pub use crate::guest_config::aarch64::static_cpu_templates::StaticCpuTemplate;
    pub use crate::guest_config::aarch64::{CpuConfiguration, Error as GuestConfigError};
    pub use crate::guest_config::templates::aarch64::CustomCpuTemplate;
}

pub use common_types::*;

/// Trait to take cpu template from VmConfig if one exist
pub trait TakeCpuTemplate {
    /// Take cpu template
    fn take_template(&mut self) -> Option<CustomCpuTemplate>;
}

/// Enum that represents types of cpu templates available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpuTemplateType {
    /// Custom cpu template
    Custom(CustomCpuTemplate),
    /// Static cpu template
    Static(StaticCpuTemplate),
}

impl From<StaticCpuTemplate> for Option<CpuTemplateType> {
    fn from(value: StaticCpuTemplate) -> Self {
        match value {
            StaticCpuTemplate::None => None,
            other => Some(CpuTemplateType::Static(other)),
        }
    }
}

impl From<&Option<CpuTemplateType>> for StaticCpuTemplate {
    fn from(value: &Option<CpuTemplateType>) -> Self {
        match value {
            Some(CpuTemplateType::Static(template)) => *template,
            Some(CpuTemplateType::Custom(_)) | None => StaticCpuTemplate::None,
        }
    }
}
