// Copyright © 2025 Computing Systems Laboratory (CSLab), ECE, NTUA. All rights reserved.
//
// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use crate::cpu_config::templates::{
    CpuTemplateType, GetCpuTemplate, GetCpuTemplateError, KvmCapability,
};

impl GetCpuTemplate for Option<CpuTemplateType> {
    // We only support the default template for now.
    fn get_cpu_template(&self) -> Result<Cow<CustomCpuTemplate>, GetCpuTemplateError> {
        match self {
            Some(template_type) => match template_type {
                CpuTemplateType::Custom(_) => unimplemented!(),
                CpuTemplateType::Static(_) => unimplemented!(),
            },
            None => Ok(Cow::Owned(CustomCpuTemplate::default())),
        }
    }
}

/// Wrapper type to containing riscv64 CPU config modifiers.
#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomCpuTemplate {
    /// Additional kvm capabilities to check before
    /// configuring vcpus.
    #[serde(default)]
    pub kvm_capabilities: Vec<KvmCapability>,
    /// Modifiers of enabled vcpu features for vcpu.
    #[serde(default)]
    pub vcpu_features: Vec<VcpuFeatures>,
    /// Modifiers for registers on Riscv64 CPUs.
    #[serde(default)]
    pub reg_modifiers: Vec<RegisterModifier>,
}

impl CustomCpuTemplate {
    /// Get a list of register IDs that are modified by the CPU template. We don't use CPU
    /// templates for RISC-V, thus just return an empty array.
    pub fn reg_list(&self) -> Vec<u64> {
        vec![]
    }

    /// Validate the correctness of the template. We don't use CPU templates on RISC-V, thus just
    /// return always successfully.
    pub fn validate(&self) -> Result<(), serde_json::Error> {
        Ok(())
    }
}

/// Struct for defining enabled vcpu features. For now, it is just used as a placeholder.
#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct VcpuFeatures;

/// Wrapper of a mask defined as a bitmap to apply changes to a given register's value. For now, it
/// is used just as a placeholder.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Hash)]
pub struct RegisterModifier;
