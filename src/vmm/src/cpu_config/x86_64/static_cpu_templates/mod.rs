// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use derive_more::Display;
use serde::{Deserialize, Serialize};

use crate::arch::x86_64::cpu_model::{
    CASCADE_LAKE_FMS, CpuModel, ICE_LAKE_FMS, MILAN_FMS, SKYLAKE_FMS,
};
use crate::cpu_config::x86_64::cpuid::{VENDOR_ID_AMD, VENDOR_ID_INTEL};

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
#[derive(Debug, Default, Display, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StaticCpuTemplate {
    /// C3 Template.
    #[display("C3")]
    C3,
    /// T2 Template.
    #[display("T2")]
    T2,
    /// T2S Template.
    #[display("T2S")]
    T2S,
    /// No CPU template is used.
    #[default]
    #[display("None")]
    None,
    /// T2CL Template.
    #[display("T2CL")]
    T2CL,
    /// T2A Template.
    #[display("T2A")]
    T2A,
}

impl StaticCpuTemplate {
    /// Check if no template specified
    pub fn is_none(&self) -> bool {
        self == &StaticCpuTemplate::None
    }

    /// Return the supported vendor for the CPU template.
    pub fn get_supported_vendor(&self) -> &'static [u8; 12] {
        match self {
            StaticCpuTemplate::C3 => VENDOR_ID_INTEL,
            StaticCpuTemplate::T2 => VENDOR_ID_INTEL,
            StaticCpuTemplate::T2S => VENDOR_ID_INTEL,
            StaticCpuTemplate::T2CL => VENDOR_ID_INTEL,
            StaticCpuTemplate::T2A => VENDOR_ID_AMD,
            StaticCpuTemplate::None => unreachable!(), // Should be handled in advance
        }
    }

    /// Return supported CPU models for the CPU template.
    pub fn get_supported_cpu_models(&self) -> &'static [CpuModel] {
        match self {
            StaticCpuTemplate::C3 => &[SKYLAKE_FMS, CASCADE_LAKE_FMS, ICE_LAKE_FMS],
            StaticCpuTemplate::T2 => &[SKYLAKE_FMS, CASCADE_LAKE_FMS, ICE_LAKE_FMS],
            StaticCpuTemplate::T2S => &[SKYLAKE_FMS, CASCADE_LAKE_FMS],
            StaticCpuTemplate::T2CL => &[CASCADE_LAKE_FMS, ICE_LAKE_FMS],
            StaticCpuTemplate::T2A => &[MILAN_FMS],
            StaticCpuTemplate::None => unreachable!(), // Should be handled in advance
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu_config::test_utils::get_json_template;

    #[test]
    fn verify_consistency_with_json_templates() {
        let static_templates = [
            (c3::c3(), "C3.json"),
            (t2::t2(), "T2.json"),
            (t2s::t2s(), "T2S.json"),
            (t2cl::t2cl(), "T2CL.json"),
            (t2a::t2a(), "T2A.json"),
        ];

        for (hardcoded_template, filename) in static_templates {
            let json_template = get_json_template(filename);
            assert_eq!(hardcoded_template, json_template);
        }
    }
}
