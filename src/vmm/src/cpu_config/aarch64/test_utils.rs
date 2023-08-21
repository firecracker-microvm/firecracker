// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::arch::aarch64::regs::{ID_AA64ISAR0_EL1, ID_AA64PFR0_EL1};
use crate::cpu_config::aarch64::custom_cpu_template::RegisterModifier;
use crate::cpu_config::templates::{CustomCpuTemplate, RegisterValueFilter};

/// Test CPU template in JSON format
pub const TEST_TEMPLATE_JSON: &str = r#"{
    "reg_modifiers":  [
        {
            "addr": "0x0030000000000011",
            "bitmap": "0b1xx1"
        },
        {
            "addr": "0x0030000000000022",
            "bitmap": "0b1x00"
        }
    ]
}"#;

/// Test CPU template in JSON format but has an invalid field for the architecture.
/// "msr_modifiers" is the field name for the model specific registers for
/// defined by x86 CPUs.
pub const TEST_INVALID_TEMPLATE_JSON: &str = r#"{
    "msr_modifiers":  [
        {
            "addr": "0x0AAC",
            "bitmap": "0b1xx1"
        }
    ]
}"#;

/// Builds a sample custom CPU template
pub fn build_test_template() -> CustomCpuTemplate {
    CustomCpuTemplate {
        reg_modifiers: vec![
            RegisterModifier {
                addr: ID_AA64PFR0_EL1,
                bitmap: RegisterValueFilter {
                    filter: 0b100010001,
                    value: 0b100000001,
                },
            },
            RegisterModifier {
                addr: ID_AA64ISAR0_EL1,
                bitmap: RegisterValueFilter {
                    filter: 0b1110,
                    value: 0b0110,
                },
            },
        ],
        ..Default::default()
    }
}
