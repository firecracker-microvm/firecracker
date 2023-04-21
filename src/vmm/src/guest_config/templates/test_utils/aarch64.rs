// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_arch = "aarch64")]
use crate::guest_config::aarch64::static_cpu_templates::v1n1::v1n1;
#[cfg(target_arch = "aarch64")]
use crate::guest_config::templates::aarch64::{RegisterModifier, RegisterValueFilter};
use crate::guest_config::templates::CustomCpuTemplate;

/// Test CPU template in JSON format
#[cfg(target_arch = "aarch64")]
pub const TEST_TEMPLATE_JSON: &str = r#"{
    "reg_modifiers":  [
        {
            "addr": "0x0AAC",
            "bitmap": "0b1xx1"
        },
        {
            "addr": "0x0AAB",
            "bitmap": "0b1x00"
        }
    ]
}"#;

/// Test CPU template in JSON format but has an invalid field for the architecture.
/// "msr_modifiers" is the field name for the model specific registers for
/// defined by x86 CPUs.
#[cfg(target_arch = "aarch64")]
pub const TEST_INVALID_TEMPLATE_JSON: &str = r#"{
    "msr_modifiers":  [
        {
            "addr": "0x0AAC",
            "bitmap": "0b1xx1"
        }
    ]
}"#;

/// Builds a sample custom CPU template
#[cfg(target_arch = "aarch64")]
pub fn build_test_template() -> CustomCpuTemplate {
    CustomCpuTemplate {
        reg_modifiers: vec![
            RegisterModifier {
                addr: 0x9999,
                bitmap: RegisterValueFilter {
                    filter: 0b100010001,
                    value: 0b100000001,
                },
            },
            RegisterModifier {
                addr: 0x8000,
                bitmap: RegisterValueFilter {
                    filter: 0b1110,
                    value: 0b0110,
                },
            },
        ],
    }
}

/// Converts an existing static template to its JSON format.
#[cfg(target_arch = "aarch64")]
pub fn test_static_template() -> String {
    serde_json::to_string(&v1n1()).expect("Error serializing static template to JSON")
}
