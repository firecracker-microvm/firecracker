// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::custom_cpu_template::{
    CpuidLeafModifier, CpuidRegister, CpuidRegisterModifier, RegisterModifier,
};
use crate::cpu_config::templates::{CustomCpuTemplate, RegisterValueFilter};
use crate::cpu_config::x86_64::cpuid::KvmCpuidFlags;

/// Test CPU template in JSON format
pub const TEST_TEMPLATE_JSON: &str = r#"{
    "cpuid_modifiers": [
        {
            "leaf": "0x80000001",
            "subleaf": "0x0007",
            "flags": 0,
            "modifiers": [
                {
                    "register": "eax",
                    "bitmap": "0bx00100xxx1xxxxxxxxxxxxxxxxxxxxx1"
                }
            ]
        },
        {
            "leaf": "0x80000002",
            "subleaf": "0x0004",
            "flags": 0,
            "modifiers": [
                {
                    "register": "ebx",
                    "bitmap": "0bxxx1xxxxxxxxxxxxxxxxxxxxx1"
                },
                {
                    "register": "ecx",
                    "bitmap": "0bx00100xxx1xxxxxxxxxxx0xxxxx0xxx1"
                }
            ]
        },
        {
            "leaf": "0x80000003",
            "subleaf": "0x0004",
            "flags": 0,
            "modifiers": [
                {
                    "register": "edx",
                    "bitmap": "0bx00100xxx1xxxxxxxxxxx0xxxxx0xxx1"
                }
            ]
        },
        {
            "leaf": "0x80000004",
            "subleaf": "0x0004",
            "flags": 0,
            "modifiers": [
                {
                    "register": "edx",
                    "bitmap": "0b00100xxx1xxxxxx1xxxxxxxxxxxxxx1"
                },
                {
                    "register": "ecx",
                    "bitmap": "0bx00100xxx1xxxxxxxxxxxxx111xxxxx1"
                }
            ]
        },
        {
            "leaf": "0x80000005",
            "subleaf": "0x0004",
            "flags": 0,
            "modifiers": [
                {
                    "register": "eax",
                    "bitmap": "0bx00100xxx1xxxxx00xxxxxx000xxxxx1"
                },
                {
                    "register": "edx",
                    "bitmap": "0bx10100xxx1xxxxxxxxxxxxx000xxxxx1"
                }
            ]
        }
    ],
    "msr_modifiers":  [
        {
            "addr": "0x0",
            "bitmap": "0bx00100xxx1xxxx00xxx1xxxxxxxxxxx1"
        },
        {
            "addr": "0x1",
            "bitmap": "0bx00111xxx1xxxx111xxxxx101xxxxxx1"
        },
        {
            "addr": "0b11",
            "bitmap": "0bx00100xxx1xxxxxx0000000xxxxxxxx1"
        },
        {
            "addr": "0xbbca",
            "bitmap": "0bx00100xxx1xxxxxxxxx1"
        }
    ]
}"#;

/// Test CPU template in JSON format but has an invalid field for the architecture.
/// "reg_modifiers" is the field name for the registers for aarch64"
pub const TEST_INVALID_TEMPLATE_JSON: &str = r#"{
    "reg_modifiers":  [
        {
            "addr": "0x0AAC",
            "bitmap": "0b1xx1"
        }
    ]
}"#;

/// Builds a sample custom CPU template
pub fn build_test_template() -> CustomCpuTemplate {
    CustomCpuTemplate {
        cpuid_modifiers: vec![CpuidLeafModifier {
            leaf: 0x3,
            subleaf: 0x0,
            flags: KvmCpuidFlags(kvm_bindings::KVM_CPUID_FLAG_STATEFUL_FUNC),
            modifiers: vec![
                CpuidRegisterModifier {
                    register: CpuidRegister::Eax,
                    bitmap: RegisterValueFilter {
                        filter: 0b0111,
                        value: 0b0101,
                    },
                },
                CpuidRegisterModifier {
                    register: CpuidRegister::Ebx,
                    bitmap: RegisterValueFilter {
                        filter: 0b0111,
                        value: 0b0100,
                    },
                },
                CpuidRegisterModifier {
                    register: CpuidRegister::Ecx,
                    bitmap: RegisterValueFilter {
                        filter: 0b0111,
                        value: 0b0111,
                    },
                },
                CpuidRegisterModifier {
                    register: CpuidRegister::Edx,
                    bitmap: RegisterValueFilter {
                        filter: 0b0111,
                        value: 0b0001,
                    },
                },
            ],
        }],
        msr_modifiers: vec![
            RegisterModifier {
                addr: 0x9999,
                bitmap: RegisterValueFilter {
                    filter: 0,
                    value: 0,
                },
            },
            RegisterModifier {
                addr: 0x8000,
                bitmap: RegisterValueFilter {
                    filter: 0,
                    value: 0,
                },
            },
        ],
        ..Default::default()
    }
}
