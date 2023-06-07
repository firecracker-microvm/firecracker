// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::cpu_config::templates::{CustomCpuTemplate, RegisterValueFilter};
use crate::cpu_config::x86_64::cpuid::KvmCpuidFlags;
use crate::cpu_config::x86_64::custom_cpu_template::{
    CpuidLeafModifier, CpuidRegister, CpuidRegisterModifier,
};

/// T2A template
///
/// Provide instruction set feature partity with Intel Cascade Lake or later using T2CL template.
#[tracing::instrument(level = "trace", ret)]
pub fn t2a() -> CustomCpuTemplate {
    CustomCpuTemplate {
        cpuid_modifiers: vec![
            CpuidLeafModifier {
                leaf: 0x1,
                subleaf: 0x0,
                flags: KvmCpuidFlags(0),
                modifiers: vec![
                    CpuidRegisterModifier {
                        register: CpuidRegister::Eax,
                        bitmap: RegisterValueFilter {
                            filter: 0b00001111111111110011111111111111,
                            value: 0b00000000000000110000011011110010,
                        },
                    },
                    CpuidRegisterModifier {
                        register: CpuidRegister::Ecx,
                        bitmap: RegisterValueFilter {
                            filter: 0b00000000000001001100110111111100,
                            value: 0b00000000000000000000000000000000,
                        },
                    },
                    CpuidRegisterModifier {
                        register: CpuidRegister::Edx,
                        bitmap: RegisterValueFilter {
                            filter: 0b11101000011001000001000010000000,
                            value: 0b00000000000000000001000010000000,
                        },
                    },
                ],
            },
            CpuidLeafModifier {
                leaf: 0x7,
                subleaf: 0x0,
                flags: KvmCpuidFlags(1),
                modifiers: vec![
                    CpuidRegisterModifier {
                        register: CpuidRegister::Ebx,
                        bitmap: RegisterValueFilter {
                            filter: 0b11111111111011111111101001010100,
                            value: 0b00000000000000000000001000000000,
                        },
                    },
                    CpuidRegisterModifier {
                        register: CpuidRegister::Ecx,
                        bitmap: RegisterValueFilter {
                            filter: 0b01000000010000010101111101011110,
                            value: 0b00000000000000000000000000000000,
                        },
                    },
                    CpuidRegisterModifier {
                        register: CpuidRegister::Edx,
                        bitmap: RegisterValueFilter {
                            filter: 0b00000000000000000000000100011100,
                            value: 0b00000000000000000000000000000000,
                        },
                    },
                ],
            },
            CpuidLeafModifier {
                leaf: 0xd,
                subleaf: 0x0,
                flags: KvmCpuidFlags(1),
                modifiers: vec![CpuidRegisterModifier {
                    register: CpuidRegister::Eax,
                    bitmap: RegisterValueFilter {
                        filter: 0b00000000000000000000001011111000,
                        value: 0b00000000000000000000000000000000,
                    },
                }],
            },
            CpuidLeafModifier {
                leaf: 0xd,
                subleaf: 0x1,
                flags: KvmCpuidFlags(1),
                modifiers: vec![CpuidRegisterModifier {
                    register: CpuidRegister::Eax,
                    bitmap: RegisterValueFilter {
                        filter: 0b00000000000000000000000000001110,
                        value: 0b00000000000000000000000000000000,
                    },
                }],
            },
            CpuidLeafModifier {
                leaf: 0x80000001,
                subleaf: 0x0,
                flags: KvmCpuidFlags(0),
                modifiers: vec![
                    CpuidRegisterModifier {
                        register: CpuidRegister::Ecx,
                        bitmap: RegisterValueFilter {
                            filter: 0b00100000000000000000000111000000,
                            value: 0b00000000000000000000000000000000,
                        },
                    },
                    CpuidRegisterModifier {
                        register: CpuidRegister::Edx,
                        bitmap: RegisterValueFilter {
                            filter: 0b00000111110000000000000000000000,
                            value: 0b00000000000000000000000000000000,
                        },
                    },
                ],
            },
            CpuidLeafModifier {
                leaf: 0x80000008,
                subleaf: 0x0,
                flags: KvmCpuidFlags(0),
                modifiers: vec![CpuidRegisterModifier {
                    register: CpuidRegister::Ebx,
                    bitmap: RegisterValueFilter {
                        filter: 0b00000000000011000000001000000101,
                        value: 0b00000000000011000000000000000000,
                    },
                }],
            },
        ],
        msr_modifiers: vec![],
    }
}
