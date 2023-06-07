// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::cpu_config::templates::{CustomCpuTemplate, RegisterValueFilter};
use crate::cpu_config::x86_64::cpuid::KvmCpuidFlags;
use crate::cpu_config::x86_64::custom_cpu_template::{
    CpuidLeafModifier, CpuidRegister, CpuidRegisterModifier,
};

/// C3 CPU template.
///
/// Mask CPUID to make exposed CPU features as close as possbile to AWS C3 instance.
#[tracing::instrument(level = "trace", ret)]
pub fn c3() -> CustomCpuTemplate {
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
                            value: 0b00000000000000110000011011100100,
                        },
                    },
                    CpuidRegisterModifier {
                        register: CpuidRegister::Ecx,
                        bitmap: RegisterValueFilter {
                            filter: 0b00000000010000001101110100111100,
                            value: 0b00000000000000000000000000000000,
                        },
                    },
                    CpuidRegisterModifier {
                        register: CpuidRegister::Edx,
                        bitmap: RegisterValueFilter {
                            filter: 0b10101000011001000001000010000000,
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
                            filter: 0b11111111101011111101110101111100,
                            value: 0b00000000000000000000000000000000,
                        },
                    },
                    CpuidRegisterModifier {
                        register: CpuidRegister::Ecx,
                        bitmap: RegisterValueFilter {
                            filter: 0b01000000010000010100100000011110,
                            value: 0b00000000000000000000000000000000,
                        },
                    },
                    CpuidRegisterModifier {
                        register: CpuidRegister::Edx,
                        bitmap: RegisterValueFilter {
                            filter: 0b00000000000000000000000000001100,
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
                            filter: 0b00000000000000000000000100100000,
                            value: 0b00000000000000000000000000000000,
                        },
                    },
                    CpuidRegisterModifier {
                        register: CpuidRegister::Edx,
                        bitmap: RegisterValueFilter {
                            filter: 0b00000100000000000000000000000000,
                            value: 0b00000000000000000000000000000000,
                        },
                    },
                ],
            },
        ],
        msr_modifiers: vec![],
    }
}
