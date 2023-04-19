// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use vmm::guest_config::cpuid::Cpuid;
use vmm::guest_config::templates::x86_64::{
    CpuidLeafModifier, CpuidRegister, CpuidRegisterModifier, RegisterModifier, RegisterValueFilter,
};
use vmm::guest_config::templates::{CpuConfiguration, CustomCpuTemplate};

/// Convert `&CpuConfiguration` to `CustomCputemplate`.
pub fn config_to_template(cpu_config: &CpuConfiguration) -> CustomCpuTemplate {
    CustomCpuTemplate {
        cpuid_modifiers: cpuid_to_modifiers(&cpu_config.cpuid),
        msr_modifiers: msrs_to_modifier(&cpu_config.msrs),
    }
}

fn cpuid_to_modifiers(cpuid: &Cpuid) -> Vec<CpuidLeafModifier> {
    cpuid
        .inner()
        .iter()
        .map(|(key, entry)| CpuidLeafModifier {
            leaf: key.leaf,
            subleaf: key.subleaf,
            flags: entry.flags,
            modifiers: vec![
                CpuidRegisterModifier {
                    register: CpuidRegister::Eax,
                    bitmap: RegisterValueFilter {
                        filter: u32::MAX.into(),
                        value: entry.result.eax.into(),
                    },
                },
                CpuidRegisterModifier {
                    register: CpuidRegister::Ebx,
                    bitmap: RegisterValueFilter {
                        filter: u32::MAX.into(),
                        value: entry.result.ebx.into(),
                    },
                },
                CpuidRegisterModifier {
                    register: CpuidRegister::Ecx,
                    bitmap: RegisterValueFilter {
                        filter: u32::MAX.into(),
                        value: entry.result.ecx.into(),
                    },
                },
                CpuidRegisterModifier {
                    register: CpuidRegister::Edx,
                    bitmap: RegisterValueFilter {
                        filter: u32::MAX.into(),
                        value: entry.result.edx.into(),
                    },
                },
            ],
        })
        .collect()
}

fn msrs_to_modifier(msrs: &HashMap<u32, u64>) -> Vec<RegisterModifier> {
    let mut msrs: Vec<RegisterModifier> = msrs
        .iter()
        .map(|(index, value)| RegisterModifier {
            addr: *index,
            bitmap: RegisterValueFilter {
                filter: u64::MAX,
                value: *value,
            },
        })
        .collect();
    msrs.sort_by_key(|modifier| modifier.addr);
    msrs
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use vmm::guest_config::cpuid::{
        CpuidEntry, CpuidKey, CpuidRegisters, IntelCpuid, KvmCpuidFlags,
    };

    use super::*;

    fn build_sample_cpuid() -> Cpuid {
        Cpuid::Intel(IntelCpuid(BTreeMap::from([
            (
                CpuidKey {
                    leaf: 0x0,
                    subleaf: 0x0,
                },
                CpuidEntry {
                    flags: KvmCpuidFlags::EMPTY,
                    result: CpuidRegisters {
                        eax: 0xffff_ffff,
                        ebx: 0x0000_ffff,
                        ecx: 0xffff_0000,
                        edx: 0x0000_0000,
                    },
                },
            ),
            (
                CpuidKey {
                    leaf: 0x1,
                    subleaf: 0x1,
                },
                CpuidEntry {
                    flags: KvmCpuidFlags::SIGNIFICANT_INDEX,
                    result: CpuidRegisters {
                        eax: 0xaaaa_aaaa,
                        ebx: 0xaaaa_5555,
                        ecx: 0x5555_aaaa,
                        edx: 0x5555_5555,
                    },
                },
            ),
        ])))
    }

    fn build_expected_cpuid_modifiers() -> Vec<CpuidLeafModifier> {
        vec![
            CpuidLeafModifier {
                leaf: 0x0,
                subleaf: 0x0,
                flags: KvmCpuidFlags::EMPTY,
                modifiers: vec![
                    CpuidRegisterModifier {
                        register: CpuidRegister::Eax,
                        bitmap: RegisterValueFilter {
                            filter: 0xffff_ffff,
                            value: 0xffff_ffff,
                        },
                    },
                    CpuidRegisterModifier {
                        register: CpuidRegister::Ebx,
                        bitmap: RegisterValueFilter {
                            filter: 0xffff_ffff,
                            value: 0x0000_ffff,
                        },
                    },
                    CpuidRegisterModifier {
                        register: CpuidRegister::Ecx,
                        bitmap: RegisterValueFilter {
                            filter: 0xffff_ffff,
                            value: 0xffff_0000,
                        },
                    },
                    CpuidRegisterModifier {
                        register: CpuidRegister::Edx,
                        bitmap: RegisterValueFilter {
                            filter: 0xffff_ffff,
                            value: 0x0000_0000,
                        },
                    },
                ],
            },
            CpuidLeafModifier {
                leaf: 0x1,
                subleaf: 0x1,
                flags: KvmCpuidFlags::SIGNIFICANT_INDEX,
                modifiers: vec![
                    CpuidRegisterModifier {
                        register: CpuidRegister::Eax,
                        bitmap: RegisterValueFilter {
                            filter: 0xffff_ffff,
                            value: 0xaaaa_aaaa,
                        },
                    },
                    CpuidRegisterModifier {
                        register: CpuidRegister::Ebx,
                        bitmap: RegisterValueFilter {
                            filter: 0xffff_ffff,
                            value: 0xaaaa_5555,
                        },
                    },
                    CpuidRegisterModifier {
                        register: CpuidRegister::Ecx,
                        bitmap: RegisterValueFilter {
                            filter: 0xffff_ffff,
                            value: 0x5555_aaaa,
                        },
                    },
                    CpuidRegisterModifier {
                        register: CpuidRegister::Edx,
                        bitmap: RegisterValueFilter {
                            filter: 0xffff_ffff,
                            value: 0x5555_5555,
                        },
                    },
                ],
            },
        ]
    }

    fn build_sample_msrs() -> HashMap<u32, u64> {
        HashMap::from([
            (0x1, 0xffff_ffff_ffff_ffff),
            (0x5, 0xffff_ffff_0000_0000),
            (0x3, 0x0000_0000_ffff_ffff),
            (0x2, 0x0000_0000_0000_0000),
        ])
    }

    fn build_expected_msr_modifiers() -> Vec<RegisterModifier> {
        vec![
            RegisterModifier {
                addr: 0x1,
                bitmap: RegisterValueFilter {
                    filter: 0xffff_ffff_ffff_ffff,
                    value: 0xffff_ffff_ffff_ffff,
                },
            },
            RegisterModifier {
                addr: 0x2,
                bitmap: RegisterValueFilter {
                    filter: 0xffff_ffff_ffff_ffff,
                    value: 0x0000_0000_0000_0000,
                },
            },
            RegisterModifier {
                addr: 0x3,
                bitmap: RegisterValueFilter {
                    filter: 0xffff_ffff_ffff_ffff,
                    value: 0x0000_0000_ffff_ffff,
                },
            },
            RegisterModifier {
                addr: 0x5,
                bitmap: RegisterValueFilter {
                    filter: 0xffff_ffff_ffff_ffff,
                    value: 0xffff_ffff_0000_0000,
                },
            },
        ]
    }

    #[test]
    fn test_cpuid_to_modifier() {
        let cpu_config = CpuConfiguration {
            cpuid: build_sample_cpuid(),
            msrs: build_sample_msrs(),
        };
        let cpu_template = CustomCpuTemplate {
            cpuid_modifiers: build_expected_cpuid_modifiers(),
            msr_modifiers: build_expected_msr_modifiers(),
        };
        assert_eq!(config_to_template(&cpu_config), cpu_template);
    }
}
