// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Module for CPUID instruction related content
pub mod cpuid;
/// Module for custom CPU templates
pub mod custom_cpu_template;
/// Module for static CPU templates
pub mod static_cpu_templates;
/// Module with test utils for custom CPU templates
pub mod test_utils;

use std::collections::BTreeMap;

use self::custom_cpu_template::CpuidRegister;
use super::templates::CustomCpuTemplate;
use crate::cpu_config::x86_64::cpuid::{Cpuid, CpuidKey};

/// Errors thrown while configuring templates.
#[derive(Debug, PartialEq, Eq, thiserror::Error, displaydoc::Display)]
pub enum CpuConfigurationError {
    /// Template changes a CPUID entry not supported by KVM: Leaf: {0:0x}, Subleaf: {1:0x}
    CpuidFeatureNotSupported(u32, u32),
    /// Template changes an MSR entry not supported by KVM: Register Address: {0:0x}
    MsrNotSupported(u32),
    /// Can create cpuid from raw: {0}
    CpuidFromKvmCpuid(#[from] crate::cpu_config::x86_64::cpuid::CpuidTryFromKvmCpuid),
    /// KVM vcpu ioctl failed: {0}
    VcpuIoctl(#[from] crate::vstate::vcpu::KvmVcpuError),
}

/// CPU configuration for x86_64 CPUs
#[derive(Debug, Clone, PartialEq)]
pub struct CpuConfiguration {
    /// CPUID configuration
    pub cpuid: Cpuid,
    /// Register values as a key pair for model specific registers
    /// Key: MSR address
    /// Value: MSR value
    pub msrs: BTreeMap<u32, u64>,
}

/// Applies the CPUID modifiers from a CPU template.
pub(crate) fn apply_template_to_cpuid(
    mut cpuid: Cpuid,
    template: &CustomCpuTemplate,
) -> Result<Cpuid, CpuConfigurationError> {
    let guest_cpuid = cpuid.inner_mut();

    for mod_leaf in &template.cpuid_modifiers {
        let cpuid_key = CpuidKey {
            leaf: mod_leaf.leaf,
            subleaf: mod_leaf.subleaf,
        };
        if let Some(entry) = guest_cpuid.get_mut(&cpuid_key) {
            entry.flags = mod_leaf.flags;

            // Can we modify one reg multiple times????
            for mod_reg in &mod_leaf.modifiers {
                match mod_reg.register {
                    CpuidRegister::Eax => entry.result.eax = mod_reg.bitmap.apply(entry.result.eax),
                    CpuidRegister::Ebx => entry.result.ebx = mod_reg.bitmap.apply(entry.result.ebx),
                    CpuidRegister::Ecx => entry.result.ecx = mod_reg.bitmap.apply(entry.result.ecx),
                    CpuidRegister::Edx => entry.result.edx = mod_reg.bitmap.apply(entry.result.edx),
                }
            }
        } else {
            return Err(CpuConfigurationError::CpuidFeatureNotSupported(
                cpuid_key.leaf,
                cpuid_key.subleaf,
            ));
        }
    }

    Ok(cpuid)
}

/// Applies the MSR modifiers from a CPU template.
pub(crate) fn apply_template_to_msrs(
    mut msrs: BTreeMap<u32, u64>,
    template: &CustomCpuTemplate,
) -> Result<BTreeMap<u32, u64>, CpuConfigurationError> {
    for modifier in &template.msr_modifiers {
        if let Some(reg_value) = msrs.get_mut(&modifier.addr) {
            *reg_value = modifier.bitmap.apply(*reg_value);
        } else {
            return Err(CpuConfigurationError::MsrNotSupported(modifier.addr));
        }
    }

    Ok(msrs)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use kvm_bindings::KVM_CPUID_FLAG_STATEFUL_FUNC;

    use super::custom_cpu_template::{CpuidLeafModifier, CpuidRegisterModifier, RegisterModifier};
    use super::*;
    use crate::cpu_config::templates::RegisterValueFilter;
    use crate::cpu_config::x86_64::cpuid::{CpuidEntry, IntelCpuid, KvmCpuidFlags};

    fn build_test_template() -> CustomCpuTemplate {
        CustomCpuTemplate {
            cpuid_modifiers: vec![CpuidLeafModifier {
                leaf: 0x3,
                subleaf: 0x0,
                flags: KvmCpuidFlags(KVM_CPUID_FLAG_STATEFUL_FUNC),
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
                        filter: 0b0111,
                        value: 0b0101,
                    },
                },
            ],
            ..Default::default()
        }
    }

    fn build_supported_cpuid() -> Cpuid {
        Cpuid::Intel(IntelCpuid(BTreeMap::from([(
            CpuidKey {
                leaf: 0x3,
                subleaf: 0x0,
            },
            CpuidEntry::default(),
        )])))
    }

    fn build_supported_msrs() -> BTreeMap<u32, u64> {
        BTreeMap::from([(0x8000, 0b1000), (0x9999, 0b1010)])
    }

    fn empty_cpuid() -> Cpuid {
        Cpuid::Intel(IntelCpuid(BTreeMap::new()))
    }

    #[test]
    fn test_empty_template() {
        let template = CustomCpuTemplate::default();
        let cpuid = build_supported_cpuid();
        let msrs = build_supported_msrs();

        assert_eq!(
            apply_template_to_cpuid(cpuid.clone(), &template).unwrap(),
            cpuid
        );
        assert_eq!(
            apply_template_to_msrs(msrs.clone(), &template).unwrap(),
            msrs
        );
    }

    #[test]
    fn test_apply_template_to_cpuid() {
        let template = build_test_template();

        // Verify that modifiers are applied to a supported CPUID leaf.
        let cpuid = apply_template_to_cpuid(build_supported_cpuid(), &template).unwrap();
        let entry = cpuid
            .inner()
            .get(&CpuidKey {
                leaf: 0x3,
                subleaf: 0x0,
            })
            .unwrap();

        assert_eq!(entry.flags, KvmCpuidFlags(KVM_CPUID_FLAG_STATEFUL_FUNC));
        assert_eq!(entry.result.eax, 0b0101);
        assert_eq!(entry.result.ebx, 0b0100);
        assert_eq!(entry.result.ecx, 0b0111);
        assert_eq!(entry.result.edx, 0b0001);

        // Verify that an unsupported CPUID leaf is rejected.
        assert_eq!(
            apply_template_to_cpuid(empty_cpuid(), &template).unwrap_err(),
            CpuConfigurationError::CpuidFeatureNotSupported(0x3, 0x0)
        );
    }

    #[test]
    fn test_apply_template_to_msrs() {
        let template = build_test_template();

        // Verify that modifiers are applied to a supported MSR.
        assert_eq!(
            apply_template_to_msrs(build_supported_msrs(), &template).unwrap(),
            BTreeMap::from([(0x8000, 0b1101), (0x9999, 0b1010)])
        );

        // Verify that an unsupported MSR is rejected.
        assert_eq!(
            apply_template_to_msrs(BTreeMap::new(), &template).unwrap_err(),
            CpuConfigurationError::MsrNotSupported(0x9999)
        );
    }
}
