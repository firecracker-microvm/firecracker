// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Module with CPU templates for x86_64
pub mod static_cpu_templates;

use std::collections::{HashMap, HashSet};

use kvm_bindings::{kvm_msr_entry, Msrs, KVM_MAX_MSR_ENTRIES};
use kvm_ioctls::VcpuFd;
use static_cpu_templates::*;

use super::cpuid::{CpuidKey, RawCpuid};
use super::templates::x86_64::CpuidRegister;
use super::templates::{CpuTemplateType, CustomCpuTemplate};
use crate::arch::x86_64::msr::create_boot_msr_entries;
use crate::guest_config::cpuid::Cpuid;
use crate::vstate::vcpu::msr_entries_to_save;
use crate::vstate::vm::Vm;

/// Errors thrown while configuring templates.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Failure in processing the CPUID in template for x86_64 CPU configuration.
    #[error("Template changes a CPUID entry not supported by KVM: Leaf: {0:0x}, Subleaf: {1:0x}")]
    CpuidFeatureNotSupported(u32, u32),
    /// Failure in processing the MSRs in template for x86_64 CPU configuration.
    #[error("Template changes an MSR entry not supported by KVM: Register Address: {0:0x}")]
    MsrNotSupported(u32),
    /// Can not join 2 cpuids.
    #[error("Can not join 2 cpuids: {0}")]
    CpuidJoin(super::cpuid::CpuidJoinError),
    /// Can create cpuid from raw.
    #[error("Can create cpuid from raw: {0}")]
    CpuidFromRaw(super::cpuid::CpuidTryFromRawCpuid),
    /// Failed to get KVM vCPU MSRs.
    #[error("Failed to get KVM vCPU MSRs: {0}")]
    VcpuGetMsrs(kvm_ioctls::Error),
    /// The number of MSRs returned by the kernel is unexpected.
    #[error("Unexpected number of MSRs reported by the kernel")]
    VcpuGetMsrsIncomplete,
}

/// CPU configuration for x86_64 CPUs
#[derive(Debug, Clone, PartialEq)]
pub struct CpuConfiguration {
    /// CPUID configuration
    pub cpuid: Cpuid,
    /// Register values as a key pair for model specific registers
    /// Key: MSR address
    /// Value: MSR value
    pub msrs: HashMap<u32, u64>,

    /// Set of supported MSRs
    pub supported_msrs: HashSet<u32>,

    /// Architectural MSPs required for boot
    pub msr_boot_entries: Vec<kvm_msr_entry>,
}

impl CpuConfiguration {
    /// Creates new CpuConfig with cpu template changes applied
    pub fn new(vm: &Vm, vcpu: &VcpuFd, template: &Option<CpuTemplateType>) -> Result<Self, Error> {
        match template {
            Some(ref cpu_template) => Self::with_template(vcpu, vm, cpu_template),
            None => Self::host(vm),
        }
    }

    /// Creates new CpuConfig with default values
    pub fn host(vm: &Vm) -> Result<Self, Error> {
        let supported_cpuid = vm.supported_cpuid().clone();
        let supported_cpuid =
            Cpuid::try_from(RawCpuid::from(supported_cpuid)).map_err(Error::CpuidFromRaw)?;

        Ok(Self {
            cpuid: supported_cpuid,
            msrs: Default::default(),
            supported_msrs: Default::default(),
            msr_boot_entries: create_boot_msr_entries(),
        })
    }

    /// Creates new CpuConfig with cpu template changes applied
    pub fn with_template(
        vcpu: &VcpuFd,
        vm: &Vm,
        template: &CpuTemplateType,
    ) -> Result<Self, Error> {
        match template {
            CpuTemplateType::Custom(template) => Self::host(vm)?.apply_template(vcpu, template),
            CpuTemplateType::Static(template) => {
                let mut config = Self::host(vm)?;
                // If a template is specified, get the CPUID template, else use `cpuid`.
                let template_cpuid = match template {
                    StaticCpuTemplate::C3 => static_cpu_templates::c3::c3(),
                    StaticCpuTemplate::T2 => static_cpu_templates::t2::t2(),
                    StaticCpuTemplate::T2S => static_cpu_templates::t2s::t2s(),
                    StaticCpuTemplate::T2CL => static_cpu_templates::t2cl::t2cl(),
                    StaticCpuTemplate::T2A => static_cpu_templates::t2a::t2a(),
                    StaticCpuTemplate::None => unreachable!("None state is invalid"),
                };

                // Include leaves from host that are not present in CPUID template.
                config.cpuid = template_cpuid
                    .include_leaves_from(config.cpuid)
                    .map_err(Error::CpuidJoin)?;

                // TODO: Some MSRs depend on values of other MSRs. This dependency will need to
                // be implemented. For now we define known dependencies statically in the CPU
                // templates.

                // Depending on which CPU template the user selected, we may need to initialize
                // additional MSRs for boot to correctly enable some CPU features. As stated in
                // the previous comment, we get from the template a static list of MSRs we need
                // to save at snapshot as well.
                // C3, T2 and T2A currently don't have extra MSRs to save/set.
                match template {
                    StaticCpuTemplate::T2S => {
                        config.supported_msrs.extend(msr_entries_to_save());
                        static_cpu_templates::t2s::update_t2s_msr_entries(
                            &mut config.msr_boot_entries,
                        );
                    }
                    StaticCpuTemplate::T2CL => {
                        config.supported_msrs.extend(msr_entries_to_save());
                        static_cpu_templates::t2cl::update_t2cl_msr_entries(
                            &mut config.msr_boot_entries,
                        );
                    }
                    _ => (),
                }

                Ok(config)
            }
        }
    }

    /// Modifies provided config with changes from template
    pub fn apply_template(
        self,
        vcpu: &VcpuFd,
        template: &CustomCpuTemplate,
    ) -> Result<Self, Error> {
        let Self {
            mut cpuid,
            mut msrs,
            supported_msrs,
            msr_boot_entries,
        } = self;

        let guest_cpuid = match &mut cpuid {
            Cpuid::Intel(cpuid) => &mut cpuid.0,
            Cpuid::Amd(cpuid) => &mut cpuid.0,
        };

        // Apply CPUID modifiers
        for mod_leaf in template.cpuid_modifiers.iter() {
            let cpuid_key = CpuidKey {
                leaf: mod_leaf.leaf,
                subleaf: mod_leaf.subleaf,
            };
            if let Some(entry) = guest_cpuid.get_mut(&cpuid_key) {
                entry.flags = mod_leaf.flags;

                // Can we modify one reg multiple times????
                for mod_reg in &mod_leaf.modifiers {
                    match mod_reg.register {
                        CpuidRegister::Eax => {
                            entry.result.eax =
                                mod_reg.bitmap.apply(u64::from(entry.result.eax)) as u32
                        }
                        CpuidRegister::Ebx => {
                            entry.result.ebx =
                                mod_reg.bitmap.apply(u64::from(entry.result.ebx)) as u32
                        }
                        CpuidRegister::Ecx => {
                            entry.result.ecx =
                                mod_reg.bitmap.apply(u64::from(entry.result.ecx)) as u32
                        }
                        CpuidRegister::Edx => {
                            entry.result.edx =
                                mod_reg.bitmap.apply(u64::from(entry.result.edx)) as u32
                        }
                    }
                }
            } else {
                return Err(Error::CpuidFeatureNotSupported(
                    cpuid_key.leaf,
                    cpuid_key.subleaf,
                ));
            }
        }

        // Extract MSR addresses from the template to a vector
        let entries: Vec<kvm_msr_entry> = template
            .msr_modifiers
            .iter()
            .map(|msr| kvm_msr_entry {
                index: msr.addr,
                ..Default::default()
            })
            .collect();

        // We have to read MSRs in chunks, because KVM only allows to read KVM_MAX_MSR_ENTRIES
        // MSRs at a time and the custom CPU template may contain more.
        for chunk in entries.chunks(KVM_MAX_MSR_ENTRIES) {
            // Safe to unwrap as we are using chunks of KVM_MAX_MSR_ENTRIES MSR entries
            let mut kvm_msrs = Msrs::from_entries(chunk).unwrap();

            // Read MSRs from KVM
            let num_msrs = vcpu.get_msrs(&mut kvm_msrs).map_err(Error::VcpuGetMsrs)?;
            if num_msrs != chunk.len() {
                return Err(Error::VcpuGetMsrsIncomplete);
            }

            msrs.extend(kvm_msrs.as_slice().iter().map(|ent| (ent.index, ent.data)));
        }

        for modifier in &template.msr_modifiers {
            if let Some(reg_value) = msrs.get_mut(&modifier.addr) {
                *reg_value = modifier.bitmap.apply(*reg_value);
            } else {
                return Err(Error::MsrNotSupported(modifier.addr));
            }
        }

        Ok(Self {
            cpuid,
            msrs,
            supported_msrs,
            msr_boot_entries,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use kvm_bindings::KVM_CPUID_FLAG_STATEFUL_FUNC;
    use kvm_ioctls::Kvm;

    use super::*;
    use crate::guest_config::cpuid::{IntelCpuid, KvmCpuidFlags};
    use crate::guest_config::templates::x86_64::{
        CpuidLeafModifier, CpuidRegisterModifier, RegisterModifier, RegisterValueFilter,
    };

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
                        filter: 0,
                        value: 0,
                    },
                },
            ],
        }
    }

    fn empty_cpu_config() -> CpuConfiguration {
        CpuConfiguration {
            cpuid: Cpuid::Intel(IntelCpuid(BTreeMap::new())),
            msrs: Default::default(),
            supported_msrs: Default::default(),
            msr_boot_entries: Default::default(),
        }
    }

    fn supported_cpu_config() -> CpuConfiguration {
        CpuConfiguration {
            cpuid: static_cpu_templates::t2::t2(),
            msrs: HashMap::from([(0x8000, 0b1000), (0x9999, 0b1010)]),
            supported_msrs: Default::default(),
            msr_boot_entries: Default::default(),
        }
    }

    fn unsupported_cpu_config() -> CpuConfiguration {
        CpuConfiguration {
            cpuid: static_cpu_templates::t2::t2(),
            msrs: HashMap::from([(0x8000, 0b1000), (0x8001, 0b1010)]),
            supported_msrs: Default::default(),
            msr_boot_entries: Default::default(),
        }
    }

    #[test]
    fn test_empty_template() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let host_configuration = empty_cpu_config();
        let guest_config_result = host_configuration
            .clone()
            .apply_template(&vcpu, &CustomCpuTemplate::default());
        assert!(
            guest_config_result.is_ok(),
            "{}",
            guest_config_result.unwrap_err()
        );
        // CPUID will be comparable, but not MSRs.
        // The configuration will be configuration required by the template,
        // not a holistic view of all registers.
        assert_eq!(guest_config_result.unwrap().cpuid, host_configuration.cpuid);
    }

    #[test]
    fn test_apply_template() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let host_configuration = supported_cpu_config();
        let guest_config_result = host_configuration
            .clone()
            .apply_template(&vcpu, &build_test_template());
        assert!(
            guest_config_result.is_ok(),
            "{}",
            guest_config_result.unwrap_err()
        );
        assert_ne!(guest_config_result.unwrap(), host_configuration);
    }

    /// Invalid test in this context is when the template
    /// has modifiers for registers that are not supported.
    #[test]
    fn test_invalid_template() {
        // Test CPUID validation
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let host_configuration = empty_cpu_config();
        let guest_template = build_test_template();
        let guest_config_result = host_configuration.apply_template(&vcpu, &guest_template);
        assert!(
            guest_config_result.is_err(),
            "Expected an error as template should have failed to modify a CPUID entry that is not \
             supported by host configuration",
        );
        assert_eq!(
            guest_config_result.unwrap_err(),
            Error::CpuidFeatureNotSupported(
                guest_template.cpuid_modifiers[0].leaf,
                guest_template.cpuid_modifiers[0].subleaf
            )
        );

        // Test MSR validation
        let host_configuration = unsupported_cpu_config();
        let guest_template = build_test_template();
        let guest_config_result = host_configuration.apply_template(&vcpu, &guest_template);
        assert!(
            guest_config_result.is_err(),
            "Expected an error as template should have failed to modify an MSR value that is not \
             supported by host configuration",
        );
        assert_eq!(
            guest_config_result.unwrap_err(),
            Error::MsrNotSupported(guest_template.msr_modifiers[0].addr)
        )
    }
}
