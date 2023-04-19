// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::guest_config::templates::aarch64::{RegisterModifier, RegisterValueFilter};
use vmm::guest_config::templates::{CpuConfiguration, CustomCpuTemplate};

pub fn config_to_template(cpu_config: &CpuConfiguration) -> CustomCpuTemplate {
    let mut reg_modifiers: Vec<RegisterModifier> = cpu_config
        .regs
        .iter()
        .map(|reg| RegisterModifier {
            addr: reg.id,
            bitmap: RegisterValueFilter {
                filter: u128::MAX,
                value: reg.value,
            },
        })
        .collect();
    reg_modifiers.sort_by_key(|modifier| modifier.addr);

    CustomCpuTemplate { reg_modifiers }
}

#[cfg(test)]
mod tests {
    use vmm::arch::aarch64::regs::Aarch64Register;

    use super::*;

    fn build_sample_regs() -> Vec<Aarch64Register> {
        vec![
            Aarch64Register {
                id: 0x0,
                value: 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
            },
            Aarch64Register {
                id: 0xffff_ffff_ffff_ffff,
                value: 0x0000_ffff_0000_ffff_0000_ffff_0000_ffff,
            },
            Aarch64Register {
                id: 0x1,
                value: 0x0000_ffff_0000_ffff_0000_ffff_0000_ffff,
            },
        ]
    }

    fn build_expected_reg_modifiers() -> Vec<RegisterModifier> {
        vec![
            RegisterModifier {
                addr: 0x0000_0000_0000_0000,
                bitmap: RegisterValueFilter {
                    filter: 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
                    value: 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
                },
            },
            RegisterModifier {
                addr: 0x0000_0000_0000_0001,
                bitmap: RegisterValueFilter {
                    filter: 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
                    value: 0x0000_ffff_0000_ffff_0000_ffff_0000_ffff,
                },
            },
            RegisterModifier {
                addr: 0xffff_ffff_ffff_ffff,
                bitmap: RegisterValueFilter {
                    filter: 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
                    value: 0x0000_ffff_0000_ffff_0000_ffff_0000_ffff,
                },
            },
        ]
    }

    #[test]
    fn test_config_to_template() {
        let cpu_config = CpuConfiguration {
            regs: build_sample_regs(),
        };
        let cpu_template = CustomCpuTemplate {
            reg_modifiers: build_expected_reg_modifiers(),
        };
        assert_eq!(config_to_template(&cpu_config), cpu_template);
    }
}
