// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::cpu_config::aarch64::custom_cpu_template::RegisterModifier;
use vmm::cpu_config::templates::{CpuConfiguration, CustomCpuTemplate, RegisterValueFilter};

use crate::utils::aarch64::reg_modifier;

pub fn config_to_template(cpu_config: &CpuConfiguration) -> CustomCpuTemplate {
    let mut reg_modifiers: Vec<RegisterModifier> = cpu_config
        .regs
        .iter()
        .map(|reg| reg_modifier!(reg.id, reg.value))
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
            reg_modifier!(
                0x0000_0000_0000_0000,
                0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff
            ),
            reg_modifier!(
                0x0000_0000_0000_0001,
                0x0000_ffff_0000_ffff_0000_ffff_0000_ffff
            ),
            reg_modifier!(
                0xffff_ffff_ffff_ffff,
                0x0000_ffff_0000_ffff_0000_ffff_0000_ffff
            ),
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
