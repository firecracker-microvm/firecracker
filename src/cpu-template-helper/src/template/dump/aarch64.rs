// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::arch::aarch64::regs::RegSize;
use vmm::cpu_config::aarch64::custom_cpu_template::RegisterModifier;
use vmm::cpu_config::templates::{CpuConfiguration, CustomCpuTemplate, RegisterValueFilter};

use crate::utils::aarch64::reg_modifier;

pub fn config_to_template(cpu_config: &CpuConfiguration) -> CustomCpuTemplate {
    let mut reg_modifiers: Vec<RegisterModifier> = cpu_config
        .regs
        .iter()
        .map(|reg| match reg.size() {
            RegSize::U32 => {
                reg_modifier!(reg.id, u128::from(reg.value::<u32, 4>()))
            }
            RegSize::U64 => {
                reg_modifier!(reg.id, u128::from(reg.value::<u64, 8>()))
            }
            RegSize::U128 => {
                reg_modifier!(reg.id, reg.value::<u128, 16>())
            }
            _ => unreachable!("Only 32, 64 and 128 bit wide registers are supported"),
        })
        .collect();
    reg_modifiers.sort_by_key(|modifier| modifier.addr);

    CustomCpuTemplate {
        reg_modifiers,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use vmm::arch::aarch64::regs::{Aarch64RegisterRef, Aarch64RegisterVec};

    use super::*;

    // These are used as IDs to satisfy requirenments
    // of `Aarch64RegisterRef::new`
    const KVM_REG_SIZE_U32: u64 = 0x0020000000000000;
    const KVM_REG_SIZE_U64: u64 = 0x0030000000000000;
    const KVM_REG_SIZE_U128: u64 = 0x0040000000000000;

    fn build_sample_regs() -> Aarch64RegisterVec {
        let mut v = Aarch64RegisterVec::default();
        v.push(Aarch64RegisterRef::new(
            KVM_REG_SIZE_U128,
            &0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_u128.to_le_bytes(),
        ));
        v.push(Aarch64RegisterRef::new(
            KVM_REG_SIZE_U32,
            &0x0000_ffff_u32.to_le_bytes(),
        ));
        v.push(Aarch64RegisterRef::new(
            KVM_REG_SIZE_U64,
            &0x0000_ffff_0000_ffff_u64.to_le_bytes(),
        ));
        v
    }

    fn build_expected_reg_modifiers() -> Vec<RegisterModifier> {
        vec![
            reg_modifier!(KVM_REG_SIZE_U32, 0x0000_ffff),
            reg_modifier!(KVM_REG_SIZE_U64, 0x0000_ffff_0000_ffff),
            reg_modifier!(KVM_REG_SIZE_U128, 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff),
        ]
    }

    #[test]
    fn test_config_to_template() {
        let cpu_config = CpuConfiguration {
            regs: build_sample_regs(),
        };
        let cpu_template = CustomCpuTemplate {
            reg_modifiers: build_expected_reg_modifiers(),
            ..Default::default()
        };
        assert_eq!(config_to_template(&cpu_config), cpu_template);
    }
}
