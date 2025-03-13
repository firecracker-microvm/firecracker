// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::arch::aarch64::regs::{PC, RegSize, SYS_CNTPCT_EL0, SYS_CNTV_CVAL_EL0};
use vmm::cpu_config::aarch64::custom_cpu_template::RegisterModifier;
use vmm::cpu_config::templates::{CpuConfiguration, CustomCpuTemplate, RegisterValueFilter};
use vmm::logger::warn;

use crate::utils::aarch64::reg_modifier;

pub fn config_to_template(cpu_config: &CpuConfiguration) -> CustomCpuTemplate {
    let mut reg_modifiers: Vec<RegisterModifier> = cpu_config
        .regs
        .iter()
        .filter_map(|reg| match reg.size() {
            RegSize::U32 => Some(reg_modifier!(reg.id, u128::from(reg.value::<u32, 4>()))),
            RegSize::U64 => Some(reg_modifier!(reg.id, u128::from(reg.value::<u64, 8>()))),
            RegSize::U128 => Some(reg_modifier!(reg.id, reg.value::<u128, 16>())),
            _ => {
                warn!(
                    "Only 32, 64 and 128 bit wide registers are supported in cpu templates. \
                     Skipping: {:#x}",
                    reg.id
                );
                None
            }
        })
        .collect();

    reg_modifiers.retain(|modifier| !REG_EXCLUSION_LIST.contains(&modifier.addr));

    reg_modifiers.sort_by_key(|modifier| modifier.addr);

    CustomCpuTemplate {
        reg_modifiers,
        ..Default::default()
    }
}

// List of register IDs excluded from the CPU configuration dump.
const REG_EXCLUSION_LIST: [u64; 3] = [
    // SYS_CNTV_CVAL_EL0 and SYS_CNTPCT_EL0 are timer registers and depend on the elapsed time.
    // This type of registers are not useful as guest CPU config dump.
    SYS_CNTV_CVAL_EL0,
    SYS_CNTPCT_EL0,
    // Program counter (PC) value is determined by the given kernel image. It should not be
    // overwritten by a custom CPU template and does not need to be tracked in a fingerprint file.
    PC,
];

#[cfg(test)]
mod tests {
    use vmm::arch::aarch64::regs::{Aarch64RegisterRef, Aarch64RegisterVec, reg_size};

    use super::*;

    // These are used as IDs to satisfy requirenments
    // of `Aarch64RegisterRef::new`
    const KVM_REG_SIZE_U32: u64 = 0x0020000000000000;
    const KVM_REG_SIZE_U64: u64 = 0x0030000000000000;
    const KVM_REG_SIZE_U128: u64 = 0x0040000000000000;
    const KVM_REG_SIZE_U256: u64 = 0x0050000000000000;
    const KVM_REG_SIZE_U512: u64 = 0x0060000000000000;
    const KVM_REG_SIZE_U1024: u64 = 0x0070000000000000;
    const KVM_REG_SIZE_U2048: u64 = 0x0080000000000000;

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
        // CPU templates only supports 32, 64 and 128 bit wide registers, so the following registers
        // should be excluded from the result.
        v.push(Aarch64RegisterRef::new(KVM_REG_SIZE_U256, &[0x69; 32]));
        v.push(Aarch64RegisterRef::new(KVM_REG_SIZE_U512, &[0x69; 64]));
        v.push(Aarch64RegisterRef::new(KVM_REG_SIZE_U1024, &[0x69; 128]));
        v.push(Aarch64RegisterRef::new(KVM_REG_SIZE_U2048, &[0x69; 256]));
        // The following registers should be excluded from the result.
        for id in REG_EXCLUSION_LIST {
            v.push(Aarch64RegisterRef::new(id, &vec![0; reg_size(id)]));
        }
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
