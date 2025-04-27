// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::cpu_config::templates::CustomCpuTemplate;

use super::{VerifyError, verify_common};
use crate::utils::aarch64::RegModifierMap;

pub fn verify(
    cpu_template: CustomCpuTemplate,
    cpu_config: CustomCpuTemplate,
) -> Result<(), VerifyError> {
    let reg_template = RegModifierMap::from(cpu_template.reg_modifiers);
    let reg_config = RegModifierMap::from(cpu_config.reg_modifiers);
    verify_common(reg_template.0, reg_config.0)
}

#[cfg(test)]
mod tests {
    use vmm::cpu_config::aarch64::custom_cpu_template::RegisterModifier;
    use vmm::cpu_config::templates::RegisterValueFilter;

    use super::*;
    use crate::utils::aarch64::reg_modifier;

    #[test]
    #[rustfmt::skip]
    fn test_verify_non_existing_reg() {
        // Test with a sample whose register exists in template, but not in config.
        let template = CustomCpuTemplate {
            reg_modifiers: vec![
                reg_modifier!(0x0, 0b00000000),
                reg_modifier!(0x1, 0b11111111),
            ],
            ..Default::default()
        };
        let config = CustomCpuTemplate {
            reg_modifiers: vec![
                reg_modifier!(0x0, 0b00000000),
            ],
            ..Default::default()
        };
        assert_eq!(
            verify(template, config).unwrap_err().to_string(),
            "ID=0x1 not found in CPU configuration."
        );
    }

    #[test]
    fn test_verify_mismatched_reg() {
        // Test with a sample whose register value mismatches.
        let template = CustomCpuTemplate {
            reg_modifiers: vec![reg_modifier!(0x0, 0b10101010, 0b11110000)],
            ..Default::default()
        };
        let config = CustomCpuTemplate {
            reg_modifiers: vec![reg_modifier!(0x0, 0b01010101, 0b11111111)],
            ..Default::default()
        };
        assert_eq!(
            verify(template, config).unwrap_err().to_string(),
            "Value for ID=0x0 mismatched.\n\
             * CPU template     : 0b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010100000\n\
             * CPU configuration: 0b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001010000\n\
             * Diff             :                                                                                                                           ^^^^    "
        )
    }
}
