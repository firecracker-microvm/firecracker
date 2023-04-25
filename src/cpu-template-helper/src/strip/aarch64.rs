// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;

use vmm::guest_config::templates::CustomCpuTemplate;

use crate::strip::remove_common;

#[allow(dead_code)]
pub fn strip(templates: Vec<CustomCpuTemplate>) -> Vec<CustomCpuTemplate> {
    // Convert `Vec<CustomCpuTemplate>` to `Vec<HashSet<RegisterModifier>>`.
    let mut reg_modifiers_sets = templates
        .into_iter()
        .map(|template| template.reg_modifiers.into_iter().collect::<HashSet<_>>())
        .collect::<Vec<_>>();

    // Remove common items.
    remove_common(&mut reg_modifiers_sets);

    // Convert back to `Vec<CustomCpuTemplate>`.
    reg_modifiers_sets
        .into_iter()
        .map(|reg_modifiers_set| {
            let mut reg_modifiers = reg_modifiers_set.into_iter().collect::<Vec<_>>();
            reg_modifiers.sort_by_key(|modifier| modifier.addr);
            CustomCpuTemplate { reg_modifiers }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use vmm::guest_config::templates::aarch64::{RegisterModifier, RegisterValueFilter};

    use super::*;

    macro_rules! reg_modifier {
        ($addr:literal, $value:literal) => {
            RegisterModifier {
                addr: $addr,
                bitmap: RegisterValueFilter {
                    filter: u128::MAX,
                    value: $value,
                },
            }
        };
    }

    // Summary of reg modifiers:
    // * As addr 0x0 modifier exists in all the templates but its values are different, it should be
    //   preserved.
    // * As addr 0x1 modifier exists in all the templates and its values are same, it should be
    //   removed.
    // * As addr 0x2 modifier only exist in the third template, it should be preserved.
    #[rustfmt::skip]
    fn build_input_templates() -> Vec<CustomCpuTemplate> {
        vec![
            CustomCpuTemplate {
                reg_modifiers: vec![
                    reg_modifier!(0x0, 0x0),
                    reg_modifier!(0x1, 0x1),
                ],
            },
            CustomCpuTemplate {
                reg_modifiers: vec![
                    reg_modifier!(0x0, 0x1),
                    reg_modifier!(0x1, 0x1),
                ],
            },
            CustomCpuTemplate {
                reg_modifiers: vec![
                    reg_modifier!(0x0, 0x2),
                    reg_modifier!(0x1, 0x1),
                    reg_modifier!(0x2, 0x1),
                ],
            },
        ]
    }

    #[rustfmt::skip]
    fn build_expected_templates() -> Vec<CustomCpuTemplate> {
        vec![
            CustomCpuTemplate {
                reg_modifiers: vec![
                    reg_modifier!(0x0, 0x0),
                ],
            },
            CustomCpuTemplate {
                reg_modifiers: vec![
                    reg_modifier!(0x0, 0x1),
                ],
            },
            CustomCpuTemplate {
                reg_modifiers: vec![
                    reg_modifier!(0x0, 0x2),
                    reg_modifier!(0x2, 0x1),
                ],
            },
        ]
    }

    #[test]
    fn test_strip_reg_modifiers() {
        let input = build_input_templates();
        let result = strip(input);
        let expected = build_expected_templates();
        assert_eq!(result, expected);
    }
}
