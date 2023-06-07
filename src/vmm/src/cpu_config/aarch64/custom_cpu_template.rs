// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Guest config sub-module specifically for
/// config templates.
use std::borrow::Cow;
use std::result::Result;

use serde::{Deserialize, Serialize};

use crate::cpu_config::aarch64::static_cpu_templates::v1n1;
use crate::cpu_config::templates::{
    CpuTemplateType, GetCpuTemplate, GetCpuTemplateError, RegisterValueFilter, StaticCpuTemplate,
};
use crate::cpu_config::templates_serde::*;

impl GetCpuTemplate for Option<CpuTemplateType> {
    fn get_cpu_template(&self) -> Result<Cow<CustomCpuTemplate>, GetCpuTemplateError> {
        match self {
            Some(template_type) => match template_type {
                CpuTemplateType::Custom(template) => Ok(Cow::Borrowed(template)),
                CpuTemplateType::Static(template) => match template {
                    // TODO: Check if the CPU model is Neoverse-V1.
                    StaticCpuTemplate::V1N1 => Ok(Cow::Owned(v1n1::v1n1())),
                    other => Err(GetCpuTemplateError::InvalidStaticCpuTemplate(*other)),
                },
            },
            None => Ok(Cow::Owned(CustomCpuTemplate::default())),
        }
    }
}

/// Wrapper type to containing aarch64 CPU config modifiers.
#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomCpuTemplate {
    /// Modifiers for registers on Aarch64 CPUs.
    #[serde(default)]
    pub reg_modifiers: Vec<RegisterModifier>,
}

impl CustomCpuTemplate {
    /// Get a list of register IDs that are modified by the CPU template.
    pub fn reg_list(&self) -> Vec<u64> {
        self.reg_modifiers
            .iter()
            .map(|modifier| modifier.addr)
            .collect()
    }
}

/// Wrapper of a mask defined as a bitmap to apply
/// changes to a given register's value.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Hash)]
pub struct RegisterModifier {
    /// Pointer of the location to be bit mapped.
    #[serde(
        deserialize_with = "deserialize_from_str_u64",
        serialize_with = "serialize_to_hex_str"
    )]
    pub addr: u64,
    /// Bit mapping to be applied as a modifier to the
    /// register's value at the address provided.
    pub bitmap: RegisterValueFilter<u128>,
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;
    use crate::cpu_config::templates::test_utils::{build_test_template, TEST_TEMPLATE_JSON};

    #[test]
    fn test_get_cpu_template_with_no_template() {
        // Test `get_cpu_template()` when no template is provided. The empty owned
        // `CustomCpuTemplate` should be returned.
        let cpu_template = None;
        assert_eq!(
            cpu_template.get_cpu_template().unwrap(),
            Cow::Owned(CustomCpuTemplate::default()),
        );
    }

    #[test]
    fn test_get_cpu_template_with_v1n1_static_template() {
        // Test `get_cpu_template()` when V1N1 static CPU template is specified. The owned
        // `CustomCpuTemplate` should be returned.
        let cpu_template = Some(CpuTemplateType::Static(StaticCpuTemplate::V1N1));
        assert_eq!(
            cpu_template.get_cpu_template().unwrap(),
            Cow::Owned(v1n1::v1n1())
        );
    }

    #[test]
    fn test_get_cpu_tempalte_with_none_static_template() {
        // Test `get_cpu_template()` when no static CPU template is provided.
        // `InvalidStaticCpuTemplate` error should be returned because it is no longer valid and
        // was replaced with `None` of `Option<CpuTemplateType>`.
        let cpu_template = Some(CpuTemplateType::Static(StaticCpuTemplate::None));
        assert_eq!(
            cpu_template.get_cpu_template().unwrap_err(),
            GetCpuTemplateError::InvalidStaticCpuTemplate(StaticCpuTemplate::None)
        );
    }

    #[test]
    fn test_get_cpu_template_with_empty0_static_template() {
        // Test `get_cpu_template()` when `Empty0` static CPU template is provided.
        // `InvalidStaticCpuTemplate` error should be returned, because `StaticCpuTemplate::Empty0`
        // is invalid and is used as a placeholder to align the position of
        // `StaticCpuTemplate::None` with x86_64.
        let cpu_template = Some(CpuTemplateType::Static(StaticCpuTemplate::Empty0));
        assert_eq!(
            cpu_template.get_cpu_template().unwrap_err(),
            GetCpuTemplateError::InvalidStaticCpuTemplate(StaticCpuTemplate::Empty0)
        );
    }

    #[test]
    fn test_get_cpu_template_with_empty1_static_template() {
        // Test `get_cpu_template()` when `Empty1` static CPU template is provided.
        // `InvalidStaticCpuTemplate` error should be returned, because `StaticCpuTemplate::Empty1`
        // is invalid and is used as a placeholder to align the position of
        // `StaticCpuTemplate::None` with x86_64.
        let cpu_template = Some(CpuTemplateType::Static(StaticCpuTemplate::Empty1));
        assert_eq!(
            cpu_template.get_cpu_template().unwrap_err(),
            GetCpuTemplateError::InvalidStaticCpuTemplate(StaticCpuTemplate::Empty1)
        );
    }

    #[test]
    fn test_get_cpu_template_with_custom_template() {
        // Test `get_cpu_template()` when a custom CPU template is provided. The borrowed
        // `CustomCpuTemplate` should be returned.
        let inner_cpu_template = CustomCpuTemplate::default();
        let cpu_template = Some(CpuTemplateType::Custom(inner_cpu_template.clone()));
        assert_eq!(
            cpu_template.get_cpu_template().unwrap(),
            Cow::Borrowed(&inner_cpu_template)
        );
    }

    #[test]
    fn test_malformed_json() {
        // Malformed register address
        let cpu_config_result = serde_json::from_str::<CustomCpuTemplate>(
            r#"{
                    "reg_modifiers":  [
                        {
                            "addr": "j",
                            "bitmap": "0bx00100xxx1xxxx00xxx1xxxxxxxxxxx1"
                        },
                    ]
                }"#,
        );
        assert!(cpu_config_result.is_err());
        let error_msg: String = cpu_config_result.unwrap_err().to_string();
        // Formatted error expected clarifying the number system prefix is missing
        assert!(
            error_msg.contains("No supported number system prefix found in value"),
            "{}",
            error_msg
        );

        // Malformed address as binary
        let cpu_config_result = serde_json::from_str::<CustomCpuTemplate>(
            r#"{
                    "reg_modifiers":  [
                        {
                            "addr": "0bK",
                            "bitmap": "0bx00100xxx1xxxx00xxx1xxxxxxxxxxx1"
                        },
                    ]
                }"#,
        );
        assert!(cpu_config_result.is_err());
        assert!(cpu_config_result
            .unwrap_err()
            .to_string()
            .contains("Failed to parse string [0bK] as a number for CPU template"));

        // Malformed 64-bit bitmap - filter failed
        let cpu_config_result = serde_json::from_str::<CustomCpuTemplate>(
            r#"{
                    "reg_modifiers":  [
                        {
                            "addr": "0x200",
                            "bitmap": "0bx0?1_0_0x_?x1xxxx00xxx1xxxxxxxxxxx1"
                        },
                    ]
                }"#,
        );
        assert!(cpu_config_result.is_err());
        assert!(cpu_config_result.unwrap_err().to_string().contains(
            "Failed to parse string [0bx0?1_0_0x_?x1xxxx00xxx1xxxxxxxxxxx1] as a bitmap"
        ));

        // Malformed 64-bit bitmap - value failed
        let cpu_config_result = serde_json::from_str::<CustomCpuTemplate>(
            r#"{
                    "reg_modifiers":  [
                        {
                            "addr": "0x200",
                            "bitmap": "0bx00100x0x1xxxx05xxx1xxxxxxxxxxx1"
                        },
                    ]
                }"#,
        );
        assert!(cpu_config_result.is_err());
        assert!(cpu_config_result
            .unwrap_err()
            .to_string()
            .contains("Failed to parse string [0bx00100x0x1xxxx05xxx1xxxxxxxxxxx1] as a bitmap"));
    }

    #[test]
    fn test_deserialization_lifecycle() {
        let cpu_config = serde_json::from_str::<CustomCpuTemplate>(TEST_TEMPLATE_JSON)
            .expect("Failed to deserialize custom CPU template.");
        assert_eq!(2, cpu_config.reg_modifiers.len());
    }

    #[test]
    fn test_serialization_lifecycle() {
        let template = build_test_template();
        let template_json_str_result = serde_json::to_string_pretty(&template);
        assert!(&template_json_str_result.is_ok());
        let template_json = template_json_str_result.unwrap();

        let deserialization_result = serde_json::from_str::<CustomCpuTemplate>(&template_json);
        assert!(deserialization_result.is_ok());
        assert_eq!(template, deserialization_result.unwrap());
    }

    /// Test to confirm that templates for different CPU architectures have
    /// a size bitmask that is supported by the architecture when serialized to JSON.
    #[test]
    fn test_bitmap_width() {
        let mut checked = false;

        let template = build_test_template();

        let aarch64_template_str =
            serde_json::to_string(&template).expect("Error serializing aarch64 template");
        let json_tree: Value = serde_json::from_str(&aarch64_template_str)
            .expect("Error deserializing aarch64 template JSON string");

        // Check that bitmap for aarch64 masks are serialized to 128-bits
        if let Some(modifiers_root) = json_tree.get("reg_modifiers") {
            let mod_node = &modifiers_root.as_array().unwrap()[0];
            if let Some(bit_map_str) = mod_node.get("bitmap") {
                // 128-bit width with a "0b" prefix for binary-formatted numbers
                assert_eq!(bit_map_str.as_str().unwrap().len(), 130);
                assert!(bit_map_str.as_str().unwrap().starts_with("0b"));
                checked = true;
            }
        }

        assert!(
            checked,
            "Bitmap width in a aarch64 template was not tested."
        );
    }
}
