// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

/// Host action requested when the guest reports a panic through pvpanic.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PvPanicAction {
    /// Report the panic without pausing guest execution.
    #[default]
    None,
    /// Pause guest execution after reporting the panic.
    Pause,
}

/// Configuration of the pvpanic device.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct PvPanicConfig {
    /// Action requested when the guest reports `PVPANIC_PANICKED`.
    pub panic_action: PvPanicAction,
}

impl<'de> Deserialize<'de> for PvPanicConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            #[serde(default)]
            panic_action: PvPanicAction,
        }
        struct ConfigVisitor;
        impl<'de> serde::de::Visitor<'de> for ConfigVisitor {
            type Value = PvPanicConfig;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a pvpanic configuration object")
            }

            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                map: M,
            ) -> Result<Self::Value, M::Error> {
                let fields =
                    Fields::deserialize(serde::de::value::MapAccessDeserializer::new(map))?;
                Ok(PvPanicConfig {
                    panic_action: fields.panic_action,
                })
            }
        }
        deserializer.deserialize_map(ConfigVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults_and_round_trip() {
        let default: PvPanicConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(default, PvPanicConfig::default());
        assert_eq!(default.panic_action, PvPanicAction::None);

        for (action, name) in [
            (PvPanicAction::None, "none"),
            (PvPanicAction::Pause, "pause"),
        ] {
            let json = format!(r#"{{"panic_action":"{name}"}}"#);
            let config: PvPanicConfig = serde_json::from_str(&json).unwrap();
            assert_eq!(config.panic_action, action);
            assert_eq!(serde_json::to_string(&config).unwrap(), json);
        }
    }

    #[test]
    fn test_config_rejects_invalid_fields_and_actions() {
        for json in [
            "null",
            "[]",
            "true",
            r#"{"panic_action":"none","panic_action":"pause"}"#,
            r#"{"panic_action":"shutdown"}"#,
            r#"{"panic_action":"Pause"}"#,
            r#"{"panic_action":null}"#,
            r#"{"panic_action":1}"#,
            r#"{"unknown":true}"#,
        ] {
            assert!(
                serde_json::from_str::<PvPanicConfig>(json).is_err(),
                "{json}"
            );
        }
    }
}
