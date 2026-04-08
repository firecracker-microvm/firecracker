// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::pci::PciSBDF;

/// Errors for device passthrough configuration.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum DevicePassthroughConfigError {
    /// Duplicate device passthrough SBDF: {0}
    DuplicateSBDF(PciSBDF),
    /// Invalid device passthrough SBDF: {0}
    InvalidSBDF(String),
}

fn serialize_sbdf_as_str<S: Serializer>(sbdf: &PciSBDF, serializer: S) -> Result<S::Ok, S::Error> {
    // Serialize to string to present in a "0000:01:02.03" format
    serializer.collect_str(&sbdf)
}

fn deserialize_sbdf_from_str<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<PciSBDF, D::Error> {
    let s = String::deserialize(deserializer)?;
    PciSBDF::new_from_str(&s).ok_or_else(|| {
        serde::de::Error::custom(DevicePassthroughConfigError::InvalidSBDF(s.to_string()))
    })
}

/// Config for device passthrough
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePassthroughConfig {
    /// ID of the device
    pub id: String,
    /// Host identifier for the PCI device
    #[serde(
        serialize_with = "serialize_sbdf_as_str",
        deserialize_with = "deserialize_sbdf_from_str"
    )]
    pub sbdf: PciSBDF,
}

/// Configs for device passthrough
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DevicePassthroughConfigs {
    /// configs
    pub configs: Vec<DevicePassthroughConfig>,
}

impl DevicePassthroughConfigs {
    /// Add config to the set. Overwrite existing one if
    /// ids are same.
    pub fn add(
        &mut self,
        config: DevicePassthroughConfig,
    ) -> Result<(), DevicePassthroughConfigError> {
        if self
            .configs
            .iter()
            .any(|b| b.sbdf == config.sbdf && b.id != config.id)
        {
            return Err(DevicePassthroughConfigError::DuplicateSBDF(config.sbdf));
        }
        if let Some(old_config) = self.configs.iter_mut().find(|b| b.id == config.id) {
            old_config.sbdf = config.sbdf;
        } else {
            self.configs.push(config);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_device_passthrough_config_and_overwrite() {
        let id1 = PciSBDF::new_from_str("01:00.0").unwrap();
        let id2 = PciSBDF::new_from_str("02:00.0").unwrap();

        let mut configs = DevicePassthroughConfigs::default();

        configs
            .add(DevicePassthroughConfig {
                id: "dev0".to_string(),
                sbdf: id1,
            })
            .unwrap();
        assert_eq!(configs.configs.len(), 1);
        assert_eq!(configs.configs[0].sbdf, id1);

        configs
            .add(DevicePassthroughConfig {
                id: "dev0".to_string(),
                sbdf: id2,
            })
            .unwrap();
        assert_eq!(configs.configs.len(), 1);
        assert_eq!(configs.configs[0].sbdf, id2);

        configs
            .add(DevicePassthroughConfig {
                id: "dev1".to_string(),
                sbdf: id1,
            })
            .unwrap();
        assert_eq!(configs.configs.len(), 2);
        assert_eq!(configs.configs[0].sbdf, id2);
        assert_eq!(configs.configs[1].sbdf, id1);

        configs
            .add(DevicePassthroughConfig {
                id: "dev1".to_string(),
                sbdf: id2,
            })
            .unwrap_err();
        assert_eq!(configs.configs.len(), 2);
        assert_eq!(configs.configs[0].sbdf, id2);
        assert_eq!(configs.configs[1].sbdf, id1);
    }
}
