// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::pci::PciSBDF;

/// Errors for VFIO device configuration.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VfioConfigError {
    /// Duplicate VFIO SBDF: {0}
    DuplicateSBDF(PciSBDF),
    /// Invalid VFIO SBDF: {0}
    InvalidSBDF(String),
}

fn serialize_sbdf_as_str<S: Serializer>(sbdf: &PciSBDF, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&format!("{sbdf}"))
}

fn deserialize_sbdf_from_str<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<PciSBDF, D::Error> {
    let s = String::deserialize(deserializer)?;
    PciSBDF::new_from_str(&s)
        .ok_or_else(|| serde::de::Error::custom(VfioConfigError::InvalidSBDF(s.to_string())))
}

/// Config for VFIO device
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VfioConfig {
    /// ID of the device
    pub id: String,
    /// Host identifier for the PCI device
    #[serde(
        serialize_with = "serialize_sbdf_as_str",
        deserialize_with = "deserialize_sbdf_from_str"
    )]
    pub sbdf: PciSBDF,
}

/// Config for VFIO passthrough devices
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VfioConfigs {
    /// VFIO configs
    pub configs: Vec<VfioConfig>,
}

impl VfioConfigs {
    /// Add config to the set. Overwrite existing one if
    /// ids are same.
    pub fn add(&mut self, config: VfioConfig) -> Result<(), VfioConfigError> {
        if self
            .configs
            .iter()
            .any(|b| b.sbdf == config.sbdf && b.id != config.id)
        {
            return Err(VfioConfigError::DuplicateSBDF(config.sbdf));
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
    fn test_add_vfio_config_and_overwrite() {
        let id1 = PciSBDF::new_from_str("01:00.0").unwrap();
        let id2 = PciSBDF::new_from_str("02:00.0").unwrap();

        let mut configs = VfioConfigs::default();

        configs
            .add(VfioConfig {
                id: "dev0".to_string(),
                sbdf: id1,
            })
            .unwrap();
        assert_eq!(configs.configs.len(), 1);
        assert_eq!(configs.configs[0].sbdf, id1);

        configs
            .add(VfioConfig {
                id: "dev0".to_string(),
                sbdf: id2,
            })
            .unwrap();
        assert_eq!(configs.configs.len(), 1);
        assert_eq!(configs.configs[0].sbdf, id2);

        configs
            .add(VfioConfig {
                id: "dev1".to_string(),
                sbdf: id1,
            })
            .unwrap();
        assert_eq!(configs.configs.len(), 2);
        assert_eq!(configs.configs[0].sbdf, id2);
        assert_eq!(configs.configs[1].sbdf, id1);

        configs
            .add(VfioConfig {
                id: "dev1".to_string(),
                sbdf: id2,
            })
            .unwrap_err();
        assert_eq!(configs.configs.len(), 2);
        assert_eq!(configs.configs[0].sbdf, id2);
        assert_eq!(configs.configs[1].sbdf, id1);
    }
}
