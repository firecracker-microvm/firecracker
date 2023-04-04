// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::fmt;

use serde::{de, Deserialize, Serialize};
use versionize::{VersionMap, Versionize, VersionizeError, VersionizeResult};
use versionize_derive::Versionize;

use crate::guest_config::templates::{CpuTemplate, GuestConfigError};

/// The default memory size of the VM, in MiB.
pub const DEFAULT_MEM_SIZE_MIB: usize = 128;
/// Firecracker aims to support small scale workloads only, so limit the maximum
/// vCPUs supported.
pub const MAX_SUPPORTED_VCPUS: u8 = 32;

/// Errors associated with configuring the microVM.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VmConfigError {
    /// The memory size is smaller than the target size set in the balloon device configuration.
    #[error(
        "The memory size (MiB) is smaller than the previously set balloon device target size."
    )]
    IncompatibleBalloonSize,
    /// The memory size is invalid. The memory can only be an unsigned integer.
    #[error("The memory size (MiB) is invalid.")]
    InvalidMemorySize,
    /// The vcpu count is invalid. When SMT is enabled, the `cpu_count` must be either
    /// 1 or an even number.
    #[error(
        "The vCPU number is invalid! The vCPU number can only be 1 or an even number when SMT is \
         enabled."
    )]
    InvalidVcpuCount,
    /// Could not get the config of the balloon device from the VM resources, even though a
    /// balloon device was previously installed.
    #[error(
        "Could not get the configuration of the previously installed balloon device to validate \
         the memory size."
    )]
    InvalidVmState,
    /// Error applying template to host-supported config to create
    /// vCPU configuration for the guest machine.
    #[error("Error applying CPU template to create guest configuration: {0}")]
    InvalidCpuTemplateConfig(GuestConfigError),
}

/// Strongly typed structure that represents the configuration of the
/// microvm.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VmConfig {
    /// Number of vcpu to start.
    #[serde(deserialize_with = "deserialize_vcpu_num")]
    pub vcpu_count: u8,
    /// The memory size in MiB.
    pub mem_size_mib: usize,
    /// Enables or disabled SMT.
    #[serde(default, deserialize_with = "deserialize_smt")]
    pub smt: bool,
    /// A CPU template that it is used to filter the CPU features exposed to the guest.
    #[serde(
        default,
        deserialize_with = "deserialize_cpu_template",
        skip_serializing_if = "CpuFeaturesTemplate::is_none"
    )]
    pub cpu_template: CpuFeaturesTemplate,
    /// Enables or disables dirty page tracking. Enabling allows incremental snapshots.
    #[serde(default)]
    pub track_dirty_pages: bool,
}

impl Default for VmConfig {
    fn default() -> Self {
        VmConfig {
            vcpu_count: 1,
            mem_size_mib: DEFAULT_MEM_SIZE_MIB,
            smt: false,
            cpu_template: CpuFeaturesTemplate::None,
            track_dirty_pages: false,
        }
    }
}

impl fmt::Display for VmConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{{ \"vcpu_count\": {:?}, \"mem_size_mib\": {:?}, \"smt\": {:?}, \"cpu_template\": \
             {:?}, \"track_dirty_pages\": {:?} }}",
            self.vcpu_count, self.mem_size_mib, self.smt, self.cpu_template, self.track_dirty_pages
        )
    }
}

/// Spec for partial configuration of the machine.
/// This struct mirrors all the fields in `VmConfig`.
/// All fields are optional, but at least one needs to be specified.
/// If a field is `Some(value)` then we assume an update is requested
/// for that field.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VmUpdateConfig {
    /// Number of vcpu to start.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_vcpu_num"
    )]
    pub vcpu_count: Option<u8>,
    /// The memory size in MiB.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_size_mib: Option<usize>,
    /// Enables or disabled SMT.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_smt"
    )]
    pub smt: Option<bool>,
    /// A CPU template that it is used to filter the CPU features exposed to the guest.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_cpu_template"
    )]
    pub cpu_template: Option<CpuFeaturesTemplate>,
    /// Enables or disables dirty page tracking. Enabling allows incremental snapshots.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub track_dirty_pages: Option<bool>,
}

impl VmUpdateConfig {
    /// Checks if the update request contains any data.
    /// Returns `true` if all fields are set to `None` which means that there is nothing
    /// to be updated.
    pub fn is_empty(&self) -> bool {
        if self.vcpu_count.is_none()
            && self.mem_size_mib.is_none()
            && self.cpu_template.is_none()
            && self.smt.is_none()
            && self.track_dirty_pages.is_none()
        {
            return true;
        }

        false
    }
}

impl From<VmConfig> for VmUpdateConfig {
    fn from(cfg: VmConfig) -> Self {
        VmUpdateConfig {
            vcpu_count: Some(cfg.vcpu_count),
            mem_size_mib: Some(cfg.mem_size_mib),
            smt: Some(cfg.smt),
            cpu_template: Some(cfg.cpu_template),
            track_dirty_pages: Some(cfg.track_dirty_pages),
        }
    }
}

/// Builder to generate VmConfig while also storing custom templates.
/// When a custom template is not defined the VmConfig can permit
/// a static template as defined by the variants in `CpuFeaturesTemplate`.
/// If a custom template is defined, the `VmConfig.cpu_template` field
/// will return CpuFeatureTemplate::None.
#[derive(Clone, Default)]
pub struct VmConfigBuilder {
    /// Custom CPU template, if populated, will force a default value
    /// for the VmConfig.cpu_feature field.
    pub custom_cpu_template: Option<CpuTemplate>,
    /// VmConfig structure with default values.
    pub config: VmConfig,
}

impl VmConfigBuilder {
    /// Gives data for initializing VmConfig that
    /// takes custom CPU templates into consideration.
    pub fn new(
        config: VmConfig,
        custom_cpu_template: Option<CpuTemplate>,
    ) -> Result<VmConfigBuilder, VmConfigError> {
        if config.cpu_template != CpuFeaturesTemplate::None && custom_cpu_template.is_some() {
            Err(VmConfigError::InvalidCpuTemplateConfig(
                GuestConfigError::ConflictingCpuTemplateConfigured,
            ))
        } else {
            Ok(VmConfigBuilder {
                custom_cpu_template,
                config,
            })
        }
    }

    pub(crate) fn build(&self) -> VmConfig {
        VmConfig {
            vcpu_count: self.config.vcpu_count,
            mem_size_mib: self.config.mem_size_mib,
            smt: self.config.smt,
            cpu_template: if self.custom_cpu_template.is_some() {
                CpuFeaturesTemplate::None
            } else {
                self.config.cpu_template
            },
            track_dirty_pages: self.config.track_dirty_pages,
        }
    }
}

/// Deserialization function for the `vcpu_num` field in `VmConfig` and `VmUpdateConfig`.
/// This is called only when `vcpu_num` is present in the JSON configuration.
/// `T` can be either `u8` or `Option<u8>` which both support ordering if `vcpu_num` is
/// present in the JSON.
fn deserialize_vcpu_num<'de, D, T>(d: D) -> std::result::Result<T, D::Error>
where
    D: de::Deserializer<'de>,
    T: Deserialize<'de> + PartialOrd + From<u8>,
{
    let val = T::deserialize(d)?;

    if val > T::from(MAX_SUPPORTED_VCPUS) {
        return Err(de::Error::invalid_value(
            de::Unexpected::Other("vcpu_num"),
            &"number of vCPUs exceeds the maximum limitation",
        ));
    }
    if val < T::from(1) {
        return Err(de::Error::invalid_value(
            de::Unexpected::Other("vcpu_num"),
            &"number of vCPUs should be larger than 0",
        ));
    }

    Ok(val)
}

/// Deserialization function for the `smt` field in `VmConfig` and `VmUpdateConfig`.
/// This is called only when `smt` is present in the JSON configuration.
fn deserialize_smt<'de, D, T>(d: D) -> std::result::Result<T, D::Error>
where
    D: de::Deserializer<'de>,
    T: Deserialize<'de> + PartialEq + From<bool>,
{
    let val = T::deserialize(d)?;

    // If this function was called it means that `smt` was specified in
    // the JSON. On aarch64 the only accepted value is `false` so throw an
    // error if `true` was specified.
    #[cfg(target_arch = "aarch64")]
    if val == T::from(true) {
        return Err(de::Error::invalid_value(
            de::Unexpected::Other("smt"),
            &"Enabling simultaneous multithreading is not supported on aarch64",
        ));
    }

    Ok(val)
}

/// Deserialization function for the `cpu_template` field in `VmConfig` and `VmUpdateConfig`.
/// This is called only when `cpu_template` is present in the JSON configuration.
fn deserialize_cpu_template<'de, D, T>(_d: D) -> std::result::Result<T, D::Error>
where
    D: de::Deserializer<'de>,
    T: Deserialize<'de>,
{
    // If this function was called it means that `cpu_template` was specified in
    // the JSON. Return an error since `cpu_template` is not supported on aarch64.
    #[cfg(target_arch = "aarch64")]
    return Err(de::Error::invalid_value(
        de::Unexpected::Enum,
        &"CPU templates are not supported on aarch64",
    ));

    #[cfg(target_arch = "x86_64")]
    T::deserialize(_d)
}

/// Template types available for configuring the CPU features that map
/// to EC2 instances.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, Versionize)]
pub enum CpuFeaturesTemplate {
    /// C3 Template.
    C3,
    /// T2 Template.
    T2,
    /// T2S Template.
    T2S,
    /// No CPU template is used.
    None,
    /// T2CL Template.
    T2CL,
    /// T2A Template.
    T2A,
}

/// Utility methods for handling CPU template types
impl CpuFeaturesTemplate {
    fn is_none(&self) -> bool {
        *self == CpuFeaturesTemplate::None
    }
}

impl fmt::Display for CpuFeaturesTemplate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CpuFeaturesTemplate::C3 => write!(f, "C3"),
            CpuFeaturesTemplate::T2 => write!(f, "T2"),
            CpuFeaturesTemplate::T2S => write!(f, "T2S"),
            CpuFeaturesTemplate::T2CL => write!(f, "T2CL"),
            CpuFeaturesTemplate::T2A => write!(f, "T2A"),
            CpuFeaturesTemplate::None => write!(f, "None"),
        }
    }
}

impl Default for CpuFeaturesTemplate {
    fn default() -> Self {
        CpuFeaturesTemplate::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_cpu_features_template() {
        assert_eq!(CpuFeaturesTemplate::C3.to_string(), String::from("C3"));
        assert_eq!(CpuFeaturesTemplate::T2.to_string(), String::from("T2"));
        assert_eq!(CpuFeaturesTemplate::T2S.to_string(), String::from("T2S"));
    }

    #[test]
    fn test_display_vm_config_error() {
        let expected_str = "The vCPU number is invalid! The vCPU number can only be 1 or an even \
                            number when SMT is enabled.";
        assert_eq!(VmConfigError::InvalidVcpuCount.to_string(), expected_str);

        let expected_str = "The memory size (MiB) is invalid.";
        assert_eq!(VmConfigError::InvalidMemorySize.to_string(), expected_str);
    }
}
