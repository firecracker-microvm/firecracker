// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{de, Deserialize, Serialize};
use std::fmt;

/// The default memory size of the VM, in MiB.
pub const DEFAULT_MEM_SIZE_MIB: usize = 128;
/// Firecracker aims to support small scale workloads only, so limit the maximum
/// vCPUs supported.
pub const MAX_SUPPORTED_VCPUS: u8 = 32;

/// Errors associated with configuring the microVM.
#[derive(Debug, PartialEq)]
pub enum VmConfigError {
    /// The memory size is smaller than the target size set in the balloon device configuration.
    IncompatibleBalloonSize,
    /// The memory size is invalid. The memory can only be an unsigned integer.
    InvalidMemorySize,
    /// The vcpu count is invalid. When hyperthreading is enabled, the `cpu_count` must be either
    /// 1 or an even number.
    InvalidVcpuCount,
    /// Could not get the config of the balloon device from the VM resources, even though a
    /// balloon device was previously installed.
    InvalidVmState,
}

impl fmt::Display for VmConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::VmConfigError::*;
        match *self {
            IncompatibleBalloonSize => write!(
                f,
                "The memory size (MiB) is smaller than the previously \
                 set balloon device target size.",
            ),
            InvalidMemorySize => write!(f, "The memory size (MiB) is invalid.",),
            InvalidVcpuCount => write!(
                f,
                "The vCPU number is invalid! The vCPU number can only \
                 be 1 or an even number when hyperthreading is enabled.",
            ),
            InvalidVmState => write!(
                f,
                "Could not get the configuration of the previously \
                 installed balloon device to validate the memory size.",
            ),
        }
    }
}

/// Strongly typed structure that represents the configuration of the
/// microvm.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VmConfig {
    /// Number of vcpu to start.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "validate_vcpu_num"
    )]
    pub vcpu_count: Option<u8>,
    /// The memory size in MiB.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_size_mib: Option<usize>,
    /// Enables or disabled hyperthreading.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ht_enabled: Option<bool>,
    /// A CPU template that it is used to filter the CPU features exposed to the guest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_template: Option<CpuFeaturesTemplate>,
    /// Enables or disables dirty page tracking. Enabling allows incremental snapshots.
    #[serde(default)]
    pub track_dirty_pages: bool,
}

impl Default for VmConfig {
    fn default() -> Self {
        VmConfig {
            vcpu_count: Some(1),
            mem_size_mib: Some(DEFAULT_MEM_SIZE_MIB),
            ht_enabled: Some(false),
            cpu_template: None,
            track_dirty_pages: false,
        }
    }
}

impl fmt::Display for VmConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let vcpu_count = self.vcpu_count.unwrap_or(1);
        let mem_size = self.mem_size_mib.unwrap_or(DEFAULT_MEM_SIZE_MIB);
        let ht_enabled = self.ht_enabled.unwrap_or(false);
        let cpu_template = self
            .cpu_template
            .map_or("Uninitialized".to_string(), |c| c.to_string());
        write!(
            f,
            "{{ \"vcpu_count\": {:?}, \"mem_size_mib\": {:?}, \"ht_enabled\": {:?}, \
             \"cpu_template\": {:?}, \"track_dirty_pages\": {:?} }}",
            vcpu_count, mem_size, ht_enabled, cpu_template, self.track_dirty_pages
        )
    }
}

fn validate_vcpu_num<'de, D>(d: D) -> std::result::Result<Option<u8>, D::Error>
where
    D: de::Deserializer<'de>,
{
    let val = Option::<u8>::deserialize(d)?;
    if let Some(ref value) = val {
        if *value > MAX_SUPPORTED_VCPUS {
            return Err(de::Error::invalid_value(
                de::Unexpected::Unsigned(u64::from(*value)),
                &"number of vCPUs exceeds the maximum limitation",
            ));
        }
    }
    Ok(val)
}

/// Template types available for configuring the CPU features that map
/// to EC2 instances.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub enum CpuFeaturesTemplate {
    /// C3 Template.
    C3,
    /// T2 Template.
    T2,
}

impl fmt::Display for CpuFeaturesTemplate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CpuFeaturesTemplate::C3 => write!(f, "C3"),
            CpuFeaturesTemplate::T2 => write!(f, "T2"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_cpu_features_template() {
        assert_eq!(CpuFeaturesTemplate::C3.to_string(), "C3".to_string());
        assert_eq!(CpuFeaturesTemplate::T2.to_string(), "T2".to_string());
    }

    #[test]
    fn test_display_vm_config_error() {
        let expected_str = "The vCPU number is invalid! The vCPU number can only \
                            be 1 or an even number when hyperthreading is enabled.";
        assert_eq!(VmConfigError::InvalidVcpuCount.to_string(), expected_str);

        let expected_str = "The memory size (MiB) is invalid.";
        assert_eq!(VmConfigError::InvalidMemorySize.to_string(), expected_str);
    }
}
