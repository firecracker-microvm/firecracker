// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::fmt::{self, Debug};

use serde::{de, Deserialize, Serialize};

use crate::cpu_config::templates::{CpuTemplateType, CustomCpuTemplate, StaticCpuTemplate};

/// The default memory size of the VM, in MiB.
pub const DEFAULT_MEM_SIZE_MIB: usize = 128;
/// Firecracker aims to support small scale workloads only, so limit the maximum
/// vCPUs supported.
pub const MAX_SUPPORTED_VCPUS: u8 = 32;

/// Errors associated with configuring the microVM.
#[derive(Debug, thiserror::Error, displaydoc::Display, PartialEq, Eq)]
pub enum VmConfigError {
    /// The memory size (MiB) is smaller than the previously set balloon device target size.
    IncompatibleBalloonSize,
    /// The memory size (MiB) is invalid.
    InvalidMemorySize,
    #[rustfmt::skip]
    #[doc = "The vCPU number is invalid! The vCPU number can only be 1 or an even number when SMT is enabled."]
    InvalidVcpuCount,
    #[rustfmt::skip]
    #[doc = "Could not get the configuration of the previously installed balloon device to validate the memory size."]
    InvalidVmState,
}

/// Struct used in PUT `/machine-config` API call.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MachineConfig {
    /// Number of vcpu to start.
    #[serde(deserialize_with = "deserialize_vcpu_num")]
    pub vcpu_count: u8,
    /// The memory size in MiB.
    pub mem_size_mib: usize,
    /// Enables or disabled SMT.
    #[serde(default, deserialize_with = "deserialize_smt")]
    pub smt: bool,
    /// A CPU template that it is used to filter the CPU features exposed to the guest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_template: Option<StaticCpuTemplate>,
    /// Enables or disables dirty page tracking. Enabling allows incremental snapshots.
    #[serde(default)]
    pub track_dirty_pages: bool,
}

impl Default for MachineConfig {
    fn default() -> Self {
        Self::from(&VmConfig::default())
    }
}

impl fmt::Display for MachineConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{{ \"vcpu_count\": {:?}, \"mem_size_mib\": {:?}, \"smt\": {:?}, \"cpu_template\": \
             {:?}, \"track_dirty_pages\": {:?} }}",
            self.vcpu_count, self.mem_size_mib, self.smt, self.cpu_template, self.track_dirty_pages
        )
    }
}

/// Struct used in PATCH `/machine-config` API call.
/// Used to update `VmConfig` in `VmResources`.
/// This struct mirrors all the fields in `MachineConfig`.
/// All fields are optional, but at least one needs to be specified.
/// If a field is `Some(value)` then we assume an update is requested
/// for that field.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MachineConfigUpdate {
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_template: Option<StaticCpuTemplate>,
    /// Enables or disables dirty page tracking. Enabling allows incremental snapshots.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub track_dirty_pages: Option<bool>,
}

impl MachineConfigUpdate {
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

impl From<MachineConfig> for MachineConfigUpdate {
    fn from(cfg: MachineConfig) -> Self {
        MachineConfigUpdate {
            vcpu_count: Some(cfg.vcpu_count),
            mem_size_mib: Some(cfg.mem_size_mib),
            smt: Some(cfg.smt),
            cpu_template: cfg.cpu_template,
            track_dirty_pages: Some(cfg.track_dirty_pages),
        }
    }
}

/// Configuration of the microvm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmConfig {
    /// Number of vcpu to start.
    pub vcpu_count: u8,
    /// The memory size in MiB.
    pub mem_size_mib: usize,
    /// Enables or disabled SMT.
    pub smt: bool,
    /// A CPU template that it is used to filter the CPU features exposed to the guest.
    pub cpu_template: Option<CpuTemplateType>,
    /// Enables or disables dirty page tracking. Enabling allows incremental snapshots.
    pub track_dirty_pages: bool,
}

impl VmConfig {
    /// Sets cpu tempalte field to `CpuTemplateType::Custom(cpu_template)`.
    pub fn set_custom_cpu_template(&mut self, cpu_template: CustomCpuTemplate) {
        self.cpu_template = Some(CpuTemplateType::Custom(cpu_template));
    }

    /// Updates `VmConfig` with `MachineConfigUpdate`.
    /// Mapping for cpu tempalte update:
    /// StaticCpuTemplate::None -> None
    /// StaticCpuTemplate::Other -> Some(CustomCpuTemplate::Static(Other))
    pub fn update(&mut self, update: &MachineConfigUpdate) -> Result<(), VmConfigError> {
        let vcpu_count = update.vcpu_count.unwrap_or(self.vcpu_count);

        let smt = update.smt.unwrap_or(self.smt);

        if vcpu_count == 0 {
            return Err(VmConfigError::InvalidVcpuCount);
        }

        // If SMT is enabled or is to be enabled in this call
        // only allow vcpu count to be 1 or even.
        if smt && vcpu_count > 1 && vcpu_count % 2 == 1 {
            return Err(VmConfigError::InvalidVcpuCount);
        }

        self.vcpu_count = vcpu_count;
        self.smt = smt;

        let mem_size_mib = update.mem_size_mib.unwrap_or(self.mem_size_mib);

        if mem_size_mib == 0 {
            return Err(VmConfigError::InvalidMemorySize);
        }

        self.mem_size_mib = mem_size_mib;

        if let Some(cpu_template) = update.cpu_template {
            self.cpu_template = match cpu_template {
                StaticCpuTemplate::None => None,
                other => Some(CpuTemplateType::Static(other)),
            };
        }

        if let Some(track_dirty_pages) = update.track_dirty_pages {
            self.track_dirty_pages = track_dirty_pages;
        }

        Ok(())
    }
}

impl Default for VmConfig {
    fn default() -> Self {
        Self {
            vcpu_count: 1,
            mem_size_mib: DEFAULT_MEM_SIZE_MIB,
            smt: false,
            cpu_template: None,
            track_dirty_pages: false,
        }
    }
}

impl From<&VmConfig> for MachineConfig {
    fn from(value: &VmConfig) -> Self {
        Self {
            vcpu_count: value.vcpu_count,
            mem_size_mib: value.mem_size_mib,
            smt: value.smt,
            cpu_template: value.cpu_template.as_ref().map(|template| template.into()),
            track_dirty_pages: value.track_dirty_pages,
        }
    }
}

/// Deserialization function for the `vcpu_num` field in `MachineConfig` and `MachineConfigUpdate`.
/// This is called only when `vcpu_num` is present in the JSON configuration.
/// `T` can be either `u8` or `Option<u8>` which both support ordering if `vcpu_num` is
/// present in the JSON.
fn deserialize_vcpu_num<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: de::Deserializer<'de>,
    T: Deserialize<'de> + PartialOrd + From<u8> + Debug,
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

/// Deserialization function for the `smt` field in `MachineConfig` and `MachineConfigUpdate`.
/// This is called only when `smt` is present in the JSON configuration.
fn deserialize_smt<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: de::Deserializer<'de>,
    T: Deserialize<'de> + PartialEq + From<bool> + Debug,
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
