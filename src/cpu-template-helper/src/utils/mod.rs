// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::fmt::Display;
use std::fs::read_to_string;
use std::hash::Hash;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use vmm::builder::{build_microvm_for_boot, StartMicrovmError};
use vmm::cpu_config::templates::{CustomCpuTemplate, Numeric};
use vmm::resources::VmResources;
use vmm::seccomp_filters::get_empty_filters;
use vmm::vmm_config::instance_info::{InstanceInfo, VmState};
use vmm::{EventManager, Vmm, HTTP_MAX_PAYLOAD_SIZE};
use vmm_sys_util::tempfile::TempFile;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

pub const CPU_TEMPLATE_HELPER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Trait for key of `HashMap`-based modifier.
///
/// This is a wrapper trait of some traits required for a key of `HashMap` modifier.
pub trait ModifierMapKey: Eq + PartialEq + Hash + Display + Clone {}

pub trait DiffString<V> {
    // Generate a string to display difference of filtered values between CPU template and guest
    // CPU config.
    #[rustfmt::skip]
    fn to_diff_string(template: V, config: V) -> String;
}

impl<V: Numeric> DiffString<V> for V {
    // Generate a string to display difference of filtered values between CPU template and guest
    // CPU config.
    #[rustfmt::skip]
    fn to_diff_string(template: V, config: V) -> String {
        let mut diff = String::new();
        for i in (0..V::BITS).rev() {
            let mask = V::one() << i;
            let template_bit = template & mask;
            let config_bit = config & mask;
            diff.push(match template_bit == config_bit {
                true => ' ',
                false => '^',
            });
        }

        format!(
            "* CPU template     : 0b{template:0width$b}\n\
             * CPU configuration: 0b{config:0width$b}\n\
             * Diff             :   {diff}",
            width = V::BITS as usize,
        )
    }
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum UtilsError {
    /// Failed to create VmResources: {0}
    CreateVmResources(vmm::resources::ResourcesError),
    /// Failed to build microVM: {0}
    BuildMicroVm(#[from] StartMicrovmError),
    /// Failed to create temporary file: {0}
    CreateTempFile(#[from] vmm_sys_util::errno::Error),
    /// Failed to operate file: {0}
    FileIo(#[from] std::io::Error),
    /// Failed to serialize/deserialize JSON file: {0}
    Serde(#[from] serde_json::Error),
}

pub fn load_cpu_template(path: &PathBuf) -> Result<CustomCpuTemplate, UtilsError> {
    let template_json = read_to_string(path)?;
    let template = serde_json::from_str(&template_json)?;
    Ok(template)
}

// Utility function to prepare scratch kernel image and rootfs and build mock Firecracker config.
fn build_mock_config() -> Result<(TempFile, TempFile, String), UtilsError> {
    let kernel = TempFile::new()?;
    kernel
        .as_file()
        .write_all(include_bytes!("mock_kernel/kernel.bin"))?;
    let rootfs = TempFile::new()?;
    let config = format!(
        r#"{{
            "boot-source": {{
                "kernel_image_path": "{}"
            }},
            "drives": [
                {{
                    "drive_id": "rootfs",
                    "is_root_device": true,
                    "path_on_host": "{}"
                }}
            ]
        }}"#,
        // Temporary file path consists of alphanumerics.
        kernel.as_path().to_str().unwrap(),
        rootfs.as_path().to_str().unwrap(),
    );
    Ok((kernel, rootfs, config))
}

pub fn build_microvm_from_config(
    config: Option<String>,
    template: Option<CustomCpuTemplate>,
) -> Result<(Arc<Mutex<Vmm>>, VmResources), UtilsError> {
    // Prepare resources from the given config file.
    let (_kernel, _rootfs, config) = match config {
        Some(config) => (None, None, config),
        None => {
            let (kernel, rootfs, config) = build_mock_config()?;
            (Some(kernel), Some(rootfs), config)
        }
    };
    let instance_info = InstanceInfo {
        id: "anonymous-instance".to_string(),
        state: VmState::NotStarted,
        vmm_version: CPU_TEMPLATE_HELPER_VERSION.to_string(),
        app_name: "cpu-template-helper".to_string(),
    };
    let mut vm_resources =
        VmResources::from_json(&config, &instance_info, HTTP_MAX_PAYLOAD_SIZE, None)
            .map_err(UtilsError::CreateVmResources)?;
    if let Some(template) = template {
        vm_resources.set_custom_cpu_template(template);
    }
    let mut event_manager = EventManager::new().unwrap();
    let seccomp_filters = get_empty_filters();

    // Build a microVM.
    let vmm = build_microvm_for_boot(
        &instance_info,
        &vm_resources,
        &mut event_manager,
        &seccomp_filters,
    )?;

    Ok((vmm, vm_resources))
}

pub fn add_suffix(path: &Path, suffix: &str) -> PathBuf {
    // Extract the part of the filename before the extension.
    let mut new_file_name = OsString::from(path.file_stem().unwrap());

    // Push the suffix and the extension.
    new_file_name.push(suffix);
    if let Some(ext) = path.extension() {
        new_file_name.push(".");
        new_file_name.push(ext);
    }

    // Swap the file name.
    path.with_file_name(new_file_name)
}

#[cfg(test)]
pub mod tests {
    use std::fmt::Display;

    use vmm::resources::VmmConfig;

    use super::*;

    const SUFFIX: &str = "_suffix";

    #[derive(Debug, PartialEq, Eq, Hash, Clone)]
    pub struct MockModifierMapKey(pub u8);

    impl ModifierMapKey for MockModifierMapKey {}
    impl Display for MockModifierMapKey {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "ID={:#x}", self.0)
        }
    }

    macro_rules! mock_modifier {
        ($key:expr, $value:expr) => {
            (
                MockModifierMapKey($key),
                RegisterValueFilter::<u8> {
                    filter: u8::MAX,
                    value: $value,
                },
            )
        };
        ($key:expr, $value:expr, $filter:expr) => {
            (
                MockModifierMapKey($key),
                RegisterValueFilter::<u8> {
                    filter: $filter,
                    value: $value,
                },
            )
        };
    }

    pub(crate) use mock_modifier;

    #[test]
    fn test_build_mock_config() {
        let kernel_path;
        let rootfs_path;
        {
            let (kernel, rootfs, config) = build_mock_config().unwrap();
            kernel_path = kernel.as_path().to_path_buf();
            rootfs_path = rootfs.as_path().to_path_buf();

            // Ensure the kernel exists and its content is written.
            assert!(kernel.as_file().metadata().unwrap().len() > 0);
            // Ensure the rootfs exists and it is empty.
            assert_eq!(rootfs.as_file().metadata().unwrap().len(), 0);
            // Ensure the generated config is valid as `VmmConfig`.
            serde_json::from_str::<VmmConfig>(&config).unwrap();
        }
        // Ensure the temporary mock resources are deleted.
        assert!(!kernel_path.exists());
        assert!(!rootfs_path.exists());
    }

    #[test]
    fn test_build_microvm() {
        build_microvm_from_config(None, None).unwrap();
    }

    #[test]
    fn test_add_suffix_filename_only() {
        let path = PathBuf::from("file.ext");
        let expected = PathBuf::from(format!("file{SUFFIX}.ext"));
        assert_eq!(add_suffix(&path, SUFFIX), expected);
    }

    #[test]
    fn test_add_suffix_filename_without_ext() {
        let path = PathBuf::from("file_no_ext");
        let expected = PathBuf::from(format!("file_no_ext{SUFFIX}"));
        assert_eq!(add_suffix(&path, SUFFIX), expected);
    }

    #[test]
    fn test_add_suffix_rel_path() {
        let path = PathBuf::from("relative/path/to/file.ext");
        let expected = PathBuf::from(format!("relative/path/to/file{SUFFIX}.ext"));
        assert_eq!(add_suffix(&path, SUFFIX), expected);
    }

    #[test]
    fn test_add_suffix_abs_path() {
        let path = PathBuf::from("/absolute/path/to/file.ext");
        let expected = PathBuf::from(format!("/absolute/path/to/file{SUFFIX}.ext"));
        assert_eq!(add_suffix(&path, SUFFIX), expected);
    }
}
