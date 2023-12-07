// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::fmt::Display;
use std::hash::Hash;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use vmm::builder::{build_microvm_for_boot, StartMicrovmError};
use vmm::cpu_config::templates::Numeric;
use vmm::resources::VmResources;
use vmm::seccomp_filters::get_empty_filters;
use vmm::vmm_config::instance_info::{InstanceInfo, VmState};
use vmm::{EventManager, Vmm, HTTP_MAX_PAYLOAD_SIZE};

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
}

pub fn build_microvm_from_config(
    config: &str,
) -> Result<(Arc<Mutex<Vmm>>, VmResources), UtilsError> {
    // Prepare resources from the given config file.
    let instance_info = InstanceInfo {
        id: "anonymous-instance".to_string(),
        state: VmState::NotStarted,
        vmm_version: CPU_TEMPLATE_HELPER_VERSION.to_string(),
        app_name: "cpu-template-helper".to_string(),
    };
    let vm_resources = VmResources::from_json(config, &instance_info, HTTP_MAX_PAYLOAD_SIZE, None)
        .map_err(UtilsError::CreateVmResources)?;
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

    use utils::tempfile::TempFile;
    use vmm::utilities::mock_resources::kernel_image_path;

    use super::*;
    use crate::tests::generate_config;

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
    fn test_build_microvm_from_valid_config() {
        let kernel_image_path = kernel_image_path(None);
        let rootfs_file = TempFile::new().unwrap();
        let valid_config =
            generate_config(&kernel_image_path, rootfs_file.as_path().to_str().unwrap());

        build_microvm_from_config(&valid_config).unwrap();
    }

    #[test]
    fn test_build_microvm_from_invalid_config() {
        let rootfs_file = TempFile::new().unwrap();
        let invalid_config = generate_config(
            "/invalid_kernel_image_path",
            rootfs_file.as_path().to_str().unwrap(),
        );

        match build_microvm_from_config(&invalid_config) {
            Ok(_) => panic!("Should fail with `No such file or directory`."),
            Err(UtilsError::CreateVmResources(_)) => (),
            Err(err) => panic!("Unexpected error: {err}"),
        }
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
