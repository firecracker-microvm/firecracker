// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::fmt::{Binary, Display};
use std::hash::Hash;
use std::ops::{BitAnd, Shl};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use vmm::builder::{build_microvm_for_boot, StartMicrovmError};
use vmm::resources::VmResources;
use vmm::seccomp_filters::get_empty_filters;
use vmm::vmm_config::instance_info::{InstanceInfo, VmState};
use vmm::{EventManager, Vmm, HTTP_MAX_PAYLOAD_SIZE};

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

pub const CPU_TEMPLATE_HELPER_VERSION: &str = env!("FIRECRACKER_VERSION");

/// Trait for key of `HashMap`-based modifier.
///
/// This is a wrapper trait of some traits required for a key of `HashMap` modifier.
pub trait ModifierMapKey: Eq + PartialEq + Hash + Display + Clone {}

/// Trait for value of `HashMap`-based modifier.
pub trait ModifierMapValue: Eq + PartialEq + Clone {
    // The data size of `Self::Type` varies depending on the target modifier.
    // * x86_64 CPUID: `u32`
    // * x86_64 MSR: `u64`
    // * aarch64 registers: `u128`
    //
    // These trait bounds are required for the following reasons:
    // * `PartialEq + Eq`: To compare `Self::Type` values (like `filter()` and `value()`).
    // * `BitAnd<Output = Self::Type>`: To use AND operation (like `filter() & value()`).
    // * `Binary`: To display in a bitwise format.
    // * `From<bool> + Shl<usize, Output = Self::Type>`: To construct bit masks in
    //   `to_diff_string()`.
    type Type: PartialEq
        + Eq
        + Copy
        + BitAnd<Output = Self::Type>
        + Binary
        + From<bool>
        + Shl<usize, Output = Self::Type>;

    // Return `filter` of arch-specific `RegisterValueFilter` in the size for the target.
    fn filter(&self) -> Self::Type;

    // Return `value` of arch-specific `RegisterValueFilter` in the size for the target.
    fn value(&self) -> Self::Type;

    // Generate a string to display difference of filtered values between CPU template and guest
    // CPU config.
    #[rustfmt::skip]
    fn to_diff_string(template: Self::Type, config: Self::Type) -> String {
        let nbits = std::mem::size_of::<Self::Type>() * 8;

        let mut diff = String::new();
        for i in (0..nbits).rev() {
            let mask = Self::Type::from(true) << i;
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
            width = nbits,
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Failed to create VmResources.
    #[error("Failed to create VmResources: {0}")]
    CreateVmResources(vmm::resources::Error),
    /// Failed to build microVM.
    #[error("Failed to build microVM: {0}")]
    BuildMicroVm(#[from] StartMicrovmError),
}

pub fn build_microvm_from_config(config: &str) -> Result<(Arc<Mutex<Vmm>>, VmResources), Error> {
    // Prepare resources from the given config file.
    let instance_info = InstanceInfo {
        id: "anonymous-instance".to_string(),
        state: VmState::NotStarted,
        vmm_version: CPU_TEMPLATE_HELPER_VERSION.to_string(),
        app_name: "cpu-template-helper".to_string(),
    };
    let vm_resources = VmResources::from_json(config, &instance_info, HTTP_MAX_PAYLOAD_SIZE, None)
        .map_err(Error::CreateVmResources)?;
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

    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct MockModifierMapValue {
        pub filter: u8,
        pub value: u8,
    }

    impl ModifierMapValue for MockModifierMapValue {
        type Type = u8;

        fn filter(&self) -> Self::Type {
            self.filter
        }

        fn value(&self) -> Self::Type {
            self.value
        }
    }

    macro_rules! mock_modifier {
        ($key:expr, ($filter:expr, $value:expr)) => {
            (
                MockModifierMapKey($key),
                MockModifierMapValue {
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
            Err(Error::CreateVmResources(_)) => (),
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
