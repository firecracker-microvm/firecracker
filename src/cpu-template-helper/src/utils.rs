// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::path::{Path, PathBuf};

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

#[cfg(target_arch = "aarch64")]
pub mod aarch64 {
    macro_rules! reg_modifier {
        ($addr:expr, $value:expr) => {
            RegisterModifier {
                addr: $addr,
                bitmap: RegisterValueFilter {
                    filter: u128::MAX,
                    value: $value,
                },
            }
        };
    }

    pub(crate) use reg_modifier;
}

#[cfg(target_arch = "x86_64")]
pub mod x86_64 {
    macro_rules! cpuid_reg_modifier {
        ($register:expr, $value:expr) => {
            CpuidRegisterModifier {
                register: $register,
                bitmap: RegisterValueFilter {
                    filter: u32::MAX.into(),
                    value: $value,
                },
            }
        };
    }

    macro_rules! cpuid_leaf_modifier {
        ($leaf:expr, $subleaf:expr, $flags:expr, $reg_modifiers:expr) => {
            CpuidLeafModifier {
                leaf: $leaf,
                subleaf: $subleaf,
                flags: $flags,
                modifiers: $reg_modifiers,
            }
        };
    }

    macro_rules! msr_modifier {
        ($addr:expr, $value:expr) => {
            RegisterModifier {
                addr: $addr,
                bitmap: RegisterValueFilter {
                    filter: u64::MAX,
                    value: $value,
                },
            }
        };
    }

    pub(crate) use {cpuid_leaf_modifier, cpuid_reg_modifier, msr_modifier};
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUFFIX: &str = "_suffix";

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
