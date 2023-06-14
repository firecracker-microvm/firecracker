// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::fs::File;
use std::io::{BufReader, Read};

use seccompiler::{deserialize_binary, BpfThreadMap, DeserializationError};
use vmm::seccomp_filters::get_empty_filters;

const THREAD_CATEGORIES: [&str; 3] = ["vmm", "api", "vcpu"];

// This byte limit is passed to `bincode` to guard against a potential memory
// allocation DOS caused by binary filters that are too large.
// This limit can be safely determined since the maximum length of a BPF
// filter is 4096 instructions and Firecracker has a finite number of threads.
const DESERIALIZATION_BYTES_LIMIT: Option<u64> = Some(100_000);

/// Error retrieving seccomp filters.
#[derive(Debug, thiserror::Error)]
pub enum FilterError {
    /// Filter deserialitaion error.
    #[error("Filter deserialization failed: {0}")]
    Deserialization(DeserializationError),
    /// Invalid thread categories.
    #[error("Invalid thread categories: {0}")]
    ThreadCategories(String),
    /// Missing Thread Category.
    #[error("Missing thread category: {0}")]
    MissingThreadCategory(String),
    /// File open error.
    #[error("Filter file open error: {0}")]
    FileOpen(std::io::Error),
}

/// Seccomp filter configuration.
pub enum SeccompConfig {
    /// Seccomp filtering disabled.
    None,
    /// Default, advanced filters.
    Advanced,
    /// Custom, user-provided filters.
    Custom(Box<dyn std::io::Read>),
}

impl SeccompConfig {
    /// Given the relevant command line args, return the appropriate config type.
    pub fn from_args(
        no_seccomp: bool,
        seccomp_filter: Option<&String>,
    ) -> Result<Self, FilterError> {
        if no_seccomp {
            Ok(SeccompConfig::None)
        } else {
            match seccomp_filter {
                Some(path) => Ok(SeccompConfig::Custom(Box::new(
                    File::open(path).map_err(FilterError::FileOpen)?,
                ))),
                None => Ok(SeccompConfig::Advanced),
            }
        }
    }
}

/// Retrieve the appropriate filters, based on the SeccompConfig.
pub fn get_filters(config: SeccompConfig) -> Result<BpfThreadMap, FilterError> {
    match config {
        SeccompConfig::None => Ok(get_empty_filters()),
        SeccompConfig::Advanced => get_default_filters(),
        SeccompConfig::Custom(reader) => get_custom_filters(reader),
    }
}

/// Retrieve the default filters containing the syscall rules required by `Firecracker`
/// to function. The binary file is generated via the `build.rs` script of this crate.
fn get_default_filters() -> Result<BpfThreadMap, FilterError> {
    // Retrieve, at compile-time, the serialized binary filter generated with seccompiler.
    let bytes: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/seccomp_filter.bpf"));
    let map = deserialize_binary(bytes, DESERIALIZATION_BYTES_LIMIT)
        .map_err(FilterError::Deserialization)?;
    filter_thread_categories(map)
}

/// Retrieve custom seccomp filters.
fn get_custom_filters<R: Read>(reader: R) -> Result<BpfThreadMap, FilterError> {
    let map = deserialize_binary(BufReader::new(reader), DESERIALIZATION_BYTES_LIMIT)
        .map_err(FilterError::Deserialization)?;
    filter_thread_categories(map)
}

/// Return an error if the BpfThreadMap contains invalid thread categories.
fn filter_thread_categories(map: BpfThreadMap) -> Result<BpfThreadMap, FilterError> {
    let (filters, invalid_filters): (BpfThreadMap, BpfThreadMap) = map
        .into_iter()
        .partition(|(k, _)| THREAD_CATEGORIES.contains(&k.as_str()));
    if !invalid_filters.is_empty() {
        // build the error message
        let mut thread_categories_string =
            invalid_filters
                .keys()
                .fold("".to_string(), |mut acc, elem| {
                    acc.push_str(elem);
                    acc.push(',');
                    acc
                });
        thread_categories_string.pop();
        return Err(FilterError::ThreadCategories(thread_categories_string));
    }

    for &category in THREAD_CATEGORIES.iter() {
        let category_string = category.to_string();
        if !filters.contains_key(&category_string) {
            return Err(FilterError::MissingThreadCategory(category_string));
        }
    }

    Ok(filters)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use seccompiler::BpfThreadMap;
    use utils::tempfile::TempFile;

    use super::*;

    #[test]
    fn test_get_filters() {
        let mut filters = get_filters(SeccompConfig::Advanced).unwrap();
        assert_eq!(filters.len(), 3);
        assert!(filters.remove("vmm").is_some());
        assert!(filters.remove("api").is_some());
        assert!(filters.remove("vcpu").is_some());

        let mut filters = get_filters(SeccompConfig::None).unwrap();
        assert_eq!(filters.len(), 3);
        assert_eq!(filters.remove("vmm").unwrap().len(), 0);
        assert_eq!(filters.remove("api").unwrap().len(), 0);
        assert_eq!(filters.remove("vcpu").unwrap().len(), 0);

        let file = TempFile::new().unwrap().into_file();

        assert!(get_filters(SeccompConfig::Custom(Box::new(file))).is_err());
    }

    #[test]
    fn test_filter_thread_categories() {
        // correct categories
        let mut map = BpfThreadMap::new();
        map.insert("vcpu".to_string(), Arc::new(vec![]));
        map.insert("vmm".to_string(), Arc::new(vec![]));
        map.insert("api".to_string(), Arc::new(vec![]));

        assert_eq!(filter_thread_categories(map).unwrap().len(), 3);

        // invalid categories
        let mut map = BpfThreadMap::new();
        map.insert("vcpu".to_string(), Arc::new(vec![]));
        map.insert("vmm".to_string(), Arc::new(vec![]));
        map.insert("thread1".to_string(), Arc::new(vec![]));
        map.insert("thread2".to_string(), Arc::new(vec![]));

        match filter_thread_categories(map).unwrap_err() {
            FilterError::ThreadCategories(err) => {
                assert!(err == "thread2,thread1" || err == "thread1,thread2")
            }
            _ => panic!("Expected ThreadCategories error."),
        }

        // missing category
        let mut map = BpfThreadMap::new();
        map.insert("vcpu".to_string(), Arc::new(vec![]));
        map.insert("vmm".to_string(), Arc::new(vec![]));

        match filter_thread_categories(map).unwrap_err() {
            FilterError::MissingThreadCategory(name) => assert_eq!(name, "api"),
            _ => panic!("Expected MissingThreadCategory error."),
        }
    }

    #[test]
    fn test_seccomp_config() {
        assert!(matches!(
            SeccompConfig::from_args(true, None),
            Ok(SeccompConfig::None)
        ));

        assert!(matches!(
            SeccompConfig::from_args(false, Some(&"/dev/null".to_string())),
            Ok(SeccompConfig::Custom(_))
        ));

        assert!(matches!(
            SeccompConfig::from_args(false, Some(&"invalid_path".to_string())),
            Err(FilterError::FileOpen(_))
        ));

        // test the default case, no parametes -> default advanced.
        assert!(matches!(
            SeccompConfig::from_args(false, None),
            Ok(SeccompConfig::Advanced)
        ));
    }
}
