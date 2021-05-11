// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use seccompiler::{deserialize_binary, BpfThreadMap, DeserializationError, InstallationError};

use std::fmt;
use std::fs::File;
use std::io::{BufReader, Read};
use std::sync::Arc;

const THREAD_CATEGORIES: [&str; 3] = ["vmm", "api", "vcpu"];

// This byte limit is passed to `bincode` to guard against a potential memory
// allocation DOS caused by binary filters that are too large.
// This limit can be safely determined since the maximum length of a BPF
// filter is 4096 instructions and Firecracker has a finite number of threads.
const DESERIALIZATION_BYTES_LIMIT: Option<u64> = Some(100_000);

/// Error retrieving seccomp filters.
#[derive(fmt::Debug)]
pub enum FilterError {
    /// Invalid SeccompConfig.
    SeccompConfig(String),
    /// Filter deserialitaion error.
    Deserialization(DeserializationError),
    /// Invalid thread categories.
    ThreadCategories(String),
    /// Missing Thread Category.
    MissingThreadCategory(String),
    /// Filter installation error.
    Install(InstallationError),
    /// File open error.
    FileOpen(std::io::Error),
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::FilterError::*;

        match *self {
            SeccompConfig(ref message) => {
                write!(f, "Invalid seccomp argument configuration: {}", message)
            }
            Deserialization(ref err) => write!(f, "Filter deserialization failed: {}", err),
            ThreadCategories(ref categories) => {
                write!(f, "Invalid thread categories: {}", categories)
            }
            MissingThreadCategory(ref category) => {
                write!(f, "Missing thread category: {}", category)
            }
            Install(ref err) => write!(f, "Filter installation error: {}", err),
            FileOpen(ref err) => write!(f, "Filter file open error: {}", err),
        }
    }
}

/// Seccomp filter configuration.
pub enum SeccompConfig {
    /// Seccomp filtering disabled.
    None,
    /// Basic filtering, matching only on syscall numbers.
    Basic,
    /// Default, advanced filters.
    /// Checks both syscall numbers and argument values (where applicable).
    Advanced,
    /// Custom, user-provided filters.
    Custom(Box<dyn std::io::Read>),
}

impl SeccompConfig {
    /// Given the relevant command line args, return the appropriate config type.
    pub fn from_args(
        seccomp_level: Option<&String>,
        no_seccomp: bool,
        seccomp_filter: Option<&String>,
    ) -> Result<Self, FilterError> {
        // The argument parser is configured to forbid usages of `--seccomp-filter` or `--no-seccomp`
        // together with `--seccomp-level`, so we do not have to check for it.
        match seccomp_level {
            Some(value) => match &value[..] {
                "0" => Ok(SeccompConfig::None),
                "1" => Ok(SeccompConfig::Basic),
                "2" => Ok(SeccompConfig::Advanced),
                _ => Err(FilterError::SeccompConfig(
                    "Invalid value for --seccomp-level.".to_string(),
                )),
            },
            None => match no_seccomp {
                true => Ok(SeccompConfig::None),
                false => match seccomp_filter {
                    Some(path) => Ok(SeccompConfig::Custom(Box::new(
                        File::open(&path).map_err(FilterError::FileOpen)?,
                    ))),
                    None => Ok(SeccompConfig::Advanced),
                },
            },
        }
    }
}

/// Retrieve the appropriate filters, based on the SeccompConfig.
pub fn get_filters(config: SeccompConfig) -> Result<BpfThreadMap, FilterError> {
    match config {
        SeccompConfig::None => Ok(get_empty_filters()),
        SeccompConfig::Basic => get_default_filters(true),
        SeccompConfig::Advanced => get_default_filters(false),
        SeccompConfig::Custom(reader) => get_custom_filters(reader),
    }
}

/// Retrieve the default filters containing the syscall rules required by `Firecracker`
/// to function. The binary file is generated via the `build.rs` script of this crate.
fn get_default_filters(basic: bool) -> Result<BpfThreadMap, FilterError> {
    // Retrieve, at compile-time, the serialized binary filter generated with seccompiler.
    let bytes: &[u8] = match basic {
        true => include_bytes!(concat!(env!("OUT_DIR"), "/basic_seccomp_filter.bpf")),
        false => include_bytes!(concat!(env!("OUT_DIR"), "/seccomp_filter.bpf")),
    };
    let map = deserialize_binary(bytes, DESERIALIZATION_BYTES_LIMIT)
        .map_err(FilterError::Deserialization)?;
    filter_thread_categories(map)
}

/// Retrieve empty seccomp filters.
fn get_empty_filters() -> BpfThreadMap {
    let mut map = BpfThreadMap::new();
    map.insert("vmm".to_string(), Arc::new(vec![]));
    map.insert("api".to_string(), Arc::new(vec![]));
    map.insert("vcpu".to_string(), Arc::new(vec![]));
    map
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
    use super::*;
    use seccompiler::BpfThreadMap;
    use utils::tempfile::TempFile;

    #[test]
    fn test_get_filters() {
        let mut filters = get_filters(SeccompConfig::Basic).unwrap();
        assert_eq!(filters.len(), 3);
        assert!(filters.remove("vmm").is_some());
        assert!(filters.remove("api").is_some());
        assert!(filters.remove("vcpu").is_some());

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
        // test deprecated seccomp-level config.
        assert!(matches!(
            SeccompConfig::from_args(Some(&"0".to_string()), false, None),
            Ok(SeccompConfig::None)
        ));

        assert!(matches!(
            SeccompConfig::from_args(Some(&"1".to_string()), false, None),
            Ok(SeccompConfig::Basic)
        ));

        assert!(matches!(
            SeccompConfig::from_args(Some(&"2".to_string()), false, None),
            Ok(SeccompConfig::Advanced)
        ));

        assert!(matches!(
            SeccompConfig::from_args(Some(&"3".to_string()), false, None),
            Err(FilterError::SeccompConfig(_))
        ));

        // test new seccomp parameters config.
        assert!(matches!(
            SeccompConfig::from_args(None, true, None),
            Ok(SeccompConfig::None)
        ));

        assert!(matches!(
            SeccompConfig::from_args(None, false, Some(&"/dev/null".to_string())),
            Ok(SeccompConfig::Custom(_))
        ));

        assert!(matches!(
            SeccompConfig::from_args(None, false, Some(&"invalid_path".to_string())),
            Err(FilterError::FileOpen(_))
        ));

        // test the default case, no parametes -> default advanced.
        assert!(matches!(
            SeccompConfig::from_args(None, false, None),
            Ok(SeccompConfig::Advanced)
        ));
    }
}
