// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::io::Read;

pub use utils::seccomp::{SeccompFeatures, UnknownSeccompFeature};

// This byte limit is passed to `bitcode` to guard against a potential memory
// allocation DOS caused by binary filters that are too large.
// This limit can be safely determined since the maximum length of a BPF
// filter is 4096 instructions and Firecracker has a finite number of threads.
const DESERIALIZATION_BYTES_LIMIT: usize = 100_000;

/// Each BPF instruction is 8 bytes long and 4 byte aligned.
/// This alignment needs to be satisfied in order for a BPF code to be accepted
/// by the syscalls. Using u64 here is is safe as it has same size and even bigger alignment.
pub type BpfInstruction = u64;

/// Program made up of a sequence of BPF instructions.
pub type BpfProgram = Vec<BpfInstruction>;

/// Reference to program made up of a sequence of BPF instructions.
pub type BpfProgramRef<'a> = &'a [BpfInstruction];

/// Part of the seccomp filter of a thread category.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FilterPart {
    /// Features that enable this part, any one of them is sufficient. A part without features is
    /// always included.
    features: SeccompFeatures,
    /// BPF code. Every part but the last falls through to the next one when none of its rules
    /// match the syscall being filtered.
    code: BpfProgram,
}

/// The seccomp filter of one thread category, as compiled by seccompiler: a sequence of parts that
/// [`SeccompFilter::compose`] assembles into the program that gets installed on a thread.
///
/// A filter without feature-gated rules is a single complete program. Otherwise the first part
/// holds the rules that are always needed and falls through instead of returning the default
/// action, the feature-gated fragments follow, and an epilogue returns the default action.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeccompFilter(Vec<FilterPart>);

impl SeccompFilter {
    /// Assemble the program for a microVM with `enabled` features: the parts without features
    /// and the ones with at least one enabled feature, in order.
    pub fn compose(&self, enabled: SeccompFeatures) -> BpfProgram {
        self.0
            .iter()
            .filter(|part| part.features.is_empty() || part.features.intersects(enabled))
            .flat_map(|part| part.code.iter().copied())
            .collect()
    }
}

/// Type that associates a thread category to its seccomp filter.
pub type BpfThreadMap = HashMap<String, SeccompFilter>;

/// Binary filter deserialization errors.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum DeserializationError {
    /// Failed to read input: {0}
    InputRead(std::io::Error),
    /// Input size {0} exceeds limit of {1} bytes
    SizeLimitExceeded(usize, usize),
    /// Bitcode deserialization failed: {0}
    Bitcode(#[from] bitcode::Error),
}

/// Retrieve empty seccomp filters.
pub fn get_empty_filters() -> BpfThreadMap {
    let mut map = BpfThreadMap::new();
    map.insert("vmm".to_string(), SeccompFilter::default());
    map.insert("api".to_string(), SeccompFilter::default());
    map.insert("vcpu".to_string(), SeccompFilter::default());
    map
}

/// Deserialize binary with bpf filters
pub fn deserialize_binary<R: Read>(reader: R) -> Result<BpfThreadMap, DeserializationError> {
    // Check size limit before reading the full file to prevent DOS attacks
    let mut buf = Vec::new();
    let bytes_read = reader
        .take((DESERIALIZATION_BYTES_LIMIT + 1) as u64)
        .read_to_end(&mut buf)
        .map_err(DeserializationError::InputRead)?;

    if bytes_read > DESERIALIZATION_BYTES_LIMIT {
        return Err(DeserializationError::SizeLimitExceeded(
            bytes_read,
            DESERIALIZATION_BYTES_LIMIT,
        ));
    }

    let result: HashMap<String, BpfProgram> = bitcode::deserialize(&buf)?;

    Ok(result
        .into_iter()
        .map(|(k, code)| {
            let features = SeccompFeatures::empty();
            (
                k.to_lowercase(),
                SeccompFilter(vec![FilterPart { features, code }]),
            )
        })
        .collect())
}

/// Filter installation errors.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum InstallationError {
    /// Filter length exceeds the maximum size of {BPF_MAX_LEN:} instructions
    FilterTooLarge,
    /// prctl` syscall failed with error code: {0}
    Prctl(std::io::Error),
}

/// The maximum seccomp-BPF program length allowed by the linux kernel.
pub const BPF_MAX_LEN: usize = 4096;

/// BPF structure definition for filter array.
/// See /usr/include/linux/filter.h .
#[repr(C)]
#[derive(Debug)]
struct SockFprog {
    len: u16,
    filter: *const BpfInstruction,
}

/// Apply bpf filter.
pub fn apply_filter(bpf_filter: BpfProgramRef) -> Result<(), InstallationError> {
    // If the program is empty, don't install the filter.
    if bpf_filter.is_empty() {
        return Ok(());
    }

    // If the program length is greater than the limit allowed by the kernel,
    // fail quickly. Otherwise, `prctl` will give a more cryptic error code.
    if BPF_MAX_LEN < bpf_filter.len() {
        return Err(InstallationError::FilterTooLarge);
    }

    let bpf_filter_len =
        u16::try_from(bpf_filter.len()).map_err(|_| InstallationError::FilterTooLarge)?;

    // SAFETY: Safe because the parameters are valid.
    unsafe {
        {
            let rc = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            if rc != 0 {
                return Err(InstallationError::Prctl(std::io::Error::last_os_error()));
            }
        }

        let bpf_prog = SockFprog {
            len: bpf_filter_len,
            filter: bpf_filter.as_ptr(),
        };
        let bpf_prog_ptr = &bpf_prog as *const SockFprog;
        {
            let rc = libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                0,
                bpf_prog_ptr,
            );
            if rc != 0 {
                return Err(InstallationError::Prctl(std::io::Error::last_os_error()));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]

    use std::collections::HashMap;
    use std::thread;

    use super::*;

    #[test]
    fn test_deserialize_binary() {
        // Malformed bitcode binary.
        let data = "adassafvc".to_string();
        deserialize_binary(data.as_bytes()).unwrap_err();

        // Test that the binary deserialization is correct, and that the thread keys
        // have been lowercased.
        let bpf_prog = vec![0; 2];
        let mut filter_map: HashMap<String, BpfProgram> = HashMap::new();
        filter_map.insert("VcpU".to_string(), bpf_prog.clone());
        let bytes = bitcode::serialize(&filter_map).unwrap();

        let mut expected_res = BpfThreadMap::new();
        expected_res.insert(
            "vcpu".to_string(),
            SeccompFilter(vec![FilterPart {
                features: SeccompFeatures::empty(),
                code: bpf_prog,
            }]),
        );
        assert_eq!(deserialize_binary(&bytes[..]).unwrap(), expected_res);

        // Test filter too large - create data that will exceed the deserialization limit
        // Create a large buffer that when serialized will exceed DESERIALIZATION_BYTES_LIMIT
        let large_data = vec![0u8; DESERIALIZATION_BYTES_LIMIT + 1000];
        deserialize_binary(&large_data[..]).unwrap_err();
    }

    #[test]
    fn test_seccomp_features() {
        for feature in SeccompFeatures::all().iter() {
            assert_eq!(SeccompFeatures::from_tag(&feature.to_string()), Ok(feature));
        }
        assert_eq!(
            SeccompFeatures::all().to_string(),
            "api,pci,hotplug,block,async-io,net,vsock,pmem,memory-hotplug"
        );
        assert_eq!(SeccompFeatures::empty().to_string(), "");
        assert_eq!(
            SeccompFeatures::from_tag("warp-drive"),
            Err(UnknownSeccompFeature("warp-drive".to_string()))
        );
    }

    #[test]
    fn test_compose() {
        let part = |features, code| FilterPart { features, code };
        assert!(
            SeccompFilter::default()
                .compose(SeccompFeatures::all())
                .is_empty()
        );

        let filter = SeccompFilter(vec![
            part(SeccompFeatures::empty(), vec![1, 2]),
            part(SeccompFeatures::NET, vec![10, 11]),
            part(
                SeccompFeatures::PMEM | SeccompFeatures::MEMORY_HOTPLUG,
                vec![20],
            ),
            part(SeccompFeatures::empty(), vec![3]),
        ]);
        for (enabled, expected) in [
            (SeccompFeatures::empty(), vec![1, 2, 3]),
            (SeccompFeatures::NET, vec![1, 2, 10, 11, 3]),
            // Any one of a part's features enables it.
            (SeccompFeatures::PMEM, vec![1, 2, 20, 3]),
            (SeccompFeatures::MEMORY_HOTPLUG, vec![1, 2, 20, 3]),
            (SeccompFeatures::BLOCK, vec![1, 2, 3]),
            (SeccompFeatures::all(), vec![1, 2, 10, 11, 20, 3]),
        ] {
            assert_eq!(filter.compose(enabled), expected, "{enabled}");
        }
    }

    #[test]
    fn test_filter_apply() {
        // Test filter too large.
        thread::spawn(|| {
            let filter: BpfProgram = vec![0; 5000];

            // Apply seccomp filter.
            assert!(matches!(
                apply_filter(&filter).unwrap_err(),
                InstallationError::FilterTooLarge
            ));
        })
        .join()
        .unwrap();

        // Test empty filter.
        thread::spawn(|| {
            let filter: BpfProgram = vec![];

            assert_eq!(filter.len(), 0);

            let seccomp_level = unsafe { libc::prctl(libc::PR_GET_SECCOMP) };
            assert_eq!(seccomp_level, 0);

            apply_filter(&filter).unwrap();

            // test that seccomp level remains 0 on failure.
            let seccomp_level = unsafe { libc::prctl(libc::PR_GET_SECCOMP) };
            assert_eq!(seccomp_level, 0);
        })
        .join()
        .unwrap();

        // Test invalid BPF code.
        thread::spawn(|| {
            let filter = vec![0xFF; 1];

            let seccomp_level = unsafe { libc::prctl(libc::PR_GET_SECCOMP) };
            assert_eq!(seccomp_level, 0);

            assert!(matches!(
                apply_filter(&filter).unwrap_err(),
                InstallationError::Prctl(_)
            ));

            // test that seccomp level remains 0 on failure.
            let seccomp_level = unsafe { libc::prctl(libc::PR_GET_SECCOMP) };
            assert_eq!(seccomp_level, 0);
        })
        .join()
        .unwrap();
    }
}
