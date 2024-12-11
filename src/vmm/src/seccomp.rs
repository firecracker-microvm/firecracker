// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;

use bincode::{DefaultOptions, Options};

/// Each BPF instruction is 8 bytes long and 4 byte aligned.
/// This alignment needs to be satisfied in order for a BPF code to be accepted
/// by the syscalls. Using u64 here is is safe as it has same size and even bigger alignment.
pub type BpfInstruction = u64;

/// Program made up of a sequence of BPF instructions.
pub type BpfProgram = Vec<BpfInstruction>;

/// Reference to program made up of a sequence of BPF instructions.
pub type BpfProgramRef<'a> = &'a [BpfInstruction];

/// Type that associates a thread category to a BPF program.
pub type BpfThreadMap = HashMap<String, Arc<BpfProgram>>;

/// Binary filter deserialization errors.
pub type DeserializationError = bincode::Error;

/// Retrieve empty seccomp filters.
pub fn get_empty_filters() -> BpfThreadMap {
    let mut map = BpfThreadMap::new();
    map.insert("vmm".to_string(), Arc::new(vec![]));
    map.insert("api".to_string(), Arc::new(vec![]));
    map.insert("vcpu".to_string(), Arc::new(vec![]));
    map
}

/// Deserialize binary with bpf filters
pub fn deserialize_binary<R: Read>(
    reader: R,
    bytes_limit: Option<u64>,
) -> Result<BpfThreadMap, DeserializationError> {
    let result = match bytes_limit {
        Some(limit) => DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_limit(limit)
            .deserialize_from::<R, HashMap<String, BpfProgram>>(reader),
        // No limit is the default.
        None => bincode::deserialize_from::<R, HashMap<String, BpfProgram>>(reader),
    }?;

    Ok(result
        .into_iter()
        .map(|(k, v)| (k.to_lowercase(), Arc::new(v)))
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
    use std::sync::Arc;
    use std::thread;

    use super::*;

    #[test]
    fn test_deserialize_binary() {
        // Malformed bincode binary.
        {
            let data = "adassafvc".to_string();
            deserialize_binary(data.as_bytes(), None).unwrap_err();
        }

        // Test that the binary deserialization is correct, and that the thread keys
        // have been lowercased.
        {
            let bpf_prog = vec![0; 2];
            let mut filter_map: HashMap<String, BpfProgram> = HashMap::new();
            filter_map.insert("VcpU".to_string(), bpf_prog.clone());
            let bytes = bincode::serialize(&filter_map).unwrap();

            let mut expected_res = BpfThreadMap::new();
            expected_res.insert("vcpu".to_string(), Arc::new(bpf_prog));
            assert_eq!(deserialize_binary(&bytes[..], None).unwrap(), expected_res);
        }

        // Test deserialization with binary_limit.
        {
            let bpf_prog = vec![0; 2];

            let mut filter_map: HashMap<String, BpfProgram> = HashMap::new();
            filter_map.insert("t1".to_string(), bpf_prog.clone());

            let bytes = bincode::serialize(&filter_map).unwrap();

            // Binary limit too low.
            assert!(matches!(
                deserialize_binary(&bytes[..], Some(20)).unwrap_err(),
                error
                    if error.to_string() == "the size limit has been reached"
            ));

            let mut expected_res = BpfThreadMap::new();
            expected_res.insert("t1".to_string(), Arc::new(bpf_prog));

            // Correct binary limit.
            assert_eq!(
                deserialize_binary(&bytes[..], Some(50)).unwrap(),
                expected_res
            );
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
