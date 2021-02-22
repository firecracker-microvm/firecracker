// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]

//! The library crate that defines common helper functions that are generally used in
//! conjunction with the seccompiler binary.

mod common;

use bincode::Error as BincodeError;
use bincode::{DefaultOptions, Options};
use common::BPF_MAX_LEN;
use std::fmt::{Display, Formatter};
use std::io::Read;

// Re-export the data types needed for calling the helper functions.
pub use common::{sock_filter, BpfProgram, BpfThreadMap};

// BPF structure definition for filter array.
// See /usr/include/linux/filter.h .
#[repr(C)]
struct sock_fprog {
    pub len: ::std::os::raw::c_ushort,
    pub filter: *const sock_filter,
}

/// Reference to program made up of a sequence of BPF instructions.
pub type BpfProgramRef<'a> = &'a [sock_filter];

/// Binary filter deserialization errors.
#[derive(Debug)]
pub enum DeserializationError {
    /// Error when doing bincode deserialization.
    Bincode(BincodeError),
}

impl Display for DeserializationError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::DeserializationError::*;

        match *self {
            Bincode(ref err) => write!(f, "Bincode deserialization failed: {}", err),
        }
    }
}

/// Filter installation errors.
#[derive(Debug, PartialEq)]
pub enum InstallationError {
    /// Filter exceeds the maximum number of instructions that a BPF program can have.
    FilterTooLarge,
    /// Error returned by `prctl`.
    Prctl(i32),
}

impl Display for InstallationError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::InstallationError::*;

        match *self {
            FilterTooLarge => write!(
                f,
                "Filter length exceeds the maximum size of {} instructions ",
                BPF_MAX_LEN
            ),
            Prctl(ref errno) => write!(f, "`prctl` syscall failed with error code: {}", errno),
        }
    }
}

/// Deserialize a BPF file into a collection of usable BPF filters.
/// Has an optional `bytes_limit` that is passed to bincode to constrain the maximum amount of memory
/// that we can allocate while performing the deserialization.
/// It's recommended that the integrator of the library uses this to prevent memory allocations DOS-es.
pub fn deserialize_binary(
    reader: &mut dyn Read,
    bytes_limit: Option<u64>,
) -> std::result::Result<BpfThreadMap, DeserializationError> {
    let result = match bytes_limit {
        // Also add the default options. These are not part of the `DefaultOptions` as per
        // this issue: https://github.com/servo/bincode/issues/333
        Some(limit) => DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_limit(limit)
            .deserialize_from::<&mut dyn Read, BpfThreadMap>(reader),
        // No limit is the default.
        None => bincode::deserialize_from::<&mut dyn Read, BpfThreadMap>(reader),
    };

    Ok(result
        .map_err(DeserializationError::Bincode)?
        .into_iter()
        .map(|(k, v)| (k.to_lowercase(), v))
        .collect())
}

/// Helper function for installing a BPF filter.
pub fn apply_filter(bpf_filter: BpfProgramRef) -> std::result::Result<(), InstallationError> {
    // If the program is empty, don't install the filter.
    if bpf_filter.is_empty() {
        return Ok(());
    }

    // If the program length is greater than the limit allowed by the kernel,
    // fail quickly. Otherwise, `prctl` will give a more cryptic error code.
    if bpf_filter.len() > BPF_MAX_LEN {
        return Err(InstallationError::FilterTooLarge);
    }

    unsafe {
        {
            let rc = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            if rc != 0 {
                return Err(InstallationError::Prctl(*libc::__errno_location()));
            }
        }

        let bpf_prog = sock_fprog {
            len: bpf_filter.len() as u16,
            filter: bpf_filter.as_ptr(),
        };
        let bpf_prog_ptr = &bpf_prog as *const sock_fprog;
        {
            let rc = libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                bpf_prog_ptr,
            );
            if rc != 0 {
                return Err(InstallationError::Prctl(*libc::__errno_location()));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::BpfProgram;
    use std::thread;
    #[test]
    fn test_deserialize_binary() {
        // Malformed bincode binary.
        {
            let mut data = "adassafvc".to_string();
            let data = unsafe { data.as_bytes_mut() };
            assert!(deserialize_binary(&mut &data[..], None).is_err());
        }

        // Test that the binary deserialization is correct, and that the thread keys
        // have been lowercased.
        {
            let bpf_prog = vec![
                sock_filter {
                    code: 32,
                    jt: 0,
                    jf: 0,
                    k: 0,
                },
                sock_filter {
                    code: 32,
                    jt: 0,
                    jf: 0,
                    k: 4,
                },
            ];
            let mut filter_map = BpfThreadMap::new();
            filter_map.insert("VcpU".to_string(), bpf_prog.clone());
            let bytes = bincode::serialize(&filter_map).unwrap();

            let mut expected_res = BpfThreadMap::new();
            expected_res.insert("vcpu".to_string(), bpf_prog);
            assert_eq!(
                deserialize_binary(&mut &bytes[..], None).unwrap(),
                expected_res
            );
        }

        // Test deserialization with binary_limit.
        {
            let bpf_prog = vec![sock_filter {
                code: 32,
                jt: 0,
                jf: 0,
                k: 0,
            }];

            let mut filter_map = BpfThreadMap::new();
            filter_map.insert("t1".to_string(), bpf_prog);

            let bytes = bincode::serialize(&filter_map).unwrap();

            // Binary limit too low.
            assert!(matches!(
                deserialize_binary(&mut &bytes[..], Some(20)).unwrap_err(),
                DeserializationError::Bincode(error)
                    if error.to_string() == "the size limit has been reached"
            ));

            // Correct binary limit.
            assert_eq!(
                deserialize_binary(&mut &bytes[..], Some(50)).unwrap(),
                filter_map
            );
        }
    }

    #[test]
    fn test_filter_apply() {
        // Test filter too large.
        thread::spawn(|| {
            let filter: BpfProgram = vec![
                sock_filter {
                    code: 6,
                    jt: 0,
                    jf: 0,
                    k: 0,
                };
                5000 // Limit is 4096
            ];

            // Apply seccomp filter.
            assert_eq!(
                apply_filter(&filter).unwrap_err(),
                InstallationError::FilterTooLarge
            );
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
            let filter = vec![sock_filter {
                // invalid opcode
                code: 9999,
                jt: 0,
                jf: 0,
                k: 0,
            }];

            let seccomp_level = unsafe { libc::prctl(libc::PR_GET_SECCOMP) };
            assert_eq!(seccomp_level, 0);

            assert_eq!(
                apply_filter(&filter).unwrap_err(),
                InstallationError::Prctl(22)
            );

            // test that seccomp level remains 0 on failure.
            let seccomp_level = unsafe { libc::prctl(libc::PR_GET_SECCOMP) };
            assert_eq!(seccomp_level, 0);
        })
        .join()
        .unwrap();
    }
}
