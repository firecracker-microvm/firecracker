// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::io::Read;

pub use seccomp_filter::{
    FeatureListError, FilterError, FilterFragment, FormatError, SeccompFeature, SeccompFeatures,
    SeccompFilter, UnknownSeccompFeature,
};

/// Each BPF instruction is 8 bytes long and 4 byte aligned.
/// This alignment needs to be satisfied in order for a BPF code to be accepted
/// by the syscalls. Using u64 here is is safe as it has same size and even bigger alignment.
pub type BpfInstruction = u64;

/// Program made up of a sequence of BPF instructions.
pub type BpfProgram = Vec<BpfInstruction>;

/// Reference to program made up of a sequence of BPF instructions.
pub type BpfProgramRef<'a> = &'a [BpfInstruction];

/// Type that associates a thread category to its seccomp filter.
pub type BpfThreadMap = HashMap<String, SeccompFilter>;

/// Binary filter deserialization errors.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum DeserializationError {
    /// Failed to read input: {0}
    InputRead(std::io::Error),
    /// {0}
    Format(#[from] FormatError),
    /// Invalid filter for the {0} thread: {1}
    Filter(String, FilterError),
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
    // Read at most one byte more than a compiled filter file can have, so that an oversized
    // input is reported as such without reading it whole.
    let mut buf = Vec::new();
    reader
        .take((seccomp_filter::MAX_ENCODED_SIZE + 1) as u64)
        .read_to_end(&mut buf)
        .map_err(DeserializationError::InputRead)?;

    seccomp_filter::decode(&buf)?
        .into_iter()
        .map(|(thread, filter)| {
            let filter = SeccompFilter::try_from(filter)
                .map_err(|err| DeserializationError::Filter(thread.clone(), err))?;
            Ok((thread.to_lowercase(), filter))
        })
        .collect()
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
pub use seccomp_filter::bpf::BPF_MAX_LEN;

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

    use std::thread;

    use seccomp_filter::bpf::{BPF_JEQ_K, BPF_LD_W_ABS, BPF_RET_K, ProgramError, insn};
    use seccomp_filter::{BpfFilter, BpfFragment, BpfMap, MAX_ENCODED_SIZE};

    use super::*;

    const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

    /// A position independent part allowing syscall `nr` and falling through otherwise.
    fn allow(nr: u32) -> Vec<u64> {
        vec![
            insn(BPF_LD_W_ABS, 0, 0, 0),
            insn(BPF_JEQ_K, 0, 1, nr),
            insn(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW),
        ]
    }

    fn trap() -> Vec<u64> {
        vec![insn(BPF_RET_K, 0, 0, SECCOMP_RET_TRAP)]
    }

    #[test]
    fn test_deserialize_binary() {
        // Not a compiled filter at all.
        assert!(matches!(
            deserialize_binary(&b"adassafvc"[..]).unwrap_err(),
            DeserializationError::Format(FormatError::UnknownFormat)
        ));

        // Test that the binary deserialization is correct, and that the thread keys
        // have been lowercased.
        let filter_map = BpfMap::from([
            (
                "VcpU".to_string(),
                BpfFilter {
                    base: allow(1),
                    fragments: vec![BpfFragment {
                        features: vec!["net".to_string(), "hotplug".to_string()],
                        code: allow(2),
                    }],
                    epilogue: trap(),
                },
            ),
            (
                "api".to_string(),
                BpfFilter {
                    base: trap(),
                    ..Default::default()
                },
            ),
            ("vmm".to_string(), BpfFilter::default()),
        ]);
        let mut expected_res = BpfThreadMap::new();
        expected_res.insert(
            "vcpu".to_string(),
            SeccompFilter::new(
                allow(1),
                vec![FilterFragment {
                    features: SeccompFeatures::from(SeccompFeature::Net) | SeccompFeature::Hotplug,
                    code: allow(2),
                }],
                trap(),
            ),
        );
        expected_res.insert("api".to_string(), SeccompFilter::from_program(trap()));
        expected_res.insert("vmm".to_string(), SeccompFilter::default());
        let bytes = seccomp_filter::encode(&filter_map).unwrap();
        assert_eq!(deserialize_binary(&bytes[..]).unwrap(), expected_res);

        // An invalid filter is reported with its thread.
        let filter_map = BpfMap::from([(
            "vmm".to_string(),
            BpfFilter {
                base: allow(1),
                fragments: vec![BpfFragment {
                    features: vec!["warp-drive".to_string()],
                    code: allow(2),
                }],
                epilogue: trap(),
            },
        )]);
        let bytes = seccomp_filter::encode(&filter_map).unwrap();
        assert!(matches!(
            deserialize_binary(&bytes[..]).unwrap_err(),
            DeserializationError::Filter(thread, FilterError::UnknownFeature(UnknownSeccompFeature(name)))
                if thread == "vmm" && name == "warp-drive"
        ));

        // So is one whose fragment would jump out of the composed program.
        let filter_map = BpfMap::from([(
            "vcpu".to_string(),
            BpfFilter {
                base: allow(1),
                fragments: vec![BpfFragment {
                    features: vec!["net".to_string()],
                    code: vec![insn(BPF_JEQ_K, 0, 2, 2)],
                }],
                epilogue: trap(),
            },
        )]);
        let bytes = seccomp_filter::encode(&filter_map).unwrap();
        assert!(matches!(
            deserialize_binary(&bytes[..]).unwrap_err(),
            DeserializationError::Filter(
                thread,
                FilterError::InvalidFragment(0, ProgramError::InvalidJump(0))
            ) if thread == "vcpu"
        ));

        // Test filter too large - create data that will exceed the deserialization limit
        let large_data = vec![0u8; MAX_ENCODED_SIZE + 1000];
        assert!(matches!(
            deserialize_binary(&large_data[..]).unwrap_err(),
            DeserializationError::Format(FormatError::SizeLimitExceeded(..))
        ));
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
