// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::str::FromStr;

use bincode::config;
use bincode::config::{Configuration, Fixint, Limit, LittleEndian};
use bincode::error::EncodeError as BincodeError;

mod bindings;
use bindings::*;

pub mod types;
pub use types::*;
use zerocopy::IntoBytes;

// This byte limit is passed to `bincode` to guard against a potential memory
// allocation DOS caused by binary filters that are too large.
// This limit can be safely determined since the maximum length of a BPF
// filter is 4096 instructions and Firecracker has a finite number of threads.
const DESERIALIZATION_BYTES_LIMIT: usize = 100_000;

pub const BINCODE_CONFIG: Configuration<LittleEndian, Fixint, Limit<DESERIALIZATION_BYTES_LIMIT>> =
    config::standard()
        .with_fixed_int_encoding()
        .with_limit::<DESERIALIZATION_BYTES_LIMIT>()
        .with_little_endian();

/// Binary filter compilation errors.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum CompilationError {
    /// Cannot open input file: {0}
    IntputOpen(std::io::Error),
    /// Cannot read input file: {0}
    InputRead(std::io::Error),
    /// Cannot deserialize json: {0}
    JsonDeserialize(serde_json::Error),
    /// Cannot parse arch: {0}
    ArchParse(String),
    /// Cannot create libseccomp context
    LibSeccompContext,
    /// Cannot add libseccomp arch
    LibSeccompArch,
    /// Cannot add libseccomp syscall
    LibSeccompSycall,
    /// Cannot add libseccomp syscall rule
    LibSeccompRule,
    /// Cannot export libseccomp bpf
    LibSeccompExport,
    /// Cannot create memfd: {0}
    MemfdCreate(std::io::Error),
    /// Cannot rewind memfd: {0}
    MemfdRewind(std::io::Error),
    /// Cannot read from memfd: {0}
    MemfdRead(std::io::Error),
    /// Cannot create output file: {0}
    OutputCreate(std::io::Error),
    /// Cannot serialize bfp: {0}
    BincodeSerialize(BincodeError),
}

pub fn compile_bpf(
    input_path: &str,
    arch: &str,
    out_path: &str,
    basic: bool,
) -> Result<(), CompilationError> {
    let mut file_content = String::new();
    File::open(input_path)
        .map_err(CompilationError::IntputOpen)?
        .read_to_string(&mut file_content)
        .map_err(CompilationError::InputRead)?;
    let bpf_map_json: BpfJson =
        serde_json::from_str(&file_content).map_err(CompilationError::JsonDeserialize)?;

    let arch = TargetArch::from_str(arch).map_err(CompilationError::ArchParse)?;

    // SAFETY: Safe because the parameters are valid.
    let memfd_fd = unsafe { libc::memfd_create(c"bpf".as_ptr().cast(), 0) };
    if memfd_fd < 0 {
        return Err(CompilationError::MemfdCreate(
            std::io::Error::last_os_error(),
        ));
    }

    // SAFETY: Safe because the parameters are valid.
    let mut memfd = unsafe { File::from_raw_fd(memfd_fd) };

    let mut bpf_map: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for (name, filter) in bpf_map_json.0.iter() {
        let default_action = filter.default_action.to_scmp_type();
        let filter_action = filter.filter_action.to_scmp_type();

        // SAFETY: Safe as all args are correct.
        let bpf_filter = {
            let r = seccomp_init(default_action);
            if r.is_null() {
                return Err(CompilationError::LibSeccompContext);
            }
            r
        };

        // SAFETY: Safe as all args are correct.
        unsafe {
            let r = seccomp_arch_add(bpf_filter, arch.to_scmp_type());
            if r != 0 && r != MINUS_EEXIST {
                return Err(CompilationError::LibSeccompArch);
            }
        }

        for rule in filter.filter.iter() {
            // SAFETY: Safe as all args are correct.
            let syscall = unsafe {
                let r = seccomp_syscall_resolve_name(rule.syscall.as_ptr());
                if r == __NR_SCMP_ERROR {
                    return Err(CompilationError::LibSeccompSycall);
                }
                r
            };

            // TODO remove when we drop deprecated "basic" arg from cli.
            // "basic" bpf means it ignores condition checks.
            if basic {
                // SAFETY: Safe as all args are correct.
                unsafe {
                    if seccomp_rule_add(bpf_filter, filter_action, syscall, 0) != 0 {
                        return Err(CompilationError::LibSeccompRule);
                    }
                }
            } else if let Some(rules) = &rule.args {
                let comparators = rules
                    .iter()
                    .map(|rule| rule.to_scmp_type())
                    .collect::<Vec<scmp_arg_cmp>>();

                // SAFETY: Safe as all args are correct.
                // We can assume no one will define u32::MAX
                // filters for a syscall.
                #[allow(clippy::cast_possible_truncation)]
                unsafe {
                    if seccomp_rule_add_array(
                        bpf_filter,
                        filter_action,
                        syscall,
                        comparators.len() as u32,
                        comparators.as_ptr(),
                    ) != 0
                    {
                        return Err(CompilationError::LibSeccompRule);
                    }
                }
            } else {
                // SAFETY: Safe as all args are correct.
                unsafe {
                    if seccomp_rule_add(bpf_filter, filter_action, syscall, 0) != 0 {
                        return Err(CompilationError::LibSeccompRule);
                    }
                }
            }
        }

        // SAFETY: Safe as all args are correect.
        unsafe {
            if seccomp_export_bpf(bpf_filter, memfd.as_raw_fd()) != 0 {
                return Err(CompilationError::LibSeccompExport);
            }
        }
        memfd.rewind().map_err(CompilationError::MemfdRewind)?;

        // Cast is safe because usize == u64
        #[allow(clippy::cast_possible_truncation)]
        let size = memfd.metadata().unwrap().size() as usize;
        // Bpf instructions are 8 byte values and 4 byte alignment.
        // We use u64 to satisfy these requirements.
        let instructions = size / std::mem::size_of::<u64>();
        let mut bpf = vec![0_u64; instructions];

        memfd
            .read_exact(bpf.as_mut_bytes())
            .map_err(CompilationError::MemfdRead)?;
        memfd.rewind().map_err(CompilationError::MemfdRewind)?;

        bpf_map.insert(name.clone(), bpf);
    }

    let mut output_file = File::create(out_path).map_err(CompilationError::OutputCreate)?;

    bincode::encode_into_std_write(&bpf_map, &mut output_file, BINCODE_CONFIG)
        .map_err(CompilationError::BincodeSerialize)?;
    Ok(())
}
