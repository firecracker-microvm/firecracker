// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek};
use std::os::fd::FromRawFd;
use std::os::unix::fs::MetadataExt;

use bincode::Error as BincodeError;
use libseccomp::*;

pub mod types;
pub use types::*;

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
    /// Cannot create libseccomp context: {0}
    LibSeccompContext(libseccomp::error::SeccompError),
    /// Cannot add libseccomp arch: {0}
    LibSeccompArch(libseccomp::error::SeccompError),
    /// Cannot add libseccomp syscall: {0}
    LibSeccompSycall(libseccomp::error::SeccompError),
    /// Cannot add libseccomp syscall rule: {0}
    LibSeccompRule(libseccomp::error::SeccompError),
    /// Cannot create memfd: {0}
    MemfdCreate(i32),
    /// Cannot resize memfd: {0}
    MemfdResize(std::io::Error),
    /// Cannot export libseccomp bpf: {0}
    LibSeccompExport(libseccomp::error::SeccompError),
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

    let arch: TargetArch = arch.try_into().map_err(CompilationError::ArchParse)?;

    // SAFETY: Safe because the parameters are valid.
    let memfd_fd = unsafe { libc::memfd_create("bpf\0".as_ptr().cast(), 0) };
    if memfd_fd < 0 {
        return Err(CompilationError::MemfdCreate(
            // SAFETY: Safe because there are no parameters.
            unsafe { *libc::__errno_location() },
        ));
    }

    // SAFETY: Safe because the parameters are valid.
    let mut memfd = unsafe { File::from_raw_fd(memfd_fd) };

    let mut bpf_map: HashMap<String, Vec<BpfInstruction>> = HashMap::new();
    for (name, filter) in bpf_map_json.0.iter() {
        let default_action = filter.default_action.to_scmp_type();
        let filter_action = filter.filter_action.to_scmp_type();

        let mut bpf_filter = ScmpFilterContext::new_filter(default_action)
            .map_err(CompilationError::LibSeccompContext)?;
        bpf_filter
            .add_arch(arch.to_scmp_type())
            .map_err(CompilationError::LibSeccompArch)?;

        for rule in filter.filter.iter() {
            let syscall = ScmpSyscall::from_name(&rule.syscall)
                .map_err(CompilationError::LibSeccompSycall)?;

            // TODO remove when we drop deprecated "basic" arg from cli.
            // "basic" bpf means it ignores condition checks.
            if basic {
                bpf_filter
                    .add_rule(filter_action, syscall)
                    .map_err(CompilationError::LibSeccompRule)?;
            } else if let Some(rules) = &rule.args {
                let comparators = rules
                    .iter()
                    .map(|rule| {
                        #[cfg(target_arch = "x86_64")]
                        const IOCTL: i32 = 16;
                        #[cfg(target_arch = "aarch64")]
                        const IOCTL: i32 = 29;

                        // For `ioctls` we need to mask upper bits as musl
                        // sets them to 1, but libseccomp expilictly checks that they are 0.
                        // with 0x00000000FFFFFFFF mask upper bits are always 0.
                        let op = if syscall == IOCTL {
                            let original_rule = rule.op.to_scmp_type();
                            if original_rule == ScmpCompareOp::Equal {
                                ScmpCompareOp::MaskedEqual(0x00000000FFFFFFFF)
                            } else {
                                original_rule
                            }
                        } else {
                            rule.op.to_scmp_type()
                        };
                        ScmpArgCompare::new(rule.index as u32, op, rule.val)
                    })
                    .collect::<Vec<ScmpArgCompare>>();
                bpf_filter
                    .add_rule_conditional(filter_action, syscall, &comparators)
                    .map_err(CompilationError::LibSeccompRule)?;
            } else {
                bpf_filter
                    .add_rule(filter_action, syscall)
                    .map_err(CompilationError::LibSeccompRule)?;
            }
        }

        memfd.rewind().unwrap();
        bpf_filter
            .export_bpf(&mut memfd)
            .map_err(CompilationError::LibSeccompExport)?;
        memfd.rewind().unwrap();

        // Usize == u64
        #[allow(clippy::cast_possible_truncation)]
        let size = memfd.metadata().unwrap().size() as usize;
        let instructions = size / std::mem::size_of::<BpfInstruction>();
        let mut bpf = vec![0_u64; instructions];

        // SAFETY: Safe as u64 has bigger alignment and size is correct.
        let bpf_u8: &mut [u8] =
            unsafe { std::slice::from_raw_parts_mut(bpf.as_mut_ptr().cast(), size) };
        memfd.read_exact(bpf_u8).unwrap();
        bpf_map.insert(name.clone(), bpf);
    }

    let output_file = File::create(out_path).map_err(CompilationError::OutputCreate)?;

    bincode::serialize_into(output_file, &bpf_map).map_err(CompilationError::BincodeSerialize)?;
    Ok(())
}
