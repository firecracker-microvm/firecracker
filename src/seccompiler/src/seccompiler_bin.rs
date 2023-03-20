// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! seccompiler-bin is a program that compiles multi-threaded seccomp-bpf filters expressed as JSON
//! into raw BPF programs, serializing them and outputting them to a file.
//!
//! Used in conjunction with the provided library crate, one can deserialize the binary filters
//! and easily install them on a per-thread basis, in order to achieve a quick and robust
//! seccomp-based jailing solution.
//!
//! See the documentation on github for more information.
//!
//!  ```text
//! The compilation goes through a couple of steps, from JSON to BPF:
//!
//!                  JSON
//!                   |
//!            (via serde_json)
//!                   |
//!                   V
//!       collection of `Filter` objects
//!                   |
//!      (via Compiler.compile_blob(...))
//!                   |
//!                   V
//!   collection of `SeccompFilter` objects
//!     (IR - intermediate representation)
//!                   |
//!    (via SeccompFilter.try_into::<BpfProgram>(...))
//!                   |
//!                   V
//!     collection of `BpfProgram` objects
//! ```

mod backend;
mod common;
mod compiler;
mod syscall_table;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::{io, process};

use backend::{TargetArch, TargetArchError};
use bincode::Error as BincodeError;
use clap::Parser;
use common::BpfProgram;
use compiler::{Compiler, Error as FilterFormatError, JsonFile};
use serde_json::error::Error as JSONError;

const SECCOMPILER_VERSION: &str = env!("FIRECRACKER_VERSION");
const DEFAULT_OUTPUT_FILENAME: &str = "seccomp_binary_filter.out";
const EXIT_CODE_ERROR: i32 = 1;

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("Bincode (de)serialization failed: {0}")]
    Bincode(BincodeError),
    #[error("{0}")]
    FileFormat(FilterFormatError),
    #[error("{}", format!("Failed to open file {:?}: {1}", .0, .1).replace('\"', ""))]
    FileOpen(PathBuf, io::Error),
    #[error("Error parsing JSON: {0}")]
    Json(JSONError),
    #[error("{0}")]
    Arch(#[from] TargetArchError),
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Parser, PartialEq)]
struct Args {
    /// File path of the JSON input.
    #[arg(long)]
    input_file: String,
    /// Optional path of the output file.
    #[arg(long, default_value = DEFAULT_OUTPUT_FILENAME)]
    output_file: String,
    /// The computer architecture where the BPF program runs. Supported architectures: x86_64,
    /// aarch64.
    #[arg(long)]
    target_arch: TargetArch,
    /// Deprecated! Transforms the filters into basic filters. Drops all argument checks and
    /// rule-level actions. Not recommended.
    #[arg(long, default_value_t = false)]
    basic: bool,
    #[arg(long, default_value_t = false)]
    version: bool,
}

fn parse_json(reader: impl Read) -> Result<JsonFile> {
    serde_json::from_reader(reader).map_err(Error::Json)
}

fn compile(args: &Args) -> Result<()> {
    let input_file = File::open(&args.input_file)
        .map_err(|err| Error::FileOpen(PathBuf::from(&args.input_file), err))?;
    let mut input_reader = BufReader::new(input_file);
    let filters = parse_json(&mut input_reader)?;
    let compiler = Compiler::new(args.target_arch);

    // transform the IR into a Map of BPFPrograms
    let bpf_data: BTreeMap<String, BpfProgram> = compiler
        .compile_blob(filters.0, args.basic)
        .map_err(Error::FileFormat)?;

    // serialize the BPF programs & output them to a file
    let output_file = File::create(&args.output_file)
        .map_err(|err| Error::FileOpen(PathBuf::from(&args.output_file), err))?;
    bincode::serialize_into(output_file, &bpf_data).map_err(Error::Bincode)?;

    Ok(())
}

fn main() {
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(err) => {
            eprintln!(
                "Arguments parsing error: {} \n\nFor more information try --help.",
                err
            );
            process::exit(EXIT_CODE_ERROR);
        }
    };

    if args.version {
        println!("Seccompiler-bin v{}\n", SECCOMPILER_VERSION);
        return;
    }

    if let Err(err) = compile(&args) {
        eprintln!("Seccompiler error: {}", err);
        process::exit(EXIT_CODE_ERROR);
    }

    println!("Filter successfully compiled into: {}", args.output_file);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]
    use std::collections::HashMap;
    use std::io;
    use std::io::Write;
    use std::path::PathBuf;

    use bincode::Error as BincodeError;
    use utils::tempfile::TempFile;

    use super::compiler::{Error as FilterFormatError, Filter, SyscallRule};
    use super::{compile, parse_json, Error};
    use crate::backend::SeccompCmpArgLen::*;
    use crate::backend::SeccompCmpOp::{Le, *};
    use crate::backend::{SeccompAction, SeccompCondition as Cond, TargetArch, TargetArchError};

    // Correct JSON input data
    static CORRECT_JSON_INPUT: &str = r#"
        {
            "thread_1": {
                "default_action": {
                    "errno": 12
                },
                "filter_action": "allow",
                "filter": [
                    {
                        "syscall": "open"
                    },
                    {
                        "syscall": "close"
                    },
                    {
                        "syscall": "stat"
                    },
                    {
                        "syscall": "futex",
                        "args": [
                            {
                                "index": 2,
                                "type": "dword",
                                "op": "le",
                                "val": 65
                            },
                            {
                                "index": 1,
                                "type": "qword",
                                "op": "ne",
                                "val": 80
                            }
                        ]
                    },
                    {
                        "syscall": "futex",
                        "args": [
                            {
                                "index": 3,
                                "type": "qword",
                                "op": "gt",
                                "val": 65
                            },
                            {
                                "index": 1,
                                "type": "qword",
                                "op": "lt",
                                "val": 80
                            }
                        ]
                    },
                    {
                        "syscall": "futex",
                        "args": [
                            {
                                "index": 3,
                                "type": "qword",
                                "op": "ge",
                                "val": 65
                            }
                        ]
                    },
                    {
                        "syscall": "ioctl",
                        "args": [
                            {
                                "index": 3,
                                "type": "dword",
                                "op": {
                                    "masked_eq": 100
                                },
                                "val": 65
                            }
                        ]
                    }
                ]
            },
            "thread_2": {
                "default_action": "trap",
                "filter_action": "allow",
                "filter": [
                    {
                        "syscall": "ioctl",
                        "args": [
                            {
                                "index": 3,
                                "type": "dword",
                                "op": "eq",
                                "val": 65
                            }
                        ]
                    }
                ]
            }
        }
    "#;

    #[test]
    fn test_error_messages() {
        let path = PathBuf::from("/path");
        assert_eq!(
            format!(
                "{}",
                Error::Bincode(BincodeError::new(bincode::ErrorKind::SizeLimit))
            ),
            format!(
                "Bincode (de)serialization failed: {}",
                BincodeError::new(bincode::ErrorKind::SizeLimit)
            )
        );
        assert_eq!(
            format!(
                "{}",
                Error::FileFormat(FilterFormatError::SyscallName(
                    "dsaa".to_string(),
                    TargetArch::aarch64
                ))
            ),
            format!(
                "{}",
                FilterFormatError::SyscallName("dsaa".to_string(), TargetArch::aarch64)
            )
        );
        assert_eq!(
            format!(
                "{}",
                Error::FileOpen(path.clone(), io::Error::from_raw_os_error(2))
            ),
            format!(
                "Failed to open file {:?}: {}",
                path,
                io::Error::from_raw_os_error(2)
            )
            .replace('\"', "")
        );
        assert_eq!(
            format!(
                "{}",
                Error::Json(serde_json::from_str::<serde_json::Value>("").unwrap_err())
            ),
            format!(
                "Error parsing JSON: {}",
                serde_json::from_str::<serde_json::Value>("").unwrap_err()
            )
        );
        assert_eq!(
            format!(
                "{}",
                Error::Arch(TargetArchError::InvalidString("lala".to_string()))
            ),
            format!("{}", TargetArchError::InvalidString("lala".to_string()))
        );
    }

    #[test]
    fn test_parse_json() {
        // test with malformed JSON
        {
            // empty file
            assert!(parse_json(std::io::empty()).is_err());

            // not json
            let json_input = "hjkln";
            assert!(parse_json(json_input.as_bytes()).is_err());

            // top-level array
            let json_input = "[]";
            assert!(parse_json(json_input.as_bytes()).is_err());

            // thread key must be a string
            let json_input = "{1}";
            assert!(parse_json(json_input.as_bytes()).is_err());

            // empty Filter object
            let json_input = r#"{"a": {}}"#;
            assert!(parse_json(json_input.as_bytes()).is_err());

            // missing 'filter' field
            let json_input = r#"{"a": {"filter_action": "allow", "default_action":"log"}}"#;
            assert!(parse_json(json_input.as_bytes()).is_err());

            // wrong key 'filters'
            let json_input =
                r#"{"a": {"filter_action": "allow", "default_action":"log", "filters": []}}"#;
            assert!(parse_json(json_input.as_bytes()).is_err());

            // wrong action 'logs'
            let json_input =
                r#"{"a": {"filter_action": "allow", "default_action":"logs", "filter": []}}"#;
            assert!(parse_json(json_input.as_bytes()).is_err());

            // action that expects a value
            let json_input =
                r#"{"a": {"filter_action": "allow", "default_action":"errno", "filter": []}}"#;

            assert!(parse_json(json_input.as_bytes()).is_err());

            // overflowing u64 value
            let json_input = r#"
            {
                "thread_2": {
                    "default_action": "trap",
                    "filter_action": "allow",
                    "filter": [
                        {
                            "syscall": "ioctl",
                            "args": [
                                {
                                    "index": 3,
                                    "type": "qword",
                                    "op": "eq",
                                    "val": 18446744073709551616
                                }
                            ]
                        }
                    ]
                }
            }
            "#;
            assert!(parse_json(json_input.as_bytes()).is_err());

            // negative integer value
            let json_input = r#"
            {
                "thread_2": {
                    "default_action": "trap",
                    "filter_action": "allow",
                    "filter": [
                        {
                            "syscall": "ioctl",
                            "args": [
                                {
                                    "index": 3,
                                    "type": "qword",
                                    "op": "eq",
                                    "val": -1846
                                }
                            ]
                        }
                    ]
                }
            }
            "#;
            assert!(parse_json(json_input.as_bytes()).is_err());

            // float value
            let json_input = r#"
            {
                "thread_2": {
                    "default_action": "trap",
                    "filter_action": "allow",
                    "filter": [
                        {
                            "syscall": "ioctl",
                            "args": [
                                {
                                    "index": 3,
                                    "type": "qword",
                                    "op": "eq",
                                    "val": 1846.4
                                }
                            ]
                        }
                    ]
                }
            }
            "#;
            assert!(parse_json(json_input.as_bytes()).is_err());

            // duplicate filter keys
            let json_input = r#"
            {
                "thread_1": {
                    "default_action": "trap",
                    "filter_action": "allow",
                    "filter": []
                },
                "thread_1": {
                    "default_action": "trap",
                    "filter_action": "allow",
                    "filter": []
                }
            }
            "#;
            assert!(parse_json(json_input.as_bytes()).is_err());
        }

        // test with correctly formed JSON
        {
            // empty JSON file
            let json_input = "{}";
            assert_eq!(parse_json(json_input.as_bytes()).unwrap().0.len(), 0);

            // empty Filter
            let json_input =
                r#"{"a": {"filter_action": "allow", "default_action":"log", "filter": []}}"#;
            assert!(parse_json(json_input.as_bytes()).is_ok());

            // correctly formed JSON filter
            let mut filters = HashMap::new();
            filters.insert(
                "thread_1".to_string(),
                Filter::new(
                    SeccompAction::Errno(12),
                    SeccompAction::Allow,
                    vec![
                        SyscallRule::new("open".to_string(), None),
                        SyscallRule::new("close".to_string(), None),
                        SyscallRule::new("stat".to_string(), None),
                        SyscallRule::new(
                            "futex".to_string(),
                            Some(vec![
                                Cond::new(2, Dword, Le, 65).unwrap(),
                                Cond::new(1, Qword, Ne, 80).unwrap(),
                            ]),
                        ),
                        SyscallRule::new(
                            "futex".to_string(),
                            Some(vec![
                                Cond::new(3, Qword, Gt, 65).unwrap(),
                                Cond::new(1, Qword, Lt, 80).unwrap(),
                            ]),
                        ),
                        SyscallRule::new(
                            "futex".to_string(),
                            Some(vec![Cond::new(3, Qword, Ge, 65).unwrap()]),
                        ),
                        SyscallRule::new(
                            "ioctl".to_string(),
                            Some(vec![Cond::new(3, Dword, MaskedEq(100), 65).unwrap()]),
                        ),
                    ],
                ),
            );

            filters.insert(
                "thread_2".to_string(),
                Filter::new(
                    SeccompAction::Trap,
                    SeccompAction::Allow,
                    vec![SyscallRule::new(
                        "ioctl".to_string(),
                        Some(vec![Cond::new(3, Dword, Eq, 65).unwrap()]),
                    )],
                ),
            );

            // sort the HashMaps by key and transform into vectors, to make comparison possible
            let mut v1: Vec<_> = filters.into_iter().collect();
            v1.sort_by(|x, y| x.0.cmp(&y.0));

            let mut v2: Vec<_> = parse_json(CORRECT_JSON_INPUT.as_bytes())
                .unwrap()
                .0
                .into_iter()
                .collect();
            v2.sort_by(|x, y| x.0.cmp(&y.0));
            assert_eq!(v1, v2);
        }
    }

    #[allow(clippy::useless_asref)]
    #[test]
    fn test_compile() {
        // --input-file was deleted
        {
            let mut in_file = TempFile::new().unwrap();
            in_file.remove().unwrap();
            let args = crate::Args {
                input_file: in_file.as_path().to_str().unwrap().to_string(),
                target_arch: TargetArch::x86_64,
                output_file: "bpf.out".to_string(),
                basic: false,
                version: false,
            };

            match compile(&args).unwrap_err() {
                Error::FileOpen(buf, _) => assert_eq!(buf, PathBuf::from(in_file.as_path())),
                _ => panic!("Expected FileOpen error."),
            }
        }

        // test a successful compilation
        {
            let in_file = TempFile::new().unwrap();
            let out_file = TempFile::new().unwrap();

            in_file
                .as_file()
                .write_all(CORRECT_JSON_INPUT.as_bytes())
                .unwrap();

            let arguments = crate::Args {
                input_file: in_file.as_path().to_str().unwrap().to_string(),
                output_file: out_file.as_path().to_str().unwrap().to_string(),
                target_arch: TargetArch::x86_64,
                basic: false,
                version: false,
            };

            // do the compilation & check for errors
            assert!(compile(&arguments).is_ok());

            // also check with is_basic: true
            let arguments = crate::Args {
                input_file: in_file.as_path().to_str().unwrap().to_string(),
                output_file: out_file.as_path().to_str().unwrap().to_string(),
                target_arch: TargetArch::x86_64,
                basic: true,
                version: false,
            };

            // do the compilation & check for errors
            assert!(compile(&arguments).is_ok());
        }
    }
}
