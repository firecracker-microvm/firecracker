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

use std::collections::HashMap;
use std::convert::TryInto;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::{fmt, io, process};

use backend::{TargetArch, TargetArchError};
use bincode::Error as BincodeError;
use common::BpfProgram;
use compiler::{Compiler, Error as FilterFormatError, Filter};
use serde_json::error::Error as JSONError;
use utils::arg_parser::{ArgParser, Argument, Arguments as ArgumentsBag};

const SECCOMPILER_VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_OUTPUT_FILENAME: &str = "seccomp_binary_filter.out";
const EXIT_CODE_ERROR: i32 = 1;

#[derive(Debug)]
enum Error {
    Bincode(BincodeError),
    FileOpen(PathBuf, io::Error),
    FileFormat(FilterFormatError),
    Json(JSONError),
    MissingInputFile,
    MissingTargetArch,
    Arch(TargetArchError),
}

type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match *self {
            Bincode(ref err) => write!(f, "Bincode (de)serialization failed: {}", err),
            FileFormat(ref err) => write!(f, "{}", err),
            FileOpen(ref path, ref err) => write!(
                f,
                "{}",
                format!("Failed to open file {:?}: {}", path, err).replace("\"", "")
            ),
            Json(ref err) => write!(f, "Error parsing JSON: {}", err),
            MissingInputFile => write!(f, "Missing input file."),
            MissingTargetArch => write!(f, "Missing target arch."),
            Arch(ref err) => write!(f, "{}", err),
        }
    }
}

#[derive(Debug, PartialEq)]
struct Arguments {
    input_file: String,
    output_file: String,
    target_arch: TargetArch,
    is_basic: bool,
}

fn build_arg_parser() -> ArgParser<'static> {
    ArgParser::new()
        .arg(
            Argument::new("input-file")
                .required(true)
                .takes_value(true)
                .help("File path of the JSON input."),
        )
        .arg(
            Argument::new("output-file")
                .required(false)
                .takes_value(true)
                .default_value(DEFAULT_OUTPUT_FILENAME)
                .help("Optional path of the output file."),
        )
        .arg(
            Argument::new("target-arch")
                .required(true)
                .takes_value(true)
                .help("The computer architecture where the BPF program runs. Supported architectures: x86_64, aarch64."),
        )
        .arg(
            Argument::new("basic")
                .takes_value(false)
                .help("Deprecated! Transforms the filters into basic filters. Drops all argument checks \
                and rule-level actions. Not recommended."),
        )
}

fn get_argument_values(arguments: &ArgumentsBag) -> Result<Arguments> {
    let arch_string = arguments.single_value("target-arch");
    if arch_string.is_none() {
        return Err(Error::MissingTargetArch);
    }
    let target_arch: TargetArch = arch_string
        .unwrap()
        .as_str()
        .try_into()
        .map_err(Error::Arch)?;

    let input_file = arguments.single_value("input-file");
    if input_file.is_none() {
        return Err(Error::MissingInputFile);
    }

    let is_basic = arguments.flag_present("basic");
    if is_basic {
        println!(
            "Warning! You are using a deprecated parameter: --basic, that will be removed in a \
            future version.\n"
        );
    }

    Ok(Arguments {
        target_arch,
        input_file: input_file.unwrap().to_owned(),
        // Safe to unwrap because it has a default value
        output_file: arguments.single_value("output-file").unwrap().to_owned(),
        is_basic,
    })
}

fn parse_json(reader: &mut dyn Read) -> Result<HashMap<String, Filter>> {
    serde_json::from_reader(reader).map_err(Error::Json)
}

fn compile(args: &Arguments) -> Result<()> {
    let input_file = File::open(&args.input_file)
        .map_err(|err| Error::FileOpen(PathBuf::from(&args.input_file), err))?;
    let mut input_reader = BufReader::new(input_file);
    let filters = parse_json(&mut input_reader)?;
    let compiler = Compiler::new(args.target_arch);

    // transform the IR into a Map of BPFPrograms
    let bpf_data: HashMap<String, BpfProgram> = compiler
        .compile_blob(filters, args.is_basic)
        .map_err(Error::FileFormat)?;

    // serialize the BPF programs & output them to a file
    let output_file = File::create(&args.output_file)
        .map_err(|err| Error::FileOpen(PathBuf::from(&args.output_file), err))?;
    bincode::serialize_into(output_file, &bpf_data).map_err(Error::Bincode)?;

    Ok(())
}

fn main() {
    let mut arg_parser = build_arg_parser();

    if let Err(err) = arg_parser.parse_from_cmdline() {
        eprintln!(
            "Arguments parsing error: {} \n\n\
             For more information try --help.",
            err
        );
        process::exit(EXIT_CODE_ERROR);
    }

    if arg_parser.arguments().flag_present("help") {
        println!("Seccompiler-bin v{}\n", SECCOMPILER_VERSION);
        println!("{}", arg_parser.formatted_help());
        return;
    }
    if arg_parser.arguments().flag_present("version") {
        println!("Seccompiler-bin v{}\n", SECCOMPILER_VERSION);
        return;
    }

    let args = get_argument_values(arg_parser.arguments()).unwrap_or_else(|err| {
        eprintln!(
            "{} \n\n\
            For more information try --help.",
            err
        );
        process::exit(EXIT_CODE_ERROR);
    });

    if let Err(err) = compile(&args) {
        eprintln!("Seccompiler error: {}", err);
        process::exit(EXIT_CODE_ERROR);
    }

    println!("Filter successfully compiled into: {}", args.output_file);
}

#[cfg(test)]
mod tests {
    use super::compiler::{Error as FilterFormatError, Filter, SyscallRule};
    use super::{
        build_arg_parser, compile, get_argument_values, parse_json, Arguments, Error,
        DEFAULT_OUTPUT_FILENAME,
    };
    use crate::backend::SeccompCmpOp::Le;
    use crate::backend::{
        SeccompAction, SeccompCmpArgLen::*, SeccompCmpOp::*, SeccompCondition as Cond, TargetArch,
        TargetArchError,
    };
    use bincode::Error as BincodeError;
    use std::collections::HashMap;
    use std::io;
    use std::io::Write;
    use std::path::PathBuf;
    use utils::tempfile::TempFile;

    // test helper for generating correct JSON input data
    fn get_correct_json_input() -> String {
        r#"
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
                                "arg_index": 2,
                                "arg_type": "dword",
                                "op": "le",
                                "val": 65
                            },
                            {
                                "arg_index": 1,
                                "arg_type": "qword",
                                "op": "ne",
                                "val": 80
                            }
                        ]
                    },
                    {
                        "syscall": "futex",
                        "args": [
                            {
                                "arg_index": 3,
                                "arg_type": "qword",
                                "op": "gt",
                                "val": 65
                            },
                            {
                                "arg_index": 1,
                                "arg_type": "qword",
                                "op": "lt",
                                "val": 80
                            }
                        ]
                    },
                    {
                        "syscall": "futex",
                        "args": [
                            {
                                "arg_index": 3,
                                "arg_type": "qword",
                                "op": "ge",
                                "val": 65
                            }
                        ]
                    },
                    {
                        "syscall": "ioctl",
                        "args": [
                            {
                                "arg_index": 3,
                                "arg_type": "dword",
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
                                "arg_index": 3,
                                "arg_type": "dword",
                                "op": "eq",
                                "val": 65
                            }
                        ]
                    }
                ]
            }
        }
        "#
        .to_string()
    }

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
            .replace("\"", "")
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
            format!("{}", Error::MissingInputFile),
            "Missing input file."
        );
        assert_eq!(
            format!("{}", Error::MissingTargetArch),
            "Missing target arch."
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
    fn test_get_argument_values() {
        let arg_parser = build_arg_parser();
        // correct arguments
        let arguments = &mut arg_parser.arguments().clone();
        arguments
            .parse(
                vec![
                    "seccompiler-bin",
                    "--input-file",
                    "foo.txt",
                    "--target-arch",
                    "x86_64",
                ]
                .into_iter()
                .map(String::from)
                .collect::<Vec<String>>()
                .as_ref(),
            )
            .unwrap();
        assert_eq!(
            get_argument_values(arguments).unwrap(),
            Arguments {
                input_file: "foo.txt".to_string(),
                output_file: DEFAULT_OUTPUT_FILENAME.to_string(),
                target_arch: TargetArch::x86_64,
                is_basic: false,
            }
        );

        let arguments = &mut arg_parser.arguments().clone();
        arguments
            .parse(
                vec![
                    "seccompiler-bin",
                    "--input-file",
                    "foo.txt",
                    "--target-arch",
                    "x86_64",
                    "--output-file",
                    "/path.to/file.txt",
                    "--basic",
                ]
                .into_iter()
                .map(String::from)
                .collect::<Vec<String>>()
                .as_ref(),
            )
            .unwrap();
        assert_eq!(
            get_argument_values(arguments).unwrap(),
            Arguments {
                input_file: "foo.txt".to_string(),
                output_file: "/path.to/file.txt".to_string(),
                target_arch: TargetArch::x86_64,
                is_basic: true
            }
        );

        // no args
        let arguments = &mut arg_parser.arguments().clone();
        assert!(arguments
            .parse(
                vec!["seccompiler-bin"]
                    .into_iter()
                    .map(String::from)
                    .collect::<Vec<String>>()
                    .as_ref(),
            )
            .is_err());

        // missing --target-arch
        let arguments = &mut arg_parser.arguments().clone();
        assert!(arguments
            .parse(
                vec!["seccompiler-bin", "--input-file", "foo.txt"]
                    .into_iter()
                    .map(String::from)
                    .collect::<Vec<String>>()
                    .as_ref(),
            )
            .is_err());

        // missing --input-file
        let arguments = &mut arg_parser.arguments().clone();
        assert!(arguments
            .parse(
                vec!["seccompiler-bin", "--target-arch", "x86_64"]
                    .into_iter()
                    .map(String::from)
                    .collect::<Vec<String>>()
                    .as_ref(),
            )
            .is_err());

        // invalid --target-arch
        let arguments = &mut arg_parser.arguments().clone();
        arguments
            .parse(
                vec![
                    "seccompiler-bin",
                    "--input-file",
                    "foo.txt",
                    "--target-arch",
                    "x86_64das",
                    "--output-file",
                    "/path.to/file.txt",
                ]
                .into_iter()
                .map(String::from)
                .collect::<Vec<String>>()
                .as_ref(),
            )
            .unwrap();
        assert!(get_argument_values(arguments).is_err());

        // invalid value supplied to --basic
        let arguments = &mut arg_parser.arguments().clone();
        assert!(arguments
            .parse(
                vec![
                    "seccompiler-bin",
                    "--input-file",
                    "foo.txt",
                    "--target-arch",
                    "x86_64",
                    "--basic",
                    "invalid",
                ]
                .into_iter()
                .map(String::from)
                .collect::<Vec<String>>()
                .as_ref(),
            )
            .is_err());
    }

    #[allow(clippy::useless_asref)]
    #[test]
    fn test_parse_json() {
        // test with malformed JSON
        {
            // empty file
            let mut json_input = "".to_string();
            let json_input = unsafe { json_input.as_bytes_mut() };

            assert!(parse_json(&mut json_input.as_ref()).is_err());

            // not json
            let mut json_input = "hjkln".to_string();
            let json_input = unsafe { json_input.as_bytes_mut() };

            assert!(parse_json(&mut json_input.as_ref()).is_err());

            // top-level array
            let mut json_input = "[]".to_string();
            let json_input = unsafe { json_input.as_bytes_mut() };

            assert!(parse_json(&mut json_input.as_ref()).is_err());

            // thread key must be a string
            let mut json_input = "{1}".to_string();
            let json_input = unsafe { json_input.as_bytes_mut() };

            assert!(parse_json(&mut json_input.as_ref()).is_err());

            // empty Filter object
            let mut json_input = r#"{"a": {}}"#.to_string();
            let json_input = unsafe { json_input.as_bytes_mut() };

            assert!(parse_json(&mut json_input.as_ref()).is_err());

            // missing 'filter' field
            let mut json_input =
                r#"{"a": {"filter_action": "allow", "default_action":"log"}}"#.to_string();
            let json_input = unsafe { json_input.as_bytes_mut() };
            assert!(parse_json(&mut json_input.as_ref()).is_err());

            // wrong key 'filters'
            let mut json_input =
                r#"{"a": {"filter_action": "allow", "default_action":"log", "filters": []}}"#
                    .to_string();
            let json_input = unsafe { json_input.as_bytes_mut() };
            assert!(parse_json(&mut json_input.as_ref()).is_err());

            // wrong action 'logs'
            let mut json_input =
                r#"{"a": {"filter_action": "allow", "default_action":"logs", "filter": []}}"#
                    .to_string();
            let json_input = unsafe { json_input.as_bytes_mut() };
            assert!(parse_json(&mut json_input.as_ref()).is_err());

            // action that expects a value
            let mut json_input =
                r#"{"a": {"filter_action": "allow", "default_action":"errno", "filter": []}}"#
                    .to_string();
            let json_input = unsafe { json_input.as_bytes_mut() };
            assert!(parse_json(&mut json_input.as_ref()).is_err());

            // overflowing u64 value
            let mut json_input = r#"
            {
                "thread_2": {
                    "default_action": "trap",
                    "filter_action": "allow",
                    "filter": [
                        {
                            "syscall": "ioctl",
                            "args": [
                                {
                                    "arg_index": 3,
                                    "arg_type": "qword",
                                    "op": "eq",
                                    "val": 18446744073709551616
                                }
                            ]
                        }
                    ]
                }
            }
            "#
            .to_string();
            let json_input = unsafe { json_input.as_bytes_mut() };
            assert!(parse_json(&mut json_input.as_ref()).is_err());

            // negative integer value
            let mut json_input = r#"
            {
                "thread_2": {
                    "default_action": "trap",
                    "filter_action": "allow",
                    "filter": [
                        {
                            "syscall": "ioctl",
                            "args": [
                                {
                                    "arg_index": 3,
                                    "arg_type": "qword",
                                    "op": "eq",
                                    "val": -1846
                                }
                            ]
                        }
                    ]
                }
            }
            "#
            .to_string();
            let json_input = unsafe { json_input.as_bytes_mut() };
            assert!(parse_json(&mut json_input.as_ref()).is_err());

            // float value
            let mut json_input = r#"
            {
                "thread_2": {
                    "default_action": "trap",
                    "filter_action": "allow",
                    "filter": [
                        {
                            "syscall": "ioctl",
                            "args": [
                                {
                                    "arg_index": 3,
                                    "arg_type": "qword",
                                    "op": "eq",
                                    "val": 1846.4
                                }
                            ]
                        }
                    ]
                }
            }
            "#
            .to_string();
            let json_input = unsafe { json_input.as_bytes_mut() };
            assert!(parse_json(&mut json_input.as_ref()).is_err());
        }

        // test with correctly formed JSON
        {
            // empty JSON file
            let mut json_input = "{}".to_string();
            let json_input = unsafe { json_input.as_bytes_mut() };

            assert_eq!(parse_json(&mut json_input.as_ref()).unwrap().len(), 0);

            // empty Filter
            let mut json_input =
                r#"{"a": {"filter_action": "allow", "default_action":"log", "filter": []}}"#
                    .to_string();
            let json_input = unsafe { json_input.as_bytes_mut() };
            assert!(parse_json(&mut json_input.as_ref()).is_ok());

            // correctly formed JSON filter
            let mut json_input = get_correct_json_input();
            // safe because we know the string is UTF-8
            let json_input = unsafe { json_input.as_bytes_mut() };

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

            let mut v2: Vec<_> = parse_json(&mut json_input.as_ref())
                .unwrap()
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
            let args = Arguments {
                input_file: in_file.as_path().to_str().unwrap().to_string(),
                target_arch: TargetArch::x86_64,
                output_file: "bpf.out".to_string(),
                is_basic: false,
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

            let mut json_input = get_correct_json_input();
            // safe because we know the string is UTF-8
            let json_input = unsafe { json_input.as_bytes_mut() };
            in_file.as_file().write_all(json_input).unwrap();

            let arguments = Arguments {
                input_file: in_file.as_path().to_str().unwrap().to_string(),
                output_file: out_file.as_path().to_str().unwrap().to_string(),
                target_arch: TargetArch::x86_64,
                is_basic: false,
            };

            // do the compilation & check for errors
            assert!(compile(&arguments).is_ok());

            // also check with is_basic: true
            let arguments = Arguments {
                input_file: in_file.as_path().to_str().unwrap().to_string(),
                output_file: out_file.as_path().to_str().unwrap().to_string(),
                target_arch: TargetArch::x86_64,
                is_basic: true,
            };

            // do the compilation & check for errors
            assert!(compile(&arguments).is_ok());
        }
    }
}
