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

use std::collections::BTreeMap;
use std::convert::TryInto;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

mod backend;
mod common;
mod compiler;
mod syscall_table;

use backend::{TargetArch, TargetArchError};
use bincode::Error as BincodeError;
use common::BpfProgram;
use compiler::{CompilationError, Compiler, JsonFile};
use serde_json::error::Error as JSONError;
use utils::arg_parser::{ArgParser, Argument, Arguments as ArgumentsBag, Error as ArgParserError};

const SECCOMPILER_VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_OUTPUT_FILENAME: &str = "seccomp_binary_filter.out";

#[derive(Debug, thiserror::Error)]
enum SeccompError {
    #[error("Bincode (de)serialization failed: {0}")]
    Bincode(BincodeError),
    #[error("{0}")]
    Compilation(CompilationError),
    #[error("{}", format!("Failed to open file {:?}: {1}", .0, .1).replace('\"', ""))]
    FileOpen(PathBuf, std::io::Error),
    #[error("Error parsing JSON: {0}")]
    Json(JSONError),
    #[error("Missing input file.")]
    MissingInputFile,
    #[error("Missing target arch.")]
    MissingTargetArch,
    #[error("{0}")]
    Arch(#[from] TargetArchError),
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
                .help(
                    "The computer architecture where the BPF program runs. Supported \
                     architectures: x86_64, aarch64.",
                ),
        )
        .arg(Argument::new("basic").takes_value(false).help(
            "Deprecated! Transforms the filters into basic filters. Drops all argument checks and \
             rule-level actions. Not recommended.",
        ))
}

fn get_argument_values(arguments: &ArgumentsBag) -> Result<Arguments, SeccompError> {
    let arch_string = arguments.single_value("target-arch");
    if arch_string.is_none() {
        return Err(SeccompError::MissingTargetArch);
    }
    let target_arch: TargetArch = arch_string.unwrap().as_str().try_into()?;

    let input_file = arguments.single_value("input-file");
    if input_file.is_none() {
        return Err(SeccompError::MissingInputFile);
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

fn compile(args: &Arguments) -> Result<(), SeccompError> {
    let input_file = File::open(&args.input_file)
        .map_err(|err| SeccompError::FileOpen(PathBuf::from(&args.input_file), err))?;
    let mut input_reader = BufReader::new(input_file);
    let filters =
        serde_json::from_reader::<_, JsonFile>(&mut input_reader).map_err(SeccompError::Json)?;
    let compiler = Compiler::new(args.target_arch);

    // transform the IR into a Map of BPFPrograms
    let bpf_data: BTreeMap<String, BpfProgram> = compiler
        .compile_blob(filters.0, args.is_basic)
        .map_err(SeccompError::Compilation)?;

    // serialize the BPF programs & output them to a file
    let output_file = File::create(&args.output_file)
        .map_err(|err| SeccompError::FileOpen(PathBuf::from(&args.output_file), err))?;
    bincode::serialize_into(output_file, &bpf_data).map_err(SeccompError::Bincode)?;

    Ok(())
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
enum SeccompilerError {
    /// Argument Parsing Error: {0}
    ArgParsing(ArgParserError),
    /// {0} \n\nFor more information try --help.
    InvalidArgumentValue(SeccompError),
    /// {0}
    Error(SeccompError),
}

fn main() -> core::result::Result<(), SeccompilerError> {
    let result = main_exec();
    if let Err(e) = result {
        eprintln!("{}", e);
        Err(e)
    } else {
        Ok(())
    }
}

fn main_exec() -> core::result::Result<(), SeccompilerError> {
    let mut arg_parser = build_arg_parser();

    arg_parser
        .parse_from_cmdline()
        .map_err(SeccompilerError::ArgParsing)?;

    if arg_parser.arguments().flag_present("help") {
        println!("Seccompiler-bin v{}\n", SECCOMPILER_VERSION);
        println!("{}", arg_parser.formatted_help());
        return Ok(());
    }
    if arg_parser.arguments().flag_present("version") {
        println!("Seccompiler-bin v{}\n", SECCOMPILER_VERSION);
        return Ok(());
    }

    let args = get_argument_values(arg_parser.arguments())
        .map_err(SeccompilerError::InvalidArgumentValue)?;

    compile(&args).map_err(SeccompilerError::Error)?;

    println!("Filter successfully compiled into: {}", args.output_file);
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]

    use std::io;
    use std::io::Write;
    use std::path::PathBuf;

    use bincode::Error as BincodeError;
    use utils::tempfile::TempFile;

    use super::compiler::CompilationError as FilterFormatError;
    use super::{
        build_arg_parser, compile, get_argument_values, Arguments, SeccompError,
        DEFAULT_OUTPUT_FILENAME,
    };
    use crate::backend::{TargetArch, TargetArchError};

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
                SeccompError::Bincode(BincodeError::new(bincode::ErrorKind::SizeLimit))
            ),
            format!(
                "Bincode (de)serialization failed: {}",
                BincodeError::new(bincode::ErrorKind::SizeLimit)
            )
        );
        assert_eq!(
            format!(
                "{}",
                SeccompError::Compilation(FilterFormatError::SyscallName(
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
                SeccompError::FileOpen(path.clone(), io::Error::from_raw_os_error(2))
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
                SeccompError::Json(serde_json::from_str::<serde_json::Value>("").unwrap_err())
            ),
            format!(
                "Error parsing JSON: {}",
                serde_json::from_str::<serde_json::Value>("").unwrap_err()
            )
        );
        assert_eq!(
            format!("{}", SeccompError::MissingInputFile),
            "Missing input file."
        );
        assert_eq!(
            format!("{}", SeccompError::MissingTargetArch),
            "Missing target arch."
        );
        assert_eq!(
            format!(
                "{}",
                SeccompError::Arch(TargetArchError::InvalidString("lala".to_string()))
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
                SeccompError::FileOpen(buf, _) => assert_eq!(buf, PathBuf::from(in_file.as_path())),
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
