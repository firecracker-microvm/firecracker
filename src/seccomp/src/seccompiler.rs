// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod compiler;
mod syscall_table;

use bincode::Error as BincodeError;
use compiler::{Compiler, Error as FilterFormatError, Filter};
use seccomp::{BpfThreadMap, TargetArch, TargetArchError};
use serde_json::error::Error as JSONError;
use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt;
use std::fs::File;
use std::io;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::process;
use utils::arg_parser::{ArgParser, Argument, Arguments as ArgumentsBag};

const SECCOMPILER_VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_OUTPUT_FILENAME: &str = "seccomp_binary_filter.out";

#[derive(Debug)]
pub enum Error {
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

    Ok(Arguments {
        target_arch,
        input_file: input_file.unwrap().to_owned(),
        // Safe to unwrap because it has a default value
        output_file: arguments.single_value("output-file").unwrap().to_owned(),
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
    let bpf_data: BpfThreadMap = compiler.compile_blob(filters).map_err(Error::FileFormat)?;

    // serialize the BPF programs & output them to a file
    let output_file = File::create(&args.output_file)
        .map_err(|err| Error::FileOpen(PathBuf::from(&args.output_file), err))?;
    bincode::serialize_into(output_file, &bpf_data).map_err(Error::Bincode)?;

    Ok(())
}

fn main() {
    let mut arg_parser = build_arg_parser();

    if let Err(err) = arg_parser.parse_from_cmdline() {
        println!(
            "Arguments parsing error: {} \n\n\
             For more information try --help.",
            err
        );
        process::exit(1);
    }

    if arg_parser.arguments().flag_present("help") {
        println!("Seccompiler v{}\n", SECCOMPILER_VERSION);
        println!("{}", arg_parser.formatted_help());
        process::exit(0);
    }
    if arg_parser.arguments().flag_present("version") {
        println!("Seccompiler v{}\n", SECCOMPILER_VERSION);
        process::exit(0);
    }

    let args = get_argument_values(arg_parser.arguments()).unwrap_or_else(|err| {
        println!(
            "{} \n\n\
            For more information try --help.",
            err
        );
        process::exit(1);
    });

    compile(&args).expect("Seccompiler error");

    println!("Filter successfully compiled into: {}", args.output_file);
}

#[cfg(test)]
mod tests {
    use super::compiler::{Compiler, Error as FilterFormatError, Filter, SyscallRule};
    use super::{
        build_arg_parser, compile, get_argument_values, parse_json, Arguments, BpfThreadMap, Error,
        DEFAULT_OUTPUT_FILENAME,
    };
    use bincode::Error as BincodeError;
    use seccomp::{
        SeccompAction, SeccompCmpArgLen::*, SeccompCmpOp::*, SeccompCondition as Cond, TargetArch,
        TargetArchError,
    };
    use std::collections::HashMap;
    use std::io;
    use std::io::{Read, Write};
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
                        "syscall": "open",
                        "action": "log"
                    },
                    {
                        "syscall": "close",
                        "action": "trap"
                    },
                    {
                        "syscall": "stat",
                        "action": "trap"
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
                        "action": "log",
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
                    "seccompiler",
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
            }
        );

        let arguments = &mut arg_parser.arguments().clone();
        arguments
            .parse(
                vec![
                    "seccompiler",
                    "--input-file",
                    "foo.txt",
                    "--target-arch",
                    "x86_64",
                    "--output-file",
                    "/path.to/file.txt",
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
            }
        );

        // no args
        let arguments = &mut arg_parser.arguments().clone();
        assert!(arguments
            .parse(
                vec!["seccompiler"]
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
                vec!["seccompiler", "--input-file", "foo.txt"]
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
                vec!["seccompiler", "--target-arch", "x86_64"]
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
                    "seccompiler",
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
    }

    #[allow(clippy::useless_asref)]
    #[test]
    fn test_parse_json() {
        // test with malformed JSON
        {
            let mut json_input = r#"hjkln"#.to_string();
            // safe because we know the string is UTF-8
            let json_input = unsafe { json_input.as_bytes_mut() };

            assert!(parse_json(&mut json_input.as_ref()).is_err());
        }

        // test with correctly formed JSON
        {
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
                        SyscallRule::new("open".to_string(), Some(SeccompAction::Log), None),
                        SyscallRule::new("close".to_string(), Some(SeccompAction::Trap), None),
                        SyscallRule::new("stat".to_string(), Some(SeccompAction::Trap), None),
                        SyscallRule::new(
                            "futex".to_string(),
                            None,
                            Some(vec![
                                Cond::new(2, DWORD, Le, 65).unwrap(),
                                Cond::new(1, QWORD, Ne, 80).unwrap(),
                            ]),
                        ),
                        SyscallRule::new(
                            "futex".to_string(),
                            Some(SeccompAction::Log),
                            Some(vec![
                                Cond::new(3, QWORD, Gt, 65).unwrap(),
                                Cond::new(1, QWORD, Lt, 80).unwrap(),
                            ]),
                        ),
                        SyscallRule::new(
                            "futex".to_string(),
                            None,
                            Some(vec![Cond::new(3, QWORD, Ge, 65).unwrap()]),
                        ),
                        SyscallRule::new(
                            "ioctl".to_string(),
                            None,
                            Some(vec![Cond::new(3, DWORD, MaskedEq(100), 65).unwrap()]),
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
                        None,
                        Some(vec![Cond::new(3, DWORD, Eq, 65).unwrap()]),
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
            };

            // do the compilation & serialization
            compile(&arguments).unwrap();

            // get the serialized data from the file
            let mut result = Vec::new();
            out_file.as_file().read_to_end(&mut result).unwrap();

            // simulate the compilation
            let compiler = Compiler::new(arguments.target_arch);
            let filters = parse_json(&mut json_input.as_ref()).unwrap();
            let bpf_data: BpfThreadMap = compiler.compile_blob(filters).unwrap();

            // deserialize and compare
            assert_eq!(
                bincode::deserialize::<BpfThreadMap>(&result).unwrap(),
                bpf_data
            );
        }
    }
}
