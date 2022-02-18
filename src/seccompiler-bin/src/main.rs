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

use std::collections::HashMap;
use std::convert::TryInto;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::{fmt, io, process};

use bincode::Error as BincodeError;
use seccompiler::{compile_from_json, Error as SeccompilerError, TargetArch};
use utils::arg_parser::{ArgParser, Argument, Arguments as ArgumentsBag};
use utils::seccomp::sock_filter;

const SECCOMPILER_VERSION: &str = env!("FIRECRACKER_VERSION");
const DEFAULT_OUTPUT_FILENAME: &str = "seccomp_binary_filter.out";
const EXIT_CODE_ERROR: i32 = 1;

#[derive(Debug)]
enum Error {
    Bincode(BincodeError),
    FileOpen(PathBuf, io::Error),
    MissingInputFile,
    MissingTargetArch,
    Seccompiler(SeccompilerError),
}

type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match *self {
            Bincode(ref err) => write!(f, "Bincode (de)serialization failed: {}", err),
            FileOpen(ref path, ref err) => write!(
                f,
                "{}",
                format!("Failed to open file {:?}: {}", path, err).replace("\"", "")
            ),
            MissingInputFile => write!(f, "Missing input file."),
            MissingTargetArch => write!(f, "Missing target arch."),
            Seccompiler(ref err) => write!(f, "Seccompiler error: {}", err),
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
        .map_err(|e| Error::Seccompiler(SeccompilerError::Backend(e)))?;

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

fn compile(args: &Arguments) -> Result<()> {
    let input_file = File::open(&args.input_file)
        .map_err(|err| Error::FileOpen(PathBuf::from(&args.input_file), err))?;
    let input_reader = BufReader::new(input_file);

    // transform the IR into a Map of BPFPrograms
    let bpf_data: HashMap<String, Vec<sock_filter>> =
        compile_from_json(input_reader, args.target_arch)
            .map_err(Error::Seccompiler)?
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().map(|i| i.into()).collect()))
            .collect();

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
    use super::{
        build_arg_parser, compile, get_argument_values, Arguments, Error, DEFAULT_OUTPUT_FILENAME,
    };
    use bincode::Error as BincodeError;
    use seccompiler::{Error as SeccompilerError, TargetArch};
    use std::io;
    use std::io::Write;
    use std::path::PathBuf;
    use utils::tempfile::TempFile;

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
            format!("{}", Error::MissingInputFile),
            "Missing input file."
        );
        assert_eq!(
            format!("{}", Error::MissingTargetArch),
            "Missing target arch."
        );
        assert_eq!(
            format!("{}", Error::Seccompiler(SeccompilerError::EmptyFilter)),
            format!("Seccompiler error: {}", SeccompilerError::EmptyFilter)
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

        // Invalid JSON.
        {
            let in_file = TempFile::new().unwrap();
            let out_file = TempFile::new().unwrap();

            let mut json_input = r#"invalid"#.to_string();
            // safe because we know the string is UTF-8
            let json_input = unsafe { json_input.as_bytes_mut() };
            in_file.as_file().write_all(json_input).unwrap();

            let arguments = Arguments {
                input_file: in_file.as_path().to_str().unwrap().to_string(),
                output_file: out_file.as_path().to_str().unwrap().to_string(),
                target_arch: TargetArch::x86_64,
            };

            // do the compilation & check for errors
            assert!(compile(&arguments).is_err());
        }

        // test a successful compilation
        {
            let in_file = TempFile::new().unwrap();
            let out_file = TempFile::new().unwrap();

            let mut json_input = r#"
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
            "#
            .to_string();
            // safe because we know the string is UTF-8
            let json_input = unsafe { json_input.as_bytes_mut() };
            in_file.as_file().write_all(json_input).unwrap();

            let arguments = Arguments {
                input_file: in_file.as_path().to_str().unwrap().to_string(),
                output_file: out_file.as_path().to_str().unwrap().to_string(),
                target_arch: TargetArch::x86_64,
            };

            // do the compilation & check for errors
            // assert!(compile(&arguments).is_ok());
            compile(&arguments).unwrap();
        }
    }
}
