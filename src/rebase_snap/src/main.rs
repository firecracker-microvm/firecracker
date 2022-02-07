// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::cmp::min;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::{env, process};

use utils::arg_parser::{ArgParser, Argument, Arguments};
use vmm_sys_util::seek_hole::SeekHole;

const REBASE_SNAP_VERSION: &str = env!("FIRECRACKER_VERSION");
const EXIT_CODE_SUCCESS: i32 = 0;
const BASE_FILE: &str = "base-file";
const DIFF_FILE: &str = "diff-file";
const CHUNK_SIZE: usize = 4096;

#[derive(Debug)]
enum Error {
    InvalidBaseFile(std::io::Error),
    InvalidDiffFile(std::io::Error),
    SeekData(std::io::Error),
    SeekHole(std::io::Error),
    Read(std::io::Error),
    Write(std::io::Error),
    Metadata(std::io::Error),
}

fn build_arg_parser<'a>() -> ArgParser<'a> {
    let arg_parser = ArgParser::new()
        .arg(
            Argument::new(BASE_FILE)
                .required(true)
                .takes_value(true)
                .help("File path of the base mem snapshot."),
        )
        .arg(
            Argument::new(DIFF_FILE)
                .required(true)
                .takes_value(true)
                .help("File path of the diff mem snapshot."),
        );

    arg_parser
}

fn extract_args<'a>(arg_parser: &'a mut ArgParser<'a>) -> &'a Arguments<'a> {
    arg_parser.parse_from_cmdline().unwrap_or_else(|e| {
        panic!(
            "Arguments parsing error: {} \n\n\
             For more information try --help.",
            e
        );
    });

    if arg_parser.arguments().flag_present("help") {
        println!("Rebase_snap v{}\n", REBASE_SNAP_VERSION);
        println!("{}", arg_parser.formatted_help());
        process::exit(EXIT_CODE_SUCCESS);
    }
    if arg_parser.arguments().flag_present("version") {
        println!("Rebase_snap v{}\n", REBASE_SNAP_VERSION);
        process::exit(EXIT_CODE_SUCCESS);
    }

    arg_parser.arguments()
}

fn parse_args(args: &Arguments) -> Result<(File, File), Error> {
    // Safe to unwrap since the required arguments are checked as part of
    // `arg_parser.parse_from_cmdline()`
    let base_file_path = args.single_value(BASE_FILE).unwrap();
    let base_file = OpenOptions::new()
        .write(true)
        .open(base_file_path)
        .map_err(Error::InvalidBaseFile)?;
    // Safe to unwrap since the required arguments are checked as part of
    // `arg_parser.parse_from_cmdline()`
    let diff_file_path = args.single_value(DIFF_FILE).unwrap();
    let diff_file = OpenOptions::new()
        .read(true)
        .open(diff_file_path)
        .map_err(Error::InvalidDiffFile)?;

    Ok((base_file, diff_file))
}

fn rebase(base_file: &File, diff_file: &mut File) -> Result<(), Error> {
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut cursor: u64 = 0;
    while let Some(block_start) = diff_file.seek_data(cursor).map_err(Error::SeekData)? {
        cursor = block_start;
        let block_end = match diff_file.seek_hole(block_start).map_err(Error::SeekHole)? {
            Some(hole_start) => hole_start,
            None => diff_file.metadata().map_err(Error::Metadata)?.len(),
        };
        while cursor < block_end {
            let data_len = block_end.saturating_sub(cursor);
            let chunk_len = min(data_len, CHUNK_SIZE as u64);
            let chunk = &mut buf[..chunk_len as usize];
            diff_file
                .read_exact_at(chunk, cursor)
                .map_err(Error::Read)?;
            base_file
                .write_all_at(chunk, cursor)
                .map_err(Error::Write)?;

            cursor += chunk_len;
        }
    }

    Ok(())
}

fn main() {
    let mut arg_parser = build_arg_parser();
    let args = extract_args(&mut arg_parser);
    let (base_file, mut diff_file) =
        parse_args(args).unwrap_or_else(|e| panic!("Error parsing the cmd line args: {:?}", e));

    rebase(&base_file, &mut diff_file)
        .unwrap_or_else(|e| panic!("Error merging the files: {:?}", e));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};

    macro_rules! assert_err {
        ($expression:expr, $($pattern:tt)+) => {
            match $expression {
                Err($($pattern)+) => (),
                ref e =>  {
                    println!("expected `{}` but got `{:?}`", stringify!($($pattern)+), e);
                    assert!(false)
                }
            }
        }
    }

    #[test]
    fn test_parse_args() {
        let base_file = vmm_sys_util::tempfile::TempFile::new().unwrap();
        let base_file_path = base_file.as_path().to_str().unwrap().to_string();
        let diff_file = vmm_sys_util::tempfile::TempFile::new().unwrap();
        let diff_file_path = diff_file.as_path().to_str().unwrap().to_string();

        let arg_parser = build_arg_parser();
        let arguments = &mut arg_parser.arguments().clone();
        arguments
            .parse(
                vec![
                    "rebase_snap",
                    "--base-file",
                    "wrong_file",
                    "--diff-file",
                    "diff_file",
                ]
                .into_iter()
                .map(String::from)
                .collect::<Vec<String>>()
                .as_ref(),
            )
            .unwrap();
        assert_err!(parse_args(arguments), Error::InvalidBaseFile(_));

        let arguments = &mut arg_parser.arguments().clone();
        arguments
            .parse(
                vec![
                    "rebase_snap",
                    "--base-file",
                    &base_file_path,
                    "--diff-file",
                    "diff_file",
                ]
                .into_iter()
                .map(String::from)
                .collect::<Vec<String>>()
                .as_ref(),
            )
            .unwrap();
        assert_err!(parse_args(arguments), Error::InvalidDiffFile(_));

        let arguments = &mut arg_parser.arguments().clone();
        arguments
            .parse(
                vec![
                    "rebase_snap",
                    "--base-file",
                    &base_file_path,
                    "--diff-file",
                    &diff_file_path,
                ]
                .into_iter()
                .map(String::from)
                .collect::<Vec<String>>()
                .as_ref(),
            )
            .unwrap();
        assert!(parse_args(arguments).is_ok());
    }

    #[test]
    fn test_rebase() {
        // The filesystem punches holes only for blocks >= 4096.
        // It doesn't make sense to test for smaller ones.
        let block_sizes: &[usize] = &[4096, 8192];
        for &block_size in block_sizes {
            let mut expected_result = vec![];
            let base_file = vmm_sys_util::tempfile::TempFile::new().unwrap();
            let diff_file = vmm_sys_util::tempfile::TempFile::new().unwrap();

            // 1. Populated block both in base and diff file
            let base_block = vmm_sys_util::rand::rand_alphanumerics(block_size)
                .into_string()
                .unwrap();
            base_file
                .as_file()
                .write_all(base_block.as_bytes())
                .unwrap();
            let mut diff_block = vmm_sys_util::rand::rand_alphanumerics(block_size)
                .into_string()
                .unwrap();
            diff_file
                .as_file()
                .write_all(diff_block.as_bytes())
                .unwrap();
            expected_result.append(unsafe { diff_block.as_mut_vec() });

            // 2. Populated block in base file, hole in diff file
            let mut base_block = vmm_sys_util::rand::rand_alphanumerics(block_size)
                .into_string()
                .unwrap();
            base_file
                .as_file()
                .write_all(base_block.as_bytes())
                .unwrap();
            diff_file
                .as_file()
                .seek(SeekFrom::Current(block_size as i64))
                .unwrap();
            expected_result.append(unsafe { base_block.as_mut_vec() });

            // 3. Populated block in base file, zeroes block in diff file
            let base_block = vmm_sys_util::rand::rand_alphanumerics(block_size)
                .into_string()
                .unwrap();
            base_file
                .as_file()
                .write_all(base_block.as_bytes())
                .unwrap();
            let mut diff_block = vec![0u8; block_size];
            diff_file.as_file().write_all(&diff_block).unwrap();
            expected_result.append(&mut diff_block);

            // Rebase and check the result
            rebase(base_file.as_file(), &mut diff_file.into_file()).unwrap();
            let mut actual_result = vec![0u8; expected_result.len()];
            base_file
                .as_file()
                .read_exact_at(actual_result.as_mut_slice(), 0)
                .unwrap();
            assert_eq!(actual_result, expected_result);
        }
    }
}
