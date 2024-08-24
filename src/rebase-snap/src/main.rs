// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::os::unix::io::AsRawFd;

use utils::arg_parser::{ArgParser, Argument, Arguments, UtilsArgParserError as ArgError};
use vmm_sys_util::seek_hole::SeekHole;

const REBASE_SNAP_VERSION: &str = env!("CARGO_PKG_VERSION");
const BASE_FILE: &str = "base-file";
const DIFF_FILE: &str = "diff-file";
const DEPRECATION_MSG: &str = "This tool is deprecated and will be removed in the future. Please \
                               use 'snapshot-editor' instead.\n";

#[derive(Debug, thiserror::Error, displaydoc::Display)]
enum FileError {
    /// Invalid base file: {0}
    InvalidBaseFile(std::io::Error),
    /// Invalid diff file: {0}
    InvalidDiffFile(std::io::Error),
    /// Failed to seek data: {0}
    SeekData(std::io::Error),
    /// Failed to seek hole: {0}
    SeekHole(std::io::Error),
    /// Failed to seek: {0}
    Seek(std::io::Error),
    /// Failed to send the file: {0}
    SendFile(std::io::Error),
    /// Failed to get metadata: {0}
    Metadata(std::io::Error),
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
enum RebaseSnapError {
    /// Arguments parsing error: {0} \n\nFor more information try --help.
    ArgParse(ArgError),
    /// Error parsing the cmd line args: {0}
    SnapFile(FileError),
    /// Error merging the files: {0}
    RebaseFiles(FileError),
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

fn get_files(args: &Arguments) -> Result<(File, File), FileError> {
    // Safe to unwrap since the required arguments are checked as part of
    // `arg_parser.parse_from_cmdline()`
    let base_file_path = args.single_value(BASE_FILE).unwrap();
    let base_file = OpenOptions::new()
        .write(true)
        .open(base_file_path)
        .map_err(FileError::InvalidBaseFile)?;
    // Safe to unwrap since the required arguments are checked as part of
    // `arg_parser.parse_from_cmdline()`
    let diff_file_path = args.single_value(DIFF_FILE).unwrap();
    let diff_file = OpenOptions::new()
        .read(true)
        .open(diff_file_path)
        .map_err(FileError::InvalidDiffFile)?;

    Ok((base_file, diff_file))
}

fn rebase(base_file: &mut File, diff_file: &mut File) -> Result<(), FileError> {
    let mut cursor: u64 = 0;
    while let Some(block_start) = diff_file.seek_data(cursor).map_err(FileError::SeekData)? {
        cursor = block_start;
        let block_end = match diff_file
            .seek_hole(block_start)
            .map_err(FileError::SeekHole)?
        {
            Some(hole_start) => hole_start,
            None => diff_file.metadata().map_err(FileError::Metadata)?.len(),
        };

        while cursor < block_end {
            base_file
                .seek(SeekFrom::Start(cursor))
                .map_err(FileError::Seek)?;

            // SAFETY: Safe because the parameters are valid.
            let num_transferred_bytes = unsafe {
                libc::sendfile64(
                    base_file.as_raw_fd(),
                    diff_file.as_raw_fd(),
                    (&mut cursor as *mut u64).cast::<i64>(),
                    usize::try_from(block_end.saturating_sub(cursor)).unwrap(),
                )
            };
            if num_transferred_bytes < 0 {
                return Err(FileError::SendFile(std::io::Error::last_os_error()));
            }
        }
    }

    Ok(())
}

fn main() -> Result<(), RebaseSnapError> {
    let result = main_exec();
    if let Err(e) = result {
        eprintln!("{}", e);
        Err(e)
    } else {
        Ok(())
    }
}

fn main_exec() -> Result<(), RebaseSnapError> {
    let mut arg_parser = build_arg_parser();

    arg_parser
        .parse_from_cmdline()
        .map_err(RebaseSnapError::ArgParse)?;
    let arguments = arg_parser.arguments();

    if arguments.flag_present("help") {
        println!("Rebase_snap v{}", REBASE_SNAP_VERSION);
        println!(
            "Tool that copies all the non-sparse sections from a diff file onto a base file.\n"
        );
        println!("{DEPRECATION_MSG}");
        println!("{}", arg_parser.formatted_help());
        return Ok(());
    }
    if arguments.flag_present("version") {
        println!("Rebase_snap v{REBASE_SNAP_VERSION}\n{DEPRECATION_MSG}");
        return Ok(());
    }

    println!("{DEPRECATION_MSG}");
    let (mut base_file, mut diff_file) = get_files(arguments).map_err(RebaseSnapError::SnapFile)?;

    rebase(&mut base_file, &mut diff_file).map_err(RebaseSnapError::RebaseFiles)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom, Write};
    use std::os::unix::fs::FileExt;

    use vmm_sys_util::{rand, tempfile};

    use super::*;

    macro_rules! assert_err {
        ($expression:expr, $($pattern:tt)+) => {
            match $expression {
                Err($($pattern)+) => (),
                ref err =>  {
                    println!("expected `{}` but got `{:?}`", stringify!($($pattern)+), err);
                    assert!(false)
                }
            }
        }
    }

    #[test]
    fn test_parse_args() {
        let base_file = tempfile::TempFile::new().unwrap();
        let base_file_path = base_file.as_path().to_str().unwrap().to_string();
        let diff_file = tempfile::TempFile::new().unwrap();
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
        assert_err!(get_files(arguments), FileError::InvalidBaseFile(_));

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
        assert_err!(get_files(arguments), FileError::InvalidDiffFile(_));

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
        get_files(arguments).unwrap();
    }

    fn check_file_content(file: &mut File, expected_content: &[u8]) {
        let mut buf = vec![0u8; expected_content.len()];
        file.read_exact_at(buf.as_mut_slice(), 0).unwrap();
        assert_eq!(&buf, expected_content);
    }

    #[test]
    fn test_rebase_corner_cases() {
        let mut base_file = tempfile::TempFile::new().unwrap().into_file();
        let mut diff_file = tempfile::TempFile::new().unwrap().into_file();

        // 1. Empty files
        rebase(&mut base_file, &mut diff_file).unwrap();
        assert_eq!(base_file.metadata().unwrap().len(), 0);

        let initial_base_file_content = rand::rand_alphanumerics(50000).into_string().unwrap();
        base_file
            .write_all(initial_base_file_content.as_bytes())
            .unwrap();

        // 2. Diff file that has only holes
        diff_file
            .set_len(initial_base_file_content.len() as u64)
            .unwrap();
        rebase(&mut base_file, &mut diff_file).unwrap();
        check_file_content(&mut base_file, initial_base_file_content.as_bytes());

        // 3. Diff file that has only data
        let diff_data = rand::rand_alphanumerics(50000).into_string().unwrap();
        diff_file.write_all(diff_data.as_bytes()).unwrap();
        rebase(&mut base_file, &mut diff_file).unwrap();
        check_file_content(&mut base_file, diff_data.as_bytes());
    }

    #[test]
    fn test_rebase() {
        // The filesystem punches holes only for blocks >= 4096.
        // It doesn't make sense to test for smaller ones.
        let block_sizes: &[usize] = &[4096, 8192];
        for &block_size in block_sizes {
            let mut expected_result = vec![];
            let mut base_file = tempfile::TempFile::new().unwrap().into_file();
            let mut diff_file = tempfile::TempFile::new().unwrap().into_file();

            // 1. Populated block both in base and diff file
            let base_block = rand::rand_alphanumerics(block_size).into_string().unwrap();
            base_file.write_all(base_block.as_bytes()).unwrap();
            let diff_block = rand::rand_alphanumerics(block_size).into_string().unwrap();
            diff_file.write_all(diff_block.as_bytes()).unwrap();
            expected_result.append(&mut diff_block.into_bytes());

            // 2. Populated block in base file, hole in diff file
            let base_block = rand::rand_alphanumerics(block_size).into_string().unwrap();
            base_file.write_all(base_block.as_bytes()).unwrap();
            diff_file
                .seek(SeekFrom::Current(i64::try_from(block_size).unwrap()))
                .unwrap();
            expected_result.append(&mut base_block.into_bytes());

            // 3. Populated block in base file, zeroes block in diff file
            let base_block = rand::rand_alphanumerics(block_size).into_string().unwrap();
            base_file.write_all(base_block.as_bytes()).unwrap();
            let mut diff_block = vec![0u8; block_size];
            diff_file.write_all(&diff_block).unwrap();
            expected_result.append(&mut diff_block);

            // Rebase and check the result
            rebase(&mut base_file, &mut diff_file).unwrap();
            check_file_content(&mut base_file, &expected_result);

            // 4. The diff file is bigger
            let diff_block = rand::rand_alphanumerics(block_size).into_string().unwrap();
            diff_file.write_all(diff_block.as_bytes()).unwrap();
            expected_result.append(&mut diff_block.into_bytes());
            // Rebase and check the result
            rebase(&mut base_file, &mut diff_file).unwrap();
            check_file_content(&mut base_file, &expected_result);

            // 5. The base file is bigger
            let base_block = rand::rand_alphanumerics(block_size).into_string().unwrap();
            base_file.write_all(base_block.as_bytes()).unwrap();
            expected_result.append(&mut base_block.into_bytes());
            // Rebase and check the result
            rebase(&mut base_file, &mut diff_file).unwrap();
            check_file_content(&mut base_file, &expected_result);
        }
    }
}
