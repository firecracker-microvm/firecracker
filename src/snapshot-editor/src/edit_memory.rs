// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::path::PathBuf;

use clap::Subcommand;
use vmm::utils::u64_to_usize;
use vmm_sys_util::seek_hole::SeekHole;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum EditMemoryError {
    /// Could not open memory file: {0}
    OpenMemoryFile(std::io::Error),
    /// Could not open diff file: {0}
    OpenDiffFile(std::io::Error),
    /// Failed to seek data in diff file: {0}
    SeekDataDiff(std::io::Error),
    /// Failed to seek hole in diff file: {0}
    SeekHoleDiff(std::io::Error),
    /// Failed to get metadata for diff file: {0}
    MetadataDiff(std::io::Error),
    /// Failed to seek in memory file: {0}
    SeekMemory(std::io::Error),
    /// Failed to send the file: {0}
    SendFile(std::io::Error),
}

#[derive(Debug, Subcommand)]
pub enum EditMemorySubCommand {
    /// Apply a diff snapshot on top of a base one
    Rebase {
        /// Path to the memory file.
        #[arg(short, long)]
        memory_path: PathBuf,
        /// Path to the diff file.
        #[arg(short, long)]
        diff_path: PathBuf,
    },
}

pub fn edit_memory_command(command: EditMemorySubCommand) -> Result<(), EditMemoryError> {
    match command {
        EditMemorySubCommand::Rebase {
            memory_path,
            diff_path,
        } => rebase(memory_path, diff_path)?,
    }
    Ok(())
}

fn rebase(memory_path: PathBuf, diff_path: PathBuf) -> Result<(), EditMemoryError> {
    let mut base_file = OpenOptions::new()
        .write(true)
        .open(memory_path)
        .map_err(EditMemoryError::OpenMemoryFile)?;

    let mut diff_file = OpenOptions::new()
        .read(true)
        .open(diff_path)
        .map_err(EditMemoryError::OpenDiffFile)?;

    let mut cursor: u64 = 0;
    while let Some(block_start) = diff_file
        .seek_data(cursor)
        .map_err(EditMemoryError::SeekDataDiff)?
    {
        cursor = block_start;
        let block_end = match diff_file
            .seek_hole(block_start)
            .map_err(EditMemoryError::SeekHoleDiff)?
        {
            Some(hole_start) => hole_start,
            None => diff_file
                .metadata()
                .map_err(EditMemoryError::MetadataDiff)?
                .len(),
        };

        while cursor < block_end {
            base_file
                .seek(SeekFrom::Start(cursor))
                .map_err(EditMemoryError::SeekMemory)?;

            // SAFETY: Safe because the parameters are valid.
            let num_transferred_bytes = unsafe {
                libc::sendfile64(
                    base_file.as_raw_fd(),
                    diff_file.as_raw_fd(),
                    (&mut cursor as *mut u64).cast::<i64>(),
                    u64_to_usize(block_end.saturating_sub(cursor)),
                )
            };
            if num_transferred_bytes < 0 {
                return Err(EditMemoryError::SendFile(std::io::Error::last_os_error()));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{Seek, SeekFrom, Write};
    use std::os::unix::fs::FileExt;

    use vmm_sys_util::{rand, tempfile};

    use super::*;

    fn check_file_content(file: &File, expected_content: &[u8]) {
        assert_eq!(
            file.metadata().unwrap().len(),
            expected_content.len() as u64
        );
        let mut buf = vec![0u8; expected_content.len()];
        file.read_exact_at(buf.as_mut_slice(), 0).unwrap();
        assert_eq!(&buf, expected_content);
    }

    #[test]
    fn test_rebase_empty_files() {
        let base = tempfile::TempFile::new().unwrap();
        let diff = tempfile::TempFile::new().unwrap();

        let base_file = base.as_file();

        let base_path = base.as_path().to_path_buf();
        let diff_path = diff.as_path().to_path_buf();

        // Empty files
        rebase(base_path, diff_path).unwrap();
        assert_eq!(base_file.metadata().unwrap().len(), 0);
    }

    #[test]
    fn test_rebase_empty_diff() {
        let base = tempfile::TempFile::new().unwrap();
        let diff = tempfile::TempFile::new().unwrap();

        let mut base_file = base.as_file();
        let diff_file = diff.as_file();

        let base_path = base.as_path().to_path_buf();
        let diff_path = diff.as_path().to_path_buf();

        let initial_base_file_content = rand::rand_bytes(50000);
        base_file.write_all(&initial_base_file_content).unwrap();

        // Diff file that has only holes
        diff_file
            .set_len(initial_base_file_content.len() as u64)
            .unwrap();
        rebase(base_path, diff_path).unwrap();
        check_file_content(base_file, &initial_base_file_content);
    }

    #[test]
    fn test_rebase_full_diff() {
        let base = tempfile::TempFile::new().unwrap();
        let diff = tempfile::TempFile::new().unwrap();

        let base_file = base.as_file();
        let mut diff_file = diff.as_file();

        let base_path = base.as_path().to_path_buf();
        let diff_path = diff.as_path().to_path_buf();

        // Diff file that has only data
        let diff_data = rand::rand_bytes(50000);
        diff_file.write_all(&diff_data).unwrap();
        rebase(base_path, diff_path).unwrap();
        check_file_content(base_file, &diff_data);
    }

    #[test]
    fn test_rebase() {
        // The filesystem punches holes only for blocks >= 4096.
        // It doesn't make sense to test for smaller ones.
        let block_sizes: &[usize] = &[4096, 8192];
        for &block_size in block_sizes {
            let mut expected_result = vec![];

            let base = tempfile::TempFile::new().unwrap();
            let diff = tempfile::TempFile::new().unwrap();

            let mut base_file = base.as_file();
            let mut diff_file = diff.as_file();

            let base_path = base.as_path().to_path_buf();
            let diff_path = diff.as_path().to_path_buf();

            // 1. Populated block both in base and diff file
            // block:     [ ]
            // diff:      [ ]
            // expected:  [d]
            let base_block = rand::rand_bytes(block_size);
            base_file.write_all(&base_block).unwrap();
            let diff_block = rand::rand_bytes(block_size);
            diff_file.write_all(&diff_block).unwrap();
            expected_result.extend(diff_block);

            // 2. Populated block in base file, hole in diff file
            // block:     [ ] [ ]
            // diff:      [ ] ___
            // expected:  [d] [b]
            let base_block = rand::rand_bytes(block_size);
            base_file.write_all(&base_block).unwrap();
            diff_file
                .seek(SeekFrom::Current(i64::try_from(block_size).unwrap()))
                .unwrap();
            expected_result.extend(base_block);

            // 3. Populated block in base file, zeroes block in diff file
            // block:     [ ] [ ] [ ]
            // diff:      [ ] ___ [0]
            // expected:  [d] [b] [d]
            let base_block = rand::rand_bytes(block_size);
            base_file.write_all(&base_block).unwrap();
            let diff_block = vec![0u8; block_size];
            diff_file.write_all(&diff_block).unwrap();
            expected_result.extend(diff_block);

            // Rebase and check the result
            rebase(base_path.clone(), diff_path.clone()).unwrap();
            check_file_content(base_file, &expected_result);

            // 4. The diff file is bigger
            // block:     [ ] [ ] [ ]
            // diff:      [ ] ___ [0] [ ]
            // expected:  [d] [b] [d] [d]
            let diff_block = rand::rand_bytes(block_size);
            diff_file.write_all(&diff_block).unwrap();
            expected_result.extend(diff_block);
            // Rebase and check the result
            rebase(base_path.clone(), diff_path.clone()).unwrap();
            check_file_content(base_file, &expected_result);

            // 5. The base file is bigger
            // block:     [ ] [ ] [ ] [ ] [ ]
            // diff:      [ ] ___ [0] [ ]
            // expected:  [d] [b] [d] [d] [b]
            let base_block = rand::rand_bytes(block_size);
            // Adding to the base file 2 times because
            // it is 1 block smaller then diff right now.
            base_file.write_all(&base_block).unwrap();
            base_file.write_all(&base_block).unwrap();
            expected_result.extend(base_block);
            // Rebase and check the result
            rebase(base_path, diff_path).unwrap();
            check_file_content(base_file, &expected_result);
        }
    }
}
