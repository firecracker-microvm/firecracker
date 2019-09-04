// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Auxiliary module for flushing some input to a named PIPE (FIFO).

use libc::O_NONBLOCK;
use std::fs::{File, OpenOptions};
use std::io::{LineWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::result;

type Result<T> = result::Result<T, std::io::Error>;

/// Structure `PipeLogWriter` used for writing to a FIFO in a thread-safe way.
pub struct PipeLogWriter {
    line_writer: LineWriter<File>,
}

impl PipeLogWriter {
    pub fn new(fifo_path: &str) -> Result<PipeLogWriter> {
        let fifo = PathBuf::from(fifo_path);
        match OpenOptions::new()
            .custom_flags(O_NONBLOCK)
            .read(true)
            .write(true)
            .open(&fifo)
        {
            Ok(t) => Ok(PipeLogWriter {
                line_writer: LineWriter::new(t),
            }),
            Err(e) => Err(e),
        }
    }
}

impl Write for PipeLogWriter {
    fn write(&mut self, msg: &[u8]) -> Result<(usize)> {
        self.line_writer.write_all(msg).map(|()| msg.len())
    }

    fn flush(&mut self) -> Result<()> {
        self.line_writer.flush()
    }
}

#[cfg(test)]
mod tests {
    extern crate tempfile;

    use self::tempfile::NamedTempFile;
    use super::*;

    #[test]
    fn test_new() {
        let log_file_temp =
            NamedTempFile::new().expect("Failed to create temporary output logging file.");
        let good_file = String::from(log_file_temp.path().to_path_buf().to_str().unwrap());
        let res = PipeLogWriter::new(&good_file);
        assert!(res.is_ok());
    }

    #[test]
    fn test_write_trait() {
        let log_file_temp =
            NamedTempFile::new().expect("Failed to create temporary output logging file.");
        let file = String::from(log_file_temp.path().to_path_buf().to_str().unwrap());

        let mut fw = PipeLogWriter::new(&file).unwrap();
        let msg = String::from("some message");
        assert!(fw.write(&msg.as_bytes()).is_ok());
        assert!(fw.flush().is_ok());
    }
}
