// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Auxiliary module for flushing some input to a named PIPE (FIFO).

use libc::O_NONBLOCK;
use std::fs::{File, OpenOptions};
use std::io::{LineWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::result;
use std::sync::{Mutex, MutexGuard};

use error::LoggerError;

type Result<T> = result::Result<T, LoggerError>;

/// Structure `PipeLogWriter` used for writing to a file in a thread-safe way.
#[derive(Debug)]
pub struct PipeLogWriter {
    line_writer: Mutex<LineWriter<File>>,
}

impl PipeLogWriter {
    pub fn new(fifo_path: &String) -> Result<PipeLogWriter> {
        let fifo = PathBuf::from(fifo_path);
        match OpenOptions::new()
            .custom_flags(O_NONBLOCK)
            .read(true)
            .write(true)
            .open(&fifo)
        {
            Ok(t) => Ok(PipeLogWriter {
                line_writer: Mutex::new(LineWriter::new(t)),
            }),
            Err(e) => return Err(LoggerError::OpenFIFO(e)),
        }
    }

    pub fn write(&self, msg: &String) -> Result<()> {
        let mut line_writer = self.get_line_writer()?;
        line_writer
            .write_all(msg.as_bytes())
            .map_err(|e| LoggerError::LogWrite(e))
    }

    fn get_line_writer(&self) -> Result<(MutexGuard<LineWriter<File>>)> {
        self.line_writer
            .lock()
            .map_err(|e| LoggerError::MutexLockFailure(format!("{}", e)))
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
        assert!(res.is_ok())
    }

    #[test]
    fn test_write() {
        let log_file_temp =
            NamedTempFile::new().expect("Failed to create temporary output logging file.");
        let file = String::from(log_file_temp.path().to_path_buf().to_str().unwrap());

        let fw = PipeLogWriter::new(&file).unwrap();
        let msg = String::from("some message");
        let res = fw.write(&msg);
        assert!(res.is_ok())
    }
}
