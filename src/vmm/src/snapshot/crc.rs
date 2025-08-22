// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Implements readers and writers that compute the CRC64 checksum of the bytes
//! read/written.

use std::io::Write;

use crc64::crc64;

/// Computes the CRC64 checksum of the written bytes.
///
/// ```
/// use std::io::Write;
///
/// use vmm::snapshot::crc::CRC64Writer;
///
/// let mut buf = vec![0; 16];
/// let write_buf = vec![123; 16];
/// let mut slice = buf.as_mut_slice();
///
/// // Create a new writer from slice.
/// let mut crc_writer = CRC64Writer::new(&mut slice);
///
/// crc_writer.write_all(&write_buf.as_slice()).unwrap();
/// assert_eq!(crc_writer.checksum(), 0x29D5_3572_1632_6566);
/// assert_eq!(write_buf, buf);
/// ```
#[derive(Debug)]
pub struct CRC64Writer<T> {
    /// The underlying raw writer. Using this directly will bypass CRC computation!
    pub writer: T,
    crc64: u64,
}

impl<T> CRC64Writer<T>
where
    T: Write,
{
    /// Create a new writer.
    pub fn new(writer: T) -> Self {
        CRC64Writer { crc64: 0, writer }
    }

    /// Returns the current checksum value.
    pub fn checksum(&self) -> u64 {
        self.crc64
    }
}

impl<T> Write for CRC64Writer<T>
where
    T: Write,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let bytes_written = self.writer.write(buf)?;
        self.crc64 = crc64(self.crc64, &buf[..bytes_written]);
        Ok(bytes_written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::{CRC64Writer, Write};

    #[test]
    fn test_crc_new() {
        let mut buf = vec![0; 5];
        let mut slice = buf.as_mut_slice();
        let crc_writer = CRC64Writer::new(&mut slice);
        assert_eq!(crc_writer.crc64, 0);
        assert_eq!(crc_writer.writer, &[0; 5]);
        assert_eq!(crc_writer.checksum(), 0);
    }

    #[test]
    fn test_crc_write() {
        let mut buf = vec![0; 16];
        let write_buf = vec![123; 16];

        let mut slice = buf.as_mut_slice();
        let mut crc_writer = CRC64Writer::new(&mut slice);
        crc_writer.write_all(write_buf.as_slice()).unwrap();
        crc_writer.flush().unwrap();
        assert_eq!(crc_writer.checksum(), 0x29D5_3572_1632_6566);
        assert_eq!(crc_writer.checksum(), crc_writer.crc64);
    }
}
