
use crc64::crc64;
use std::io::{Read, Write};

pub(crate) struct CRC64Reader<T> {
    reader: T,
    crc64: u64
}

impl<T> CRC64Reader<T> where T: Read {
    pub fn new(reader: T) -> Self {
        CRC64Reader { crc64: 0, reader }
    }
    
    pub fn checksum(&self) -> u64 { self.crc64 }
}

impl<T> Read for CRC64Reader<T> where T: Read {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let bytes_read = self.reader.read(buf)?;
        self.crc64 = crc64(self.crc64, &buf[..bytes_read]);
        Ok(bytes_read)
    }
}

pub(crate) struct CRC64Writer<T> {
    writer: T,
    crc64: u64
}

impl<T> CRC64Writer<T> where T: Write {
    pub fn new(writer: T) -> Self {
        CRC64Writer { crc64: 0, writer }
    }
    
    pub fn checksum(&self) -> u64 { self.crc64 }
}

impl<T> Write for CRC64Writer<T> where T: Write {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize>{
        let bytes_written = self.writer.write(buf)?;
        self.crc64 = crc64(self.crc64, &buf[..bytes_written]);
        Ok(bytes_written)
    }
    
    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

mod tests {
    use super::*;
    
    #[test]
    fn test_crc_read() {
        let buf = vec![1, 2, 3, 4, 5];
        let mut read_buf = vec![0; 16];

        let mut slice = buf.as_slice();
        let mut crc_reader = CRC64Reader::new(&mut slice);
        crc_reader.read_to_end(&mut read_buf).unwrap();
        assert_eq!(crc_reader.checksum(), 0xFB0460DE06383654);
    }

    #[test]
    fn test_crc_init() {
        let buf = vec![1, 2, 3, 4, 5];
        let mut slice = buf.as_slice();
        let crc_reader = CRC64Reader::new(&mut slice);
        assert_eq!(crc_reader.checksum(), 0);
    }

    #[test]
    fn test_crc_write() {
        let mut buf = vec![0; 16];
        let write_buf = vec![123; 16];

        let mut slice = buf.as_mut_slice();
        let mut crc_writer = CRC64Writer::new(&mut slice);
        crc_writer.write_all(&mut write_buf.as_slice()).unwrap();
        crc_writer.flush().unwrap();
        assert_eq!(crc_writer.checksum(), 0x29D5357216326566);
    }
}