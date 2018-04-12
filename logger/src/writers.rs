use error::LoggerError;
use std::fs::File;
use std::io::{LineWriter, Write};
use std::path::Path;
use std::result;
use std::sync::{Mutex, MutexGuard};

pub type Result<T> = result::Result<T, LoggerError>;

/// Structure `FileLogWriter` used for writing to a file in a thread-safe way.
#[derive(Debug)]
pub struct FileLogWriter {
    line_writer: Mutex<LineWriter<File>>,
}

impl FileLogWriter {
    pub fn new(log_path: &String) -> Result<FileLogWriter> {
        let p_file = Path::new(&log_path);
        if Path::new(log_path).exists() {
            eprintln!(
                "Log file {} already exists. Overwriting its contents...",
                log_path
            );
        }
        match File::create(&p_file) {
            Ok(t) => Ok(FileLogWriter {
                line_writer: Mutex::new(LineWriter::new(t)),
            }),
            Err(e) => return Err(LoggerError::CreateLogFile(e)),
        }
    }

    pub fn write(&self, msg: &String) -> Result<()> {
        let mut line_writer = self.get_line_writer()?;
        line_writer
            .write_all(msg.as_bytes())
            .map_err(|e| LoggerError::FileLogWrite(e))
    }

    pub fn flush(&self) -> Result<()> {
        let mut line_writer = self.get_line_writer()?;
        line_writer
            .flush()
            .map_err(|e| LoggerError::FileLogFlush(e))
    }

    fn get_line_writer(&self) -> Result<(MutexGuard<LineWriter<File>>)> {
        self.line_writer
            .lock()
            .map_err(|e| LoggerError::FileLogLock(format!("{}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::remove_file;

    #[test]
    fn test_new() {
        let mut file: String = "./inexistent/tmp.log".to_string();
        assert!(FileLogWriter::new(&file).is_err());
        format!("{:?}", FileLogWriter::new(&file));
        file = "tmp_writers_new.log".to_string();
        let res = FileLogWriter::new(&file);
        format!("{:?}", res);
        remove_file(file).unwrap();
        assert!(res.is_ok())
    }

    #[test]
    fn test_write() {
        let file: String = "tmp_writers_write.log".to_string();
        let fw = FileLogWriter::new(&file).unwrap();
        let msg = String::from("some message");
        let res = fw.write(&msg);
        remove_file(file).unwrap();
        assert!(res.is_ok())
    }

    #[test]
    fn test_flush() {
        let file: String = "tmp_writers_flush.log".to_string();
        let fw = FileLogWriter::new(&file).unwrap();
        let res = fw.flush();
        remove_file(file).unwrap();
        assert!(res.is_ok())
    }
}
