// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod async_io;
pub mod sync_io;

pub use self::async_io::AsyncFileEngine;
pub use self::sync_io::SyncFileEngine;
use std::fs::File;
use vm_memory::{GuestAddress, GuestMemoryMmap};

#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct UserDataOk<T> {
    pub user_data: Box<T>,
    pub count: u32,
}

#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum FileEngineOk<T> {
    Submitted,
    Executed(UserDataOk<T>),
}

#[derive(Debug)]
pub enum Error {
    Sync(sync_io::Error),
    Async(async_io::Error),
}

#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct UserDataError<T, E> {
    pub user_data: Box<T>,
    pub error: E,
}

pub enum FileEngine<T> {
    #[allow(unused)]
    Async(AsyncFileEngine<T>),
    Sync(SyncFileEngine),
}

impl<T> FileEngine<T> {
    pub fn from_file(file: File) -> std::io::Result<FileEngine<T>> {
        Ok(FileEngine::Sync(SyncFileEngine::from_file(file)))
    }

    pub fn file(&self) -> &File {
        match self {
            FileEngine::Async(engine) => engine.file(),
            FileEngine::Sync(engine) => engine.file(),
        }
    }

    pub fn read(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
        user_data: Box<T>,
    ) -> Result<FileEngineOk<T>, UserDataError<T, Error>> {
        match self {
            FileEngine::Async(engine) => {
                match engine.push_read(offset, mem, addr, count, user_data) {
                    Ok(_) => Ok(FileEngineOk::Submitted),
                    Err(e) => Err(UserDataError {
                        user_data: e.user_data,
                        error: Error::Async(e.error),
                    }),
                }
            }
            FileEngine::Sync(engine) => match engine.read(offset, mem, addr, count) {
                Ok(count) => Ok(FileEngineOk::Executed(UserDataOk { user_data, count })),
                Err(e) => Err(UserDataError {
                    user_data,
                    error: Error::Sync(e),
                }),
            },
        }
    }

    pub fn write(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
        user_data: Box<T>,
    ) -> Result<FileEngineOk<T>, UserDataError<T, Error>> {
        match self {
            FileEngine::Async(engine) => {
                match engine.push_write(offset, mem, addr, count, user_data) {
                    Ok(_) => Ok(FileEngineOk::Submitted),
                    Err(e) => Err(UserDataError {
                        user_data: e.user_data,
                        error: Error::Async(e.error),
                    }),
                }
            }
            FileEngine::Sync(engine) => match engine.write(offset, mem, addr, count) {
                Ok(count) => Ok(FileEngineOk::Executed(UserDataOk { user_data, count })),
                Err(e) => Err(UserDataError {
                    user_data,
                    error: Error::Sync(e),
                }),
            },
        }
    }

    pub fn flush(&mut self, user_data: Box<T>) -> Result<FileEngineOk<T>, UserDataError<T, Error>> {
        match self {
            FileEngine::Async(engine) => match engine.push_flush(user_data) {
                Ok(_) => Ok(FileEngineOk::Submitted),
                Err(e) => Err(UserDataError {
                    user_data: e.user_data,
                    error: Error::Async(e.error),
                }),
            },
            FileEngine::Sync(engine) => match engine.flush() {
                Ok(_) => Ok(FileEngineOk::Executed(UserDataOk {
                    user_data,
                    count: 0,
                })),
                Err(e) => Err(UserDataError {
                    user_data,
                    error: Error::Sync(e),
                }),
            },
        }
    }

    pub fn drain(&mut self, flush: bool) -> Result<(), Error> {
        match self {
            FileEngine::Async(engine) => engine.drain(flush).map_err(Error::Async),
            FileEngine::Sync(engine) => {
                if !flush {
                    return Ok(());
                }
                engine.flush().map_err(Error::Sync)
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use std::os::unix::ffi::OsStrExt;

    use super::*;
    use std::os::unix::io::FromRawFd;
    use utils::tempfile::TempFile;
    use vm_memory::{Bytes, GuestMemory, GuestMemoryRegion, MemoryRegionAddress};

    const FILE_LEN: u32 = 1024;
    const MEM_LEN: usize = 4096;

    macro_rules! assert_err {
        ($expression:expr, $($pattern:tt)+) => {
            match $expression {
                Err(UserDataError {
                    user_data: _,
                    error: $($pattern)+,
                }) => (),
                ref e => {
                    println!("expected `{}` but got `{:?}`", stringify!($($pattern)+), e);
                    assert!(false)
                }
            }
        };
    }

    macro_rules! assert_executed {
        ($expression:expr, $count:expr) => {
            if let Ok(FileEngineOk::Executed(UserDataOk {
                user_data: _,
                count,
            })) = $expression
            {
                assert_eq!(count, $count);
            } else {
                println!("expected Ok, received Err");
                assert!(false);
            }
        };
    }

    fn clear_mem(mem: &GuestMemoryMmap) {
        for region in mem.iter() {
            let empty_data = vec![0u8; region.len() as usize];
            region
                .write_slice(&empty_data, MemoryRegionAddress(0))
                .unwrap();
        }
    }

    #[test]
    fn test_sync() {
        // Create guest memory
        let mem =
            vm_memory::test_utils::create_anon_guest_memory(&[(GuestAddress(0), MEM_LEN)], false)
                .unwrap();

        // Check invalid file
        let file = unsafe { File::from_raw_fd(-2) };
        let mut engine = FileEngine::from_file(file).unwrap();
        let res = engine.read(0, &mem, GuestAddress(0), 0, Box::new(()));
        assert_err!(res, Error::Sync(sync_io::Error::Seek(_e)));
        let res = engine.write(0, &mem, GuestAddress(0), 0, Box::new(()));
        assert_err!(res, Error::Sync(sync_io::Error::Seek(_e)));
        let res = engine.flush(Box::new(()));
        assert_err!(res, Error::Sync(sync_io::Error::SyncAll(_e)));

        // Create backing file.
        let file = TempFile::new().unwrap().into_file();
        let mut engine = FileEngine::from_file(file).unwrap();

        let data = utils::rand::rand_alphanumerics(FILE_LEN as usize)
            .as_bytes()
            .to_vec();

        // Partial write
        let partial_len = 50;
        let addr = GuestAddress(MEM_LEN as u64 - partial_len);
        mem.write(&data, addr).unwrap();
        assert_executed!(
            engine.write(0, &mem, addr, FILE_LEN, Box::new(())),
            partial_len as u32
        );
        // Partial read
        clear_mem(&mem);
        assert_executed!(
            engine.read(0, &mem, addr, FILE_LEN, Box::new(())),
            partial_len as u32
        );
        // Check data
        let mut buf = vec![0u8; partial_len as usize];
        mem.read_slice(&mut buf, addr).unwrap();
        assert_eq!(buf, data[..partial_len as usize]);

        // Offset write
        let offset = 100;
        let partial_len = 50;
        let addr = GuestAddress(0);
        mem.write(&data, addr).unwrap();
        assert_executed!(
            engine.write(offset, &mem, addr, partial_len, Box::new(())),
            partial_len as u32
        );
        // Offset read
        clear_mem(&mem);
        assert_executed!(
            engine.read(offset, &mem, addr, partial_len, Box::new(())),
            partial_len as u32
        );
        // Check data
        let mut buf = vec![0u8; partial_len as usize];
        mem.read_slice(&mut buf, addr).unwrap();
        assert_eq!(buf, data[..partial_len as usize]);

        // Full write
        mem.write(&data, GuestAddress(0)).unwrap();
        assert_executed!(
            engine.write(0, &mem, GuestAddress(0), FILE_LEN, Box::new(())),
            FILE_LEN
        );
        // Full read
        clear_mem(&mem);
        assert_executed!(
            engine.read(0, &mem, GuestAddress(0), FILE_LEN, Box::new(())),
            FILE_LEN
        );
        // Check data
        let mut buf = vec![0u8; FILE_LEN as usize];
        mem.read_slice(&mut buf, GuestAddress(0)).unwrap();
        assert_eq!(buf, data.as_slice());

        // Check other ops
        assert!(engine.flush(Box::new(())).is_ok());
        assert!(engine.drain(true).is_ok());
        assert!(engine.drain(false).is_ok());
    }

    #[test]
    fn test_async() {
        // Create guest memory
        let mem =
            vm_memory::test_utils::create_anon_guest_memory(&[(GuestAddress(0), MEM_LEN)], false)
                .unwrap();

        // Create backing file.
        let file = TempFile::new().unwrap().into_file();
        let mut engine = FileEngine::Async(AsyncFileEngine::from_file(file).unwrap());

        // All ops should return an Error
        let addr = GuestAddress(0);
        let res = engine.write(0, &mem, addr, FILE_LEN, Box::new(()));
        assert_err!(res, Error::Async(async_io::Error::OpNotImplemented));
        let res = engine.read(0, &mem, addr, FILE_LEN, Box::new(()));
        assert_err!(res, Error::Async(async_io::Error::OpNotImplemented));
        let res = engine.flush(Box::new(()));
        assert_err!(res, Error::Async(async_io::Error::OpNotImplemented));
        assert!(engine.drain(true).is_err());
        assert!(engine.drain(false).is_err());

        if let FileEngine::Async(mut engine) = engine {
            assert!(engine.kick_submission_queue().is_err());
            assert!(engine.pop().is_none());
        }
    }
}
