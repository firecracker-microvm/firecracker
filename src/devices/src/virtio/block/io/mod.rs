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
    pub user_data: T,
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
    pub user_data: T,
    pub error: E,
}

pub enum FileEngine<T> {
    #[allow(unused)]
    Async(AsyncFileEngine<T>),
    Sync(SyncFileEngine),
}

impl<T> FileEngine<T> {
    pub fn from_file_sync(file: File) -> Result<FileEngine<T>, Error> {
        Ok(FileEngine::Sync(SyncFileEngine::from_file(file)))
    }

    #[allow(unused)]
    pub fn from_file_async(file: File) -> Result<FileEngine<T>, Error> {
        Ok(FileEngine::Async(
            AsyncFileEngine::from_file(file).map_err(Error::Async)?,
        ))
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
        user_data: T,
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
        user_data: T,
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

    pub fn flush(&mut self, user_data: T) -> Result<FileEngineOk<T>, UserDataError<T, Error>> {
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
    use std::os::unix::io::FromRawFd;

    use super::*;
    use utils::kernel_version::KernelVersion;
    use utils::tempfile::TempFile;
    use vm_memory::{Bitmap, Bytes, GuestMemory};

    const FILE_LEN: u32 = 1024;
    // 2 pages of memory should be enough to test read/write ops and also dirty tracking.
    const MEM_LEN: usize = 8192;

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

    macro_rules! assert_sync_execution {
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

    macro_rules! assert_queued {
        ($expression:expr) => {
            assert!(matches!($expression, Ok(FileEngineOk::Submitted)))
        };
    }

    fn assert_async_execution(mem: &GuestMemoryMmap, engine: &mut FileEngine<()>, count: u32) {
        if let FileEngine::Async(ref mut engine) = engine {
            engine.kick_submission_queue_and_wait(1).unwrap();
            assert_eq!(engine.pop(mem).unwrap().unwrap().result().unwrap(), count);
        }
    }

    fn create_mem() -> GuestMemoryMmap {
        vm_memory::test_utils::create_anon_guest_memory(&[(GuestAddress(0), MEM_LEN)], true)
            .unwrap()
    }

    fn check_dirty_mem(mem: &GuestMemoryMmap, addr: GuestAddress, len: u32) {
        let bitmap = mem.find_region(addr).unwrap().bitmap().as_ref().unwrap();
        for offset in addr.0..addr.0 + len as u64 {
            assert!(bitmap.dirty_at(offset as usize));
        }
    }

    fn check_clean_mem(mem: &GuestMemoryMmap, addr: GuestAddress, len: u32) {
        let bitmap = mem.find_region(addr).unwrap().bitmap().as_ref().unwrap();
        for offset in addr.0..addr.0 + len as u64 {
            assert!(!bitmap.dirty_at(offset as usize));
        }
    }

    #[test]
    fn test_sync() {
        // Check invalid file
        let mem = create_mem();
        let file = unsafe { File::from_raw_fd(-2) };
        let mut engine = FileEngine::from_file_sync(file).unwrap();
        let res = engine.read(0, &mem, GuestAddress(0), 0, ());
        assert_err!(res, Error::Sync(sync_io::Error::Seek(_e)));
        let res = engine.write(0, &mem, GuestAddress(0), 0, ());
        assert_err!(res, Error::Sync(sync_io::Error::Seek(_e)));
        let res = engine.flush(());
        assert_err!(res, Error::Sync(sync_io::Error::SyncAll(_e)));

        // Create backing file.
        let file = TempFile::new().unwrap().into_file();
        let mut engine = FileEngine::from_file_sync(file).unwrap();

        let data = utils::rand::rand_alphanumerics(FILE_LEN as usize)
            .as_bytes()
            .to_vec();

        // Partial write
        let partial_len = 50;
        let addr = GuestAddress(MEM_LEN as u64 - partial_len);
        mem.write(&data, addr).unwrap();
        assert_sync_execution!(
            engine.write(0, &mem, addr, FILE_LEN, ()),
            partial_len as u32
        );
        // Partial read
        let mem = create_mem();
        assert_sync_execution!(engine.read(0, &mem, addr, FILE_LEN, ()), partial_len as u32);
        // Check data
        let mut buf = vec![0u8; partial_len as usize];
        mem.read_slice(&mut buf, addr).unwrap();
        assert_eq!(buf, data[..partial_len as usize]);

        // Offset write
        let offset = 100;
        let partial_len = 50;
        let addr = GuestAddress(0);
        mem.write(&data, addr).unwrap();
        assert_sync_execution!(
            engine.write(offset, &mem, addr, partial_len, ()),
            partial_len as u32
        );
        // Offset read
        let mem = create_mem();
        assert_sync_execution!(
            engine.read(offset, &mem, addr, partial_len, ()),
            partial_len as u32
        );
        // Check data
        let mut buf = vec![0u8; partial_len as usize];
        mem.read_slice(&mut buf, addr).unwrap();
        assert_eq!(buf, data[..partial_len as usize]);

        // Full write
        mem.write(&data, GuestAddress(0)).unwrap();
        assert_sync_execution!(
            engine.write(0, &mem, GuestAddress(0), FILE_LEN, ()),
            FILE_LEN
        );
        // Full read
        let mem = create_mem();
        assert_sync_execution!(
            engine.read(0, &mem, GuestAddress(0), FILE_LEN, ()),
            FILE_LEN
        );
        // Check data
        let mut buf = vec![0u8; FILE_LEN as usize];
        mem.read_slice(&mut buf, GuestAddress(0)).unwrap();
        assert_eq!(buf, data.as_slice());

        // Check other ops
        assert!(engine.flush(()).is_ok());
        assert!(engine.drain(true).is_ok());
        assert!(engine.drain(false).is_ok());
    }

    #[test]
    fn test_async() {
        if KernelVersion::get().unwrap() < KernelVersion::new(5, 10, 0) {
            return;
        }

        // Check invalid file
        let file = unsafe { File::from_raw_fd(-2) };
        assert!(FileEngine::<()>::from_file_async(file).is_err());

        // Create backing file.
        let file = TempFile::new().unwrap().into_file();
        let mut engine = FileEngine::<()>::from_file_async(file).unwrap();

        let data = utils::rand::rand_alphanumerics(FILE_LEN as usize)
            .as_bytes()
            .to_vec();

        // Partial reads and writes cannot really be tested because io_uring will return an error
        // code for trying to write to unmapped memory.

        // Offset write
        let mem = create_mem();
        let offset = 100;
        let partial_len = 50;
        let addr = GuestAddress(0);
        mem.write(&data, addr).unwrap();
        assert_queued!(engine.write(offset, &mem, addr, partial_len, ()));
        assert_async_execution(&mem, &mut engine, partial_len as u32);
        // Offset read
        let mem = create_mem();
        assert_queued!(engine.read(offset, &mem, addr, partial_len, ()));
        assert_async_execution(&mem, &mut engine, partial_len as u32);
        // Check data
        let mut buf = vec![0u8; partial_len as usize];
        mem.read_slice(&mut buf, addr).unwrap();
        assert_eq!(buf, data[..partial_len as usize]);
        // check dirty mem
        check_dirty_mem(&mem, addr, partial_len);
        check_clean_mem(&mem, GuestAddress(4096), 4096);

        // Full write
        mem.write(&data, GuestAddress(0)).unwrap();
        assert_queued!(engine.write(0, &mem, addr, FILE_LEN, ()));
        assert_async_execution(&mem, &mut engine, FILE_LEN as u32);

        // Full read
        let mem = create_mem();
        assert_queued!(engine.read(0, &mem, addr, FILE_LEN, ()));
        assert_async_execution(&mem, &mut engine, FILE_LEN as u32);
        // Check data
        let mut buf = vec![0u8; FILE_LEN as usize];
        mem.read_slice(&mut buf, GuestAddress(0)).unwrap();
        assert_eq!(buf, data.as_slice());
        // check dirty mem
        check_dirty_mem(&mem, addr, FILE_LEN);
        check_clean_mem(&mem, GuestAddress(4096), 4096);

        // Check other ops
        assert_queued!(engine.flush(()));
        assert_async_execution(&mem, &mut engine, 0);

        assert!(engine.drain(true).is_ok());
        assert!(engine.drain(false).is_ok());
    }
}
