// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod async_io;
pub mod sync_io;

use std::fmt::Debug;
use std::fs::File;

use utils::vm_memory::{GuestAddress, GuestMemoryMmap};

pub use self::async_io::{AsyncFileEngine, AsyncIoError};
pub use self::sync_io::{SyncFileEngine, SyncIoError};
use crate::devices::virtio::block::device::FileEngineType;

#[derive(Debug, PartialEq, Eq)]
pub struct UserDataOk<T> {
    pub user_data: T,
    pub count: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FileEngineOk<T> {
    Submitted,
    Executed(UserDataOk<T>),
}

#[derive(Debug)]
pub enum BlockIoError {
    Sync(SyncIoError),
    Async(AsyncIoError),
    UnsupportedEngine(FileEngineType),
    GetKernelVersion(utils::kernel_version::Error),
}

impl BlockIoError {
    pub fn is_throttling_err(&self) -> bool {
        match self {
            BlockIoError::Async(AsyncIoError::IoUring(err)) => err.is_throttling_err(),
            _ => false,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct UserDataError<T, E> {
    pub user_data: T,
    pub error: E,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum FileEngine<T> {
    #[allow(unused)]
    Async(AsyncFileEngine<T>),
    Sync(SyncFileEngine),
}

impl<T: Debug> FileEngine<T> {
    pub fn from_file(
        file: File,
        engine_type: FileEngineType,
    ) -> Result<FileEngine<T>, BlockIoError> {
        if !engine_type
            .is_supported()
            .map_err(BlockIoError::GetKernelVersion)?
        {
            return Err(BlockIoError::UnsupportedEngine(engine_type));
        }
        match engine_type {
            FileEngineType::Async => Ok(FileEngine::Async(
                AsyncFileEngine::from_file(file).map_err(BlockIoError::Async)?,
            )),
            FileEngineType::Sync => Ok(FileEngine::Sync(SyncFileEngine::from_file(file))),
        }
    }

    #[cfg(test)]
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
    ) -> Result<FileEngineOk<T>, UserDataError<T, BlockIoError>> {
        match self {
            FileEngine::Async(engine) => {
                match engine.push_read(offset, mem, addr, count, user_data) {
                    Ok(_) => Ok(FileEngineOk::Submitted),
                    Err(err) => Err(UserDataError {
                        user_data: err.user_data,
                        error: BlockIoError::Async(err.error),
                    }),
                }
            }
            FileEngine::Sync(engine) => match engine.read(offset, mem, addr, count) {
                Ok(count) => Ok(FileEngineOk::Executed(UserDataOk { user_data, count })),
                Err(err) => Err(UserDataError {
                    user_data,
                    error: BlockIoError::Sync(err),
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
    ) -> Result<FileEngineOk<T>, UserDataError<T, BlockIoError>> {
        match self {
            FileEngine::Async(engine) => {
                match engine.push_write(offset, mem, addr, count, user_data) {
                    Ok(_) => Ok(FileEngineOk::Submitted),
                    Err(err) => Err(UserDataError {
                        user_data: err.user_data,
                        error: BlockIoError::Async(err.error),
                    }),
                }
            }
            FileEngine::Sync(engine) => match engine.write(offset, mem, addr, count) {
                Ok(count) => Ok(FileEngineOk::Executed(UserDataOk { user_data, count })),
                Err(err) => Err(UserDataError {
                    user_data,
                    error: BlockIoError::Sync(err),
                }),
            },
        }
    }

    pub fn flush(
        &mut self,
        user_data: T,
    ) -> Result<FileEngineOk<T>, UserDataError<T, BlockIoError>> {
        match self {
            FileEngine::Async(engine) => match engine.push_flush(user_data) {
                Ok(_) => Ok(FileEngineOk::Submitted),
                Err(err) => Err(UserDataError {
                    user_data: err.user_data,
                    error: BlockIoError::Async(err.error),
                }),
            },
            FileEngine::Sync(engine) => match engine.flush() {
                Ok(_) => Ok(FileEngineOk::Executed(UserDataOk {
                    user_data,
                    count: 0,
                })),
                Err(err) => Err(UserDataError {
                    user_data,
                    error: BlockIoError::Sync(err),
                }),
            },
        }
    }

    pub fn drain(&mut self, discard: bool) -> Result<(), BlockIoError> {
        match self {
            FileEngine::Async(engine) => engine.drain(discard).map_err(BlockIoError::Async),
            FileEngine::Sync(_engine) => Ok(()),
        }
    }

    pub fn drain_and_flush(&mut self, discard: bool) -> Result<(), BlockIoError> {
        match self {
            FileEngine::Async(engine) => {
                engine.drain_and_flush(discard).map_err(BlockIoError::Async)
            }
            FileEngine::Sync(engine) => engine.flush().map_err(BlockIoError::Sync),
        }
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::FromRawFd;

    use utils::kernel_version::{min_kernel_version_for_io_uring, KernelVersion};
    use utils::tempfile::TempFile;
    use utils::vm_memory::{Bitmap, Bytes, GuestMemory};
    use utils::{skip_if_io_uring_supported, skip_if_io_uring_unsupported};

    use super::*;
    use crate::devices::virtio::block::device::FileEngineType;
    use crate::devices::virtio::block::request::PendingRequest;

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
                ref err => {
                    panic!("expected `{}` but got `{:?}`", stringify!($($pattern)+), err);
                }
            }
        };
    }

    macro_rules! assert_sync_execution {
        ($expression:expr, $count:expr) => {
            match $expression {
                Ok(FileEngineOk::Executed(UserDataOk {
                    user_data: _,
                    count,
                })) => assert_eq!(count, $count),
                other => panic!(
                    "Expected: Ok(FileEngineOk::Executed(UserDataOk {{ user_data: _, count: {} \
                     }})), got: {:?}",
                    $count, other
                ),
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
            engine.drain(false).unwrap();
            assert_eq!(engine.pop(mem).unwrap().unwrap().result().unwrap(), count);
        }
    }

    fn create_mem() -> GuestMemoryMmap {
        utils::vm_memory::test_utils::create_anon_guest_memory(&[(GuestAddress(0), MEM_LEN)], true)
            .unwrap()
    }

    fn check_dirty_mem(mem: &GuestMemoryMmap, addr: GuestAddress, len: u32) {
        let bitmap = mem.find_region(addr).unwrap().bitmap().as_ref().unwrap();
        for offset in addr.0..addr.0 + u64::from(len) {
            assert!(bitmap.dirty_at(offset as usize));
        }
    }

    fn check_clean_mem(mem: &GuestMemoryMmap, addr: GuestAddress, len: u32) {
        let bitmap = mem.find_region(addr).unwrap().bitmap().as_ref().unwrap();
        for offset in addr.0..addr.0 + u64::from(len) {
            assert!(!bitmap.dirty_at(offset as usize));
        }
    }

    #[test]
    fn test_unsupported_engine_type() {
        skip_if_io_uring_supported!();

        assert!(matches!(
            FileEngine::<PendingRequest>::from_file(
                TempFile::new().unwrap().into_file(),
                FileEngineType::Async
            ),
            Err(BlockIoError::UnsupportedEngine(FileEngineType::Async))
        ));
    }

    #[test]
    fn test_sync() {
        // Check invalid file
        let mem = create_mem();
        let file = unsafe { File::from_raw_fd(-2) };
        let mut engine = FileEngine::from_file(file, FileEngineType::Sync).unwrap();
        let res = engine.read(0, &mem, GuestAddress(0), 0, ());
        assert_err!(res, BlockIoError::Sync(sync_io::SyncIoError::Seek(_e)));
        let res = engine.write(0, &mem, GuestAddress(0), 0, ());
        assert_err!(res, BlockIoError::Sync(sync_io::SyncIoError::Seek(_e)));
        let res = engine.flush(());
        assert_err!(res, BlockIoError::Sync(sync_io::SyncIoError::SyncAll(_e)));

        // Create backing file.
        let file = TempFile::new().unwrap().into_file();
        let mut engine = FileEngine::from_file(file, FileEngineType::Sync).unwrap();

        let data = utils::rand::rand_alphanumerics(FILE_LEN as usize)
            .as_bytes()
            .to_vec();

        // Partial write
        let partial_len = 50;
        let addr = GuestAddress(MEM_LEN as u64 - partial_len);
        mem.write(&data, addr).unwrap();
        assert_sync_execution!(
            engine.write(0, &mem, addr, partial_len as u32, ()),
            partial_len as u32
        );
        // Partial read
        let mem = create_mem();
        assert_sync_execution!(
            engine.read(0, &mem, addr, partial_len as u32, ()),
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
        assert_sync_execution!(
            engine.write(offset, &mem, addr, partial_len, ()),
            partial_len
        );
        // Offset read
        let mem = create_mem();
        assert_sync_execution!(
            engine.read(offset, &mem, addr, partial_len, ()),
            partial_len
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
        assert!(engine.drain_and_flush(true).is_ok());
    }

    #[test]
    fn test_async() {
        skip_if_io_uring_unsupported!();

        // Check invalid file
        let file = unsafe { File::from_raw_fd(-2) };
        assert!(FileEngine::<()>::from_file(file, FileEngineType::Async).is_err());

        // Create backing file.
        let file = TempFile::new().unwrap().into_file();
        let mut engine = FileEngine::<()>::from_file(file, FileEngineType::Async).unwrap();

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
        assert_async_execution(&mem, &mut engine, partial_len);
        // Offset read
        let mem = create_mem();
        assert_queued!(engine.read(offset, &mem, addr, partial_len, ()));
        assert_async_execution(&mem, &mut engine, partial_len);
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
        assert_async_execution(&mem, &mut engine, FILE_LEN);

        // Full read
        let mem = create_mem();
        assert_queued!(engine.read(0, &mem, addr, FILE_LEN, ()));
        assert_async_execution(&mem, &mut engine, FILE_LEN);
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
        assert!(engine.drain_and_flush(true).is_ok());
    }
}
