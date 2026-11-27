// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod async_io;
pub mod format;
pub mod sync_io;

use std::fmt::Debug;
use std::fs::File;

pub use self::async_io::{AsyncFileEngine, AsyncIoError};
pub use self::format::{DiskImageFormat, VmdkFileEngine, VmdkIoError};
pub use self::sync_io::{SyncFileEngine, SyncIoError};
pub(super) use self::vectored::DataSegment;
use crate::devices::virtio::block::virtio::device::FileEngineType;
use crate::devices::virtio::block::virtio::{MAX_VECTORED_BYTES, PendingRequest};
use crate::vstate::memory::{GuestAddress, GuestMemoryMmap};

#[derive(Debug)]
pub struct RequestOk {
    pub req: PendingRequest,
    pub count: u32,
}

#[derive(Debug)]
pub enum FileEngineOk {
    Submitted,
    Executed(RequestOk),
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum BlockIoError {
    /// Sync error: {0}
    Sync(SyncIoError),
    /// Async error: {0}
    Async(AsyncIoError),
    /// Direct I/O backing: {0}
    Direct(std::io::Error),
    /// VMDK error: {0}
    Vmdk(VmdkIoError),
    /// Vectored request exceeds the host I/O limit
    VectorTooLarge,
}

impl BlockIoError {
    pub fn is_throttling_err(&self) -> bool {
        match self {
            BlockIoError::Async(AsyncIoError::IoUring(err)) => err.is_throttling_err(),
            BlockIoError::Async(AsyncIoError::BounceInFlight) => true,
            _ => false,
        }
    }
}

#[derive(Debug)]
pub struct RequestError<E> {
    pub req: PendingRequest,
    pub error: E,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum FileEngine {
    #[allow(unused)]
    Async(AsyncFileEngine),
    Sync(SyncFileEngine),
    Vmdk(VmdkFileEngine),
}

impl From<&FileEngine> for DiskImageFormat {
    fn from(engine: &FileEngine) -> Self {
        match engine {
            FileEngine::Vmdk(_) => DiskImageFormat::Vmdk,
            FileEngine::Async(_) | FileEngine::Sync(_) => DiskImageFormat::Raw,
        }
    }
}

impl FileEngine {
    pub fn from_file(file: File, engine_type: FileEngineType) -> Result<FileEngine, BlockIoError> {
        Self::new(file, engine_type, None)
    }

    /// Construct a raw engine using a backing opened with O_DIRECT.
    pub fn from_direct_file(
        file: File,
        engine_type: FileEngineType,
        disk_size: u64,
    ) -> Result<Self, BlockIoError> {
        let direct = direct::DirectIo::probe(&file, disk_size).map_err(BlockIoError::Direct)?;
        Self::new(file, engine_type, Some(direct))
    }

    fn new(
        file: File,
        engine_type: FileEngineType,
        direct: Option<direct::DirectIo>,
    ) -> Result<Self, BlockIoError> {
        match engine_type {
            FileEngineType::Async => Ok(Self::Async(
                AsyncFileEngine::from_file(file, direct).map_err(BlockIoError::Async)?,
            )),
            FileEngineType::Sync => Ok(Self::Sync(SyncFileEngine::from_file(file, direct))),
        }
    }

    pub(super) fn direct_write_through(&self) -> bool {
        let direct = match self {
            Self::Sync(engine) => &engine.direct,
            Self::Async(engine) => &engine.direct,
            Self::Vmdk(_) => return false,
        };
        direct.as_ref().is_some_and(|d| d.write_through)
    }

    pub(super) fn set_direct_write_through(&mut self, enabled: bool) {
        let direct = match self {
            Self::Sync(engine) => &mut engine.direct,
            Self::Async(engine) => &mut engine.direct,
            Self::Vmdk(_) => return,
        };
        if let Some(direct) = direct {
            direct.write_through = enabled;
        }
    }

    pub fn update_direct_file_path(
        &mut self,
        file: File,
        disk_size: u64,
    ) -> Result<(), BlockIoError> {
        let mut direct = direct::DirectIo::probe(&file, disk_size).map_err(BlockIoError::Direct)?;
        direct.write_through = self.direct_write_through();
        self.update_file(file, Some(direct))
    }

    pub fn update_file_path(&mut self, file: File) -> Result<(), BlockIoError> {
        self.update_file(file, None)
    }

    fn update_file(
        &mut self,
        file: File,
        direct: Option<direct::DirectIo>,
    ) -> Result<(), BlockIoError> {
        match self {
            FileEngine::Async(engine) => engine
                .update_file(file, direct)
                .map_err(BlockIoError::Async)?,
            FileEngine::Sync(engine) => *engine = SyncFileEngine::from_file(file, direct),
            FileEngine::Vmdk(_) => {
                return Err(BlockIoError::Vmdk(VmdkIoError::UnsupportedOperation));
            }
        };

        Ok(())
    }

    pub fn file(&self) -> &File {
        match self {
            FileEngine::Async(engine) => engine.file(),
            FileEngine::Sync(engine) => engine.file(),
            FileEngine::Vmdk(_) => {
                panic!("file() is not supported for VMDK engine")
            }
        }
    }

    pub fn read(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
        req: PendingRequest,
    ) -> Result<FileEngineOk, RequestError<BlockIoError>> {
        match self {
            FileEngine::Async(engine) => {
                match engine.transfer(false, offset, mem, addr, count, req) {
                    Ok(ok) => Ok(ok),
                    Err(err) => Err(RequestError {
                        req: err.req,
                        error: BlockIoError::Async(err.error),
                    }),
                }
            }
            FileEngine::Sync(engine) => match engine.read(offset, mem, addr, count) {
                Ok(count) => Ok(FileEngineOk::Executed(RequestOk { req, count })),
                Err(err) => Err(RequestError {
                    req,
                    error: BlockIoError::Sync(err),
                }),
            },
            FileEngine::Vmdk(engine) => match engine.read(offset, mem, addr, count) {
                Ok(count) => Ok(FileEngineOk::Executed(RequestOk { req, count })),
                Err(err) => Err(RequestError {
                    req,
                    error: BlockIoError::Vmdk(err),
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
        req: PendingRequest,
    ) -> Result<FileEngineOk, RequestError<BlockIoError>> {
        match self {
            FileEngine::Async(engine) => match engine.transfer(true, offset, mem, addr, count, req)
            {
                Ok(ok) => Ok(ok),
                Err(err) => Err(RequestError {
                    req: err.req,
                    error: BlockIoError::Async(err.error),
                }),
            },
            FileEngine::Sync(engine) => match engine.write(offset, mem, addr, count) {
                Ok(count) => Ok(FileEngineOk::Executed(RequestOk { req, count })),
                Err(err) => Err(RequestError {
                    req,
                    error: BlockIoError::Sync(err),
                }),
            },
            FileEngine::Vmdk(engine) => match engine.write(offset, mem, addr, count) {
                Ok(count) => Ok(FileEngineOk::Executed(RequestOk { req, count })),
                Err(err) => Err(RequestError {
                    req,
                    error: BlockIoError::Vmdk(err),
                }),
            },
        }
    }

    pub(super) fn transfer_vectored(
        &mut self,
        write: bool,
        offset: u64,
        mem: &GuestMemoryMmap,
        segments: Vec<DataSegment>,
        req: PendingRequest,
    ) -> Result<FileEngineOk, RequestError<BlockIoError>> {
        if req.data_len() > MAX_VECTORED_BYTES {
            return Err(RequestError {
                req,
                error: BlockIoError::VectorTooLarge,
            });
        }
        match self {
            FileEngine::Async(engine) => engine
                .transfer_vectored(write, offset, mem, segments, req)
                .map_err(|err| RequestError {
                    req: err.req,
                    error: BlockIoError::Async(err.error),
                }),
            FileEngine::Sync(engine) => {
                let count = engine
                    .transfer_vectored(write, offset, mem, &segments, req.data_len())
                    .map_err(BlockIoError::Sync);
                match count {
                    Ok(count) => Ok(FileEngineOk::Executed(RequestOk { req, count })),
                    Err(error) => Err(RequestError { req, error }),
                }
            }
            FileEngine::Vmdk(_) => Err(RequestError {
                req,
                error: BlockIoError::Vmdk(VmdkIoError::UnsupportedOperation),
            }),
        }
    }

    pub fn flush(
        &mut self,
        req: PendingRequest,
    ) -> Result<FileEngineOk, RequestError<BlockIoError>> {
        match self {
            FileEngine::Async(engine) => match engine.push_flush(req) {
                Ok(_) => Ok(FileEngineOk::Submitted),
                Err(err) => Err(RequestError {
                    req: err.req,
                    error: BlockIoError::Async(err.error),
                }),
            },
            FileEngine::Sync(engine) => match engine.flush() {
                Ok(_) => Ok(FileEngineOk::Executed(RequestOk { req, count: 0 })),
                Err(err) => Err(RequestError {
                    req,
                    error: BlockIoError::Sync(err),
                }),
            },
            FileEngine::Vmdk(engine) => match engine.flush() {
                Ok(_) => Ok(FileEngineOk::Executed(RequestOk { req, count: 0 })),
                Err(err) => Err(RequestError {
                    req,
                    error: BlockIoError::Vmdk(err),
                }),
            },
        }
    }

    pub fn discard(
        &mut self,
        range: (u64, u32),
        req: PendingRequest,
    ) -> Result<FileEngineOk, RequestError<BlockIoError>> {
        match self {
            FileEngine::Async(engine) => match engine.discard(range) {
                Ok(count) => Ok(FileEngineOk::Executed(RequestOk { req, count })),
                Err(err) => Err(RequestError {
                    req,
                    error: BlockIoError::Async(err),
                }),
            },
            FileEngine::Sync(engine) => match engine.discard(range) {
                Ok(count) => Ok(FileEngineOk::Executed(RequestOk { req, count })),
                Err(err) => Err(RequestError {
                    req,
                    error: BlockIoError::Sync(err),
                }),
            },
            FileEngine::Vmdk(_) => Err(RequestError {
                req,
                error: BlockIoError::Vmdk(VmdkIoError::WriteNotSupported),
            }),
        }
    }

    pub fn drain(&mut self, discard: bool) -> Result<(), BlockIoError> {
        match self {
            FileEngine::Async(engine) => engine.drain(discard).map_err(BlockIoError::Async),
            FileEngine::Sync(_engine) => Ok(()),
            FileEngine::Vmdk(_engine) => Ok(()),
        }
    }

    pub fn drain_and_flush(&mut self, discard: bool) -> Result<(), BlockIoError> {
        match self {
            FileEngine::Async(engine) => {
                engine.drain_and_flush(discard).map_err(BlockIoError::Async)
            }
            FileEngine::Sync(engine) => engine.flush().map_err(BlockIoError::Sync),
            FileEngine::Vmdk(engine) => engine.flush().map_err(BlockIoError::Vmdk),
        }
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]
    use std::os::unix::ffi::OsStrExt;

    use vm_memory::{GuestMemoryBackend, GuestMemoryError, GuestMemoryRegion};
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::devices::virtio::block::virtio::device::FileEngineType;
    use crate::devices::virtio::block::virtio::io::format::vmdk::tests::create_test_vmdk;
    use crate::utils::u64_to_usize;
    use crate::vmm_config::machine_config::HugePageConfig;
    use crate::vstate::memory;
    use crate::vstate::memory::{Bitmap, Bytes, GuestRegionMmapExt};

    const FILE_LEN: u32 = 1024;
    // 2 pages of memory should be enough to test read/write ops and also dirty tracking.
    const MEM_LEN: usize = 8192;

    macro_rules! assert_sync_execution {
        ($expression:expr, $count:expr) => {
            match $expression {
                Ok(FileEngineOk::Executed(RequestOk { req: _, count })) => {
                    assert_eq!(count, $count)
                }
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

    fn assert_async_execution(mem: &GuestMemoryMmap, engine: &mut FileEngine, count: u32) {
        if let FileEngine::Async(engine) = engine {
            engine.drain(false).unwrap();
            assert_eq!(engine.pop(mem).unwrap().unwrap().result().unwrap(), count);
        }
    }

    pub(super) fn create_mem() -> GuestMemoryMmap {
        GuestMemoryMmap::from_regions(
            memory::anonymous(&[(GuestAddress(0), MEM_LEN)], true, HugePageConfig::None)
                .unwrap()
                .into_iter()
                .map(|region| GuestRegionMmapExt::dram_from_mmap_region(region, 0))
                .collect(),
        )
        .unwrap()
    }

    pub(super) fn check_dirty_mem(mem: &GuestMemoryMmap, addr: GuestAddress, len: u32) {
        let bitmap = mem.find_region(addr).unwrap().bitmap();
        for offset in addr.0..addr.0 + u64::from(len) {
            assert!(bitmap.dirty_at(u64_to_usize(offset)));
        }
    }

    pub(super) fn check_clean_mem(mem: &GuestMemoryMmap, addr: GuestAddress, len: u32) {
        let bitmap = mem.find_region(addr).unwrap().bitmap();
        for offset in addr.0..addr.0 + u64::from(len) {
            assert!(!bitmap.dirty_at(u64_to_usize(offset)));
        }
    }

    #[test]
    fn test_sync() {
        let mem = create_mem();
        // Create backing file.
        let file = TempFile::new().unwrap().into_file();
        let mut engine = FileEngine::from_file(file, FileEngineType::Sync).unwrap();

        let data = vmm_sys_util::rand::rand_alphanumerics(FILE_LEN as usize)
            .as_bytes()
            .to_vec();

        // Partial write
        let partial_len = 50;
        let addr = GuestAddress(MEM_LEN as u64 - u64::from(partial_len));
        mem.write(&data, addr).unwrap();
        assert_sync_execution!(
            engine.write(0, &mem, addr, partial_len, PendingRequest::default()),
            partial_len
        );
        // Partial read
        let mem = create_mem();
        assert_sync_execution!(
            engine.read(0, &mem, addr, partial_len, PendingRequest::default()),
            partial_len
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
            engine.write(offset, &mem, addr, partial_len, PendingRequest::default()),
            partial_len
        );
        // Offset read
        let mem = create_mem();
        assert_sync_execution!(
            engine.read(offset, &mem, addr, partial_len, PendingRequest::default()),
            partial_len
        );
        // Check data
        let mut buf = vec![0u8; partial_len as usize];
        mem.read_slice(&mut buf, addr).unwrap();
        assert_eq!(buf, data[..partial_len as usize]);

        // Full write
        mem.write(&data, GuestAddress(0)).unwrap();
        assert_sync_execution!(
            engine.write(
                0,
                &mem,
                GuestAddress(0),
                FILE_LEN,
                PendingRequest::default()
            ),
            FILE_LEN
        );
        // Full read
        let mem = create_mem();
        assert_sync_execution!(
            engine.read(
                0,
                &mem,
                GuestAddress(0),
                FILE_LEN,
                PendingRequest::default()
            ),
            FILE_LEN
        );
        // Check data
        let mut buf = vec![0u8; FILE_LEN as usize];
        mem.read_slice(&mut buf, GuestAddress(0)).unwrap();
        assert_eq!(buf, data.as_slice());

        // Check other ops
        engine.flush(PendingRequest::default()).unwrap();
        engine.drain(true).unwrap();
        engine.drain_and_flush(true).unwrap();
    }

    #[test]
    fn test_sync_dirty_tracking() {
        let temp_file = TempFile::new().unwrap();
        // A second, write-only handle on the same file, for the failing read below.
        let write_only = std::fs::OpenOptions::new()
            .write(true)
            .open(temp_file.as_path())
            .unwrap();
        let mut engine =
            FileEngine::from_file(temp_file.into_file(), FileEngineType::Sync).unwrap();
        let data = vmm_sys_util::rand::rand_alphanumerics(FILE_LEN as usize)
            .as_bytes()
            .to_vec();
        let mem = create_mem();
        mem.write(&data, GuestAddress(0)).unwrap();
        assert_sync_execution!(
            engine.write(
                0,
                &mem,
                GuestAddress(0),
                FILE_LEN,
                PendingRequest::default()
            ),
            FILE_LEN
        );

        // A read into the second page marks that page and not the first.
        let mem = create_mem();
        let addr = GuestAddress(4096);
        assert_sync_execution!(
            engine.read(0, &mem, addr, FILE_LEN, PendingRequest::default()),
            FILE_LEN
        );
        check_clean_mem(&mem, GuestAddress(0), 4096);
        check_dirty_mem(&mem, addr, FILE_LEN);

        // A read past the end of the file fails after reading what there is, and marks only
        // that: the file ends in the first page, so the second page stays clean.
        let mem = create_mem();
        let too_long = FILE_LEN + 4096;
        match engine.read(
            0,
            &mem,
            GuestAddress(0),
            too_long,
            PendingRequest::default(),
        ) {
            Err(err) => assert!(matches!(
                err.error,
                BlockIoError::Sync(SyncIoError::Transfer(GuestMemoryError::IOError(_)))
            )),
            Ok(_) => panic!("read past the end of the file succeeded"),
        }
        let mut buf = vec![0u8; FILE_LEN as usize];
        mem.read_slice(&mut buf, GuestAddress(0)).unwrap();
        assert_eq!(buf, data.as_slice());
        check_dirty_mem(&mem, GuestAddress(0), FILE_LEN);
        check_clean_mem(&mem, GuestAddress(4096), 4096);

        // A `read` that fails outright writes nothing, so nothing is marked: on the write-only
        // handle `read` fails with EBADF on the first call.
        let mut engine = FileEngine::from_file(write_only, FileEngineType::Sync).unwrap();
        let mem = create_mem();
        match engine.read(
            0,
            &mem,
            GuestAddress(0),
            2 * 4096,
            PendingRequest::default(),
        ) {
            Err(err) => assert!(matches!(
                err.error,
                BlockIoError::Sync(SyncIoError::Transfer(GuestMemoryError::IOError(_)))
            )),
            Ok(_) => panic!("read from a write-only file succeeded"),
        }
        check_clean_mem(&mem, GuestAddress(0), 2 * 4096);
    }

    #[test]
    fn test_async() {
        // Create backing file.
        let file = TempFile::new().unwrap().into_file();
        let mut engine = FileEngine::from_file(file, FileEngineType::Async).unwrap();

        let data = vmm_sys_util::rand::rand_alphanumerics(FILE_LEN as usize)
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
        assert_queued!(engine.write(offset, &mem, addr, partial_len, PendingRequest::default()));
        assert_async_execution(&mem, &mut engine, partial_len);
        // Offset read
        let mem = create_mem();
        assert_queued!(engine.read(offset, &mem, addr, partial_len, PendingRequest::default()));
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
        assert_queued!(engine.write(0, &mem, addr, FILE_LEN, PendingRequest::default()));
        assert_async_execution(&mem, &mut engine, FILE_LEN);

        // Full read
        let mem = create_mem();
        assert_queued!(engine.read(0, &mem, addr, FILE_LEN, PendingRequest::default()));
        assert_async_execution(&mem, &mut engine, FILE_LEN);
        // Check data
        let mut buf = vec![0u8; FILE_LEN as usize];
        mem.read_slice(&mut buf, GuestAddress(0)).unwrap();
        assert_eq!(buf, data.as_slice());
        // check dirty mem
        check_dirty_mem(&mem, addr, FILE_LEN);
        check_clean_mem(&mem, GuestAddress(4096), 4096);

        // Check other ops
        assert_queued!(engine.flush(PendingRequest::default()));
        assert_async_execution(&mem, &mut engine, 0);

        engine.drain(true).unwrap();
        engine.drain_and_flush(true).unwrap();
    }

    #[test]
    fn test_vmdk() {
        let (_dir, descriptor) = create_test_vmdk("extent", 0);
        let mut engine = FileEngine::Vmdk(VmdkFileEngine::from_path(&descriptor).unwrap());
        let mem = create_mem();

        assert_sync_execution!(
            engine.read(0, &mem, GuestAddress(0), 512, PendingRequest::default()),
            512
        );
        assert!(matches!(
            engine
                .read(
                    0,
                    &mem,
                    GuestAddress(MEM_LEN as u64),
                    512,
                    PendingRequest::default()
                )
                .unwrap_err()
                .error,
            BlockIoError::Vmdk(VmdkIoError::GuestMemory(_))
        ));
        assert!(matches!(
            engine
                .write(0, &mem, GuestAddress(0), 512, PendingRequest::default())
                .unwrap_err()
                .error,
            BlockIoError::Vmdk(VmdkIoError::WriteNotSupported)
        ));
        assert_sync_execution!(engine.flush(PendingRequest::default()), 0);
        assert!(matches!(
            engine
                .discard((0, 512), PendingRequest::default())
                .unwrap_err()
                .error,
            BlockIoError::Vmdk(VmdkIoError::WriteNotSupported)
        ));
        engine.drain(true).unwrap();
        engine.drain_and_flush(true).unwrap();
        assert!(matches!(
            engine.update_file_path(File::open(descriptor).unwrap()),
            Err(BlockIoError::Vmdk(VmdkIoError::UnsupportedOperation))
        ));
    }
}

mod direct {
    //! Host alignment and bounded staging for a single-queue raw O_DIRECT drive.

    use std::fs::File;
    use std::io::{self, Read, Seek, SeekFrom, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::FileTypeExt;

    use rustix::fs::{AtFlags, StatxFlags, statx};
    use vm_memory::Bytes;

    use super::DataSegment;
    use crate::vstate::memory::{GuestAddress, GuestMemoryMmap, with_plugged_slice};

    pub(super) const BUFFER_SIZE: usize = 64 * 1024;

    /// One reusable staging area per direct drive, independent of guest request size.
    #[repr(align(4096))]
    pub(super) struct Buffer(pub [u8; BUFFER_SIZE]);

    // Debug output for a drive must not include guest disk data.
    impl std::fmt::Debug for Buffer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Buffer").field("len", &BUFFER_SIZE).finish()
        }
    }

    #[derive(Debug)]
    pub(super) struct DirectIo {
        mem_align: usize,
        offset_align: usize,
        size: u64,
        pub(super) write_through: bool,
        buffer: Option<Box<Buffer>>,
    }

    impl DirectIo {
        pub(super) fn probe(file: &File, size: u64) -> io::Result<Self> {
            let ty = file.metadata()?.file_type();
            if !ty.is_block_device() && !ty.is_file() {
                return Err(io::Error::other(
                    "direct I/O requires a regular file or block device",
                ));
            }
            match statx(file, "", AtFlags::EMPTY_PATH, StatxFlags::DIOALIGN) {
                Ok(info) if info.stx_mask & StatxFlags::DIOALIGN.bits() != 0 => {
                    return Self::new(
                        info.stx_dio_mem_align as usize,
                        info.stx_dio_offset_align as usize,
                        size,
                    );
                }
                Ok(_) => {}
                Err(
                    rustix::io::Errno::NOSYS
                    | rustix::io::Errno::INVAL
                    | rustix::io::Errno::OPNOTSUPP,
                ) if ty.is_block_device() => {}
                Err(err) => return Err(err.into()),
            }
            if !ty.is_block_device() {
                return Err(io::Error::other(
                    "filesystem did not report direct I/O alignment",
                ));
            }
            // Older kernels do not report the device's DMA alignment. Use a whole
            // host page for buffers, independently of the logical sector length.
            let mut sector = 0i32;
            // SAFETY: BLKSSZGET writes one integer into the supplied pointer.
            if unsafe { libc::ioctl(file.as_raw_fd(), libc::BLKSSZGET, &mut sector) } < 0 {
                return Err(io::Error::last_os_error());
            }
            if sector < 512 {
                return Err(io::Error::other("invalid logical sector size"));
            }
            Self::new(
                crate::arch::host_page_size(),
                usize::try_from(sector).unwrap(),
                size,
            )
        }

        pub(super) fn new(mem_align: usize, offset_align: usize, size: u64) -> io::Result<Self> {
            if ![mem_align, offset_align]
                .into_iter()
                .all(|n| n.is_power_of_two() && n <= align_of::<Buffer>())
            {
                return Err(io::Error::other(format!(
                    "unsupported direct I/O alignment: memory {mem_align}, offset {offset_align}"
                )));
            }
            let offset_align = offset_align.max(512);
            if !size.is_multiple_of(offset_align as u64) {
                return Err(io::Error::other(
                    "disk size is not a multiple of the transfer alignment",
                ));
            }
            Ok(Self {
                mem_align,
                offset_align,
                size,
                write_through: false,
                buffer: None,
            })
        }

        pub(super) fn check_range(&self, offset: u64, count: u32) -> io::Result<()> {
            if offset
                .checked_add(u64::from(count))
                .is_none_or(|end| end > self.size)
            {
                return Err(io::Error::other("direct I/O exceeds backing size"));
            }
            Ok(())
        }

        pub(super) fn aligned_span(&self, offset: u64, count: u32) -> bool {
            offset.is_multiple_of(self.offset_align as u64) && self.aligned_len(count as usize)
        }

        pub(super) fn aligned_len(&self, count: usize) -> bool {
            count.is_multiple_of(self.offset_align)
        }

        pub(super) fn aligned_buffer(&self, ptr: usize) -> bool {
            ptr.is_multiple_of(self.mem_align)
        }

        pub(super) fn buffer(&mut self) -> &mut Buffer {
            self.buffer
                .get_or_insert_with(|| Box::new(Buffer([0; BUFFER_SIZE])))
        }

        pub(super) fn finish_write(&self, file: &File, count: u32) -> io::Result<u32> {
            if self.write_through && count != 0 {
                file.sync_data()?;
            }
            Ok(count)
        }

        /// Stage an unaligned request in whole host blocks. Only the start and end of the
        /// request can require a read-modify-write. The caller excludes concurrent writes.
        pub(super) fn transfer(
            &mut self,
            file: &mut File,
            write: bool,
            offset: u64,
            mem: &GuestMemoryMmap,
            addr: GuestAddress,
            count: u32,
        ) -> io::Result<u32> {
            self.transfer_segments(file, write, offset, mem, &[(addr, count)], count)
        }

        /// Stage a contiguous disk range independent of guest segment boundaries.
        #[allow(clippy::too_many_arguments)]
        pub(super) fn transfer_segments(
            &mut self,
            file: &mut File,
            write: bool,
            offset: u64,
            mem: &GuestMemoryMmap,
            segments: &[DataSegment],
            count: u32,
        ) -> io::Result<u32> {
            let block = self.offset_align;
            let buf = &mut self.buffer().0;
            let mut done = 0;
            while done < count {
                let cursor = offset + u64::from(done);
                let head = usize::try_from(cursor % block as u64)
                    .expect("remainder is smaller than a block");
                let start = cursor - head as u64;
                let n = ((count - done) as usize).min(BUFFER_SIZE - head);
                let span = (head + n).next_multiple_of(block);

                let step = (|| -> io::Result<usize> {
                    if write {
                        if head != 0 || n != span {
                            file.seek(SeekFrom::Start(start))?;
                            file.read_exact(&mut buf[..span])?;
                        }
                        copy_guest_segments(
                            segments,
                            done,
                            &mut buf[head..head + n],
                            |addr, part| {
                                with_plugged_slice(mem, addr, part.len(), |slice| {
                                    slice.read_slice(part, 0)
                                })
                            },
                        )?;
                        file.seek(SeekFrom::Start(start))?;
                        let written = retry_interrupted(|| file.write(&buf[..span]))?;
                        Ok(written.saturating_sub(head).min(n))
                    } else {
                        file.seek(SeekFrom::Start(start))?;
                        let read = retry_interrupted(|| file.read(&mut buf[..span]))?;
                        let available = read.saturating_sub(head).min(n);
                        copy_guest_segments(
                            segments,
                            done,
                            &mut buf[head..head + available],
                            |addr, part| {
                                with_plugged_slice(mem, addr, part.len(), |slice| {
                                    slice.write_slice(part, 0)
                                })
                            },
                        )?;
                        Ok(available)
                    }
                })();

                match step {
                    Ok(bytes) => {
                        done += u32::try_from(bytes).expect("bounded by buffer size");
                        if bytes != n {
                            break;
                        }
                    }
                    // A short count makes the virtio request fail and accounts for the
                    // prefix already delivered to guest memory.
                    Err(_) if done > 0 => break,
                    Err(err) => return Err(err),
                }
            }
            if write {
                self.finish_write(file, done)
            } else {
                Ok(done)
            }
        }
    }

    fn copy_guest_segments(
        segments: &[DataSegment],
        mut skip: u32,
        mut buffer: &mut [u8],
        mut copy: impl FnMut(GuestAddress, &mut [u8]) -> Result<(), vm_memory::GuestMemoryError>,
    ) -> io::Result<()> {
        for &(addr, len) in segments {
            if buffer.is_empty() {
                return Ok(());
            }
            if skip >= len {
                skip -= len;
                continue;
            }
            let len = ((len - skip) as usize).min(buffer.len());
            let (part, rest) = buffer.split_at_mut(len);
            copy(GuestAddress(addr.0 + u64::from(skip)), part).map_err(io::Error::other)?;
            buffer = rest;
            skip = 0;
        }
        if !buffer.is_empty() {
            return Err(io::Error::other(
                "guest segments end before requested length",
            ));
        }
        Ok(())
    }

    pub(super) fn retry_interrupted<T>(mut f: impl FnMut() -> io::Result<T>) -> io::Result<T> {
        loop {
            match f() {
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                result => return result,
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_write_through_reports_sync_error() {
            let mut direct = DirectIo::new(4096, 4096, 4096).unwrap();
            let disk = File::options().write(true).open("/dev/null").unwrap();
            assert_eq!(direct.finish_write(&disk, 512).unwrap(), 512);
            direct.write_through = true;
            assert_eq!(direct.finish_write(&disk, 0).unwrap(), 0);
            assert_eq!(
                direct.finish_write(&disk, 512).unwrap_err().raw_os_error(),
                Some(libc::EINVAL)
            );
        }
    }
}

mod vectored {
    use vm_memory::{GuestMemoryBackend, GuestMemoryError};

    use super::direct::DirectIo;
    use crate::vstate::memory::{GuestAddress, GuestMemoryExtension, GuestMemoryMmap};

    pub(in super::super) type DataSegment = (GuestAddress, u32);

    #[derive(Debug)]
    pub(super) struct IoVecs(Box<[libc::iovec]>);

    // SAFETY: The entries only contain addresses in validated guest memory. Their owner must
    // keep the memory map alive for each operation and accesses the buffers via the kernel.
    unsafe impl Send for IoVecs {}

    impl IoVecs {
        pub(super) fn new(
            mem: &GuestMemoryMmap,
            segments: &[DataSegment],
        ) -> Result<Self, GuestMemoryError> {
            segments
                .iter()
                .map(|&(addr, len)| {
                    let slice = mem.get_slice(addr, len as usize)?;
                    Ok(libc::iovec {
                        iov_base: slice.ptr_guard_mut().as_ptr().cast(),
                        iov_len: len as usize,
                    })
                })
                .collect::<Result<Box<[_]>, _>>()
                .map(Self)
        }

        pub(super) fn as_slice(&self) -> &[libc::iovec] {
            &self.0
        }

        pub(super) fn as_mut_slice(&mut self) -> &mut [libc::iovec] {
            &mut self.0
        }

        pub(super) fn needs_bounce(&self, direct: &DirectIo, offset: u64) -> bool {
            !direct.aligned_span(offset, 0)
                || self.0.iter().any(|iov| {
                    iov.iov_len != 0
                        && (!direct.aligned_buffer(iov.iov_base as usize)
                            || !direct.aligned_len(iov.iov_len))
                })
        }
    }

    pub(super) fn mark_read_dirty(mem: &GuestMemoryMmap, segments: &[DataSegment], mut count: u32) {
        for &(addr, len) in segments {
            let written = count.min(len);
            if written > 0 {
                mem.mark_dirty(addr, written as usize);
                count -= written;
            }
            if count == 0 {
                break;
            }
        }
    }
}

#[cfg(test)]
mod direct_tests {
    use std::fs::OpenOptions;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{FileExt, OpenOptionsExt};

    use utils::time::MockClock;
    use vmm_sys_util::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
    use vmm_sys_util::tempfile::TempFile;

    use super::direct::DirectIo;
    use super::tests::{check_clean_mem, check_dirty_mem, create_mem};
    use super::*;
    use crate::devices::virtio::block::virtio::request::{
        RequestHeader, VIRTIO_BLK_S_OK, VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT,
    };
    use crate::devices::virtio::block::virtio::test_utils::{
        default_block, direct_io_test_file, set_queue, set_rate_limiter,
        simulate_queue_and_async_completion_events, simulate_queue_event,
    };
    use crate::devices::virtio::device::VirtioDevice;
    use crate::devices::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    use crate::devices::virtio::test_utils::{VirtQueue, default_interrupt, default_mem};
    use crate::rate_limiter::RateLimiter;
    use crate::vstate::memory::Bytes;

    fn next_completion(engine: &mut FileEngine, mem: &GuestMemoryMmap) -> u32 {
        let FileEngine::Async(engine) = engine else {
            unreachable!()
        };
        engine.drain(false).unwrap();
        engine.pop(mem).unwrap().unwrap().result().unwrap()
    }

    fn completed(engine: &mut FileEngine, mem: &GuestMemoryMmap, result: FileEngineOk) -> u32 {
        match result {
            FileEngineOk::Submitted => next_completion(engine, mem),
            FileEngineOk::Executed(done) => done.count,
        }
    }

    #[test]
    fn test_direct_geometry() {
        let geometry = DirectIo::new(4096, 512, 1536).unwrap();
        assert!(geometry.aligned_span(512, 1024));
        assert!(!geometry.aligned_buffer(512));
        assert!(geometry.aligned_buffer(4096));
        DirectIo::new(0, 512, 4096).unwrap_err();
        DirectIo::new(4096, 0, 4096).unwrap_err();
        DirectIo::new(8192, 512, 4096).unwrap_err();
        DirectIo::new(512, 4096, 4608).unwrap_err();
        geometry.check_range(u64::MAX - 511, 512).unwrap_err();
    }

    #[test]
    fn test_rmw_preserves_neighbors_and_waits_for_prior_write() {
        for ty in [FileEngineType::Sync, FileEngineType::Async] {
            let file = TempFile::new().unwrap().into_file();
            file.write_all_at(&[0x55; 8192], 0).unwrap();
            let mut engine =
                FileEngine::new(file, ty, Some(DirectIo::new(4096, 4096, 8192).unwrap())).unwrap();
            let mem = create_mem();
            mem.write_slice(&[0x33; 4096], GuestAddress(0)).unwrap();
            let first = engine
                .write(0, &mem, GuestAddress(0), 4096, PendingRequest::default())
                .unwrap();

            // Straddles two host blocks while modifying only two guest sectors.
            let src = GuestAddress(4097);
            mem.write_slice(&[0xa5; 1024], src).unwrap();
            let patch = engine
                .write(3584, &mem, src, 1024, PendingRequest::default())
                .unwrap();
            assert_eq!(completed(&mut engine, &mem, patch), 1024);
            assert_eq!(completed(&mut engine, &mem, first), 4096);
            let mut bytes = [0; 8192];
            engine.file().read_exact_at(&mut bytes, 0).unwrap();
            assert_eq!(&bytes[..3584], &[0x33; 3584]);
            assert_eq!(&bytes[3584..4608], &[0xa5; 1024]);
            assert_eq!(&bytes[4608..], &[0x55; 3584]);

            // A truncated backing cannot supply the second block to preserve.
            engine.file().set_len(4096).unwrap();
            engine
                .write(3584, &mem, src, 1024, PendingRequest::default())
                .unwrap_err();
            let mut first_block = [0; 4096];
            engine.file().read_exact_at(&mut first_block, 0).unwrap();
            assert_eq!(first_block, bytes[..4096]);
        }
    }

    #[test]
    fn test_direct_short_read_marks_and_reports_only_delivered_prefix() {
        for ty in [FileEngineType::Sync, FileEngineType::Async] {
            for offset in [0, 512] {
                // Admit an 8K guest disk, then truncate its backing to inject a short host read.
                let file = TempFile::new().unwrap().into_file();
                file.write_all_at(&[0x42; 4096], 0).unwrap();
                let mut engine =
                    FileEngine::new(file, ty, Some(DirectIo::new(4096, 4096, 8192).unwrap()))
                        .unwrap();
                let mem = create_mem();
                let result = engine
                    .read(
                        offset,
                        &mem,
                        GuestAddress(0),
                        8192 - u32::try_from(offset).unwrap(),
                        PendingRequest::default(),
                    )
                    .unwrap();
                let len = completed(&mut engine, &mem, result);
                assert_eq!(u64::from(len), 4096 - offset);
                check_dirty_mem(&mem, GuestAddress(0), len);
                check_clean_mem(&mem, GuestAddress(4096), 4096);
                let mut copy = vec![0; len as usize];
                mem.read_slice(&mut copy, GuestAddress(0)).unwrap();
                assert!(copy.iter().all(|byte| *byte == 0x42));
            }
        }
    }

    #[test]
    fn test_direct_staged_read_short_completion() {
        let file = TempFile::new().unwrap().into_file();
        file.write_all_at(&[0xbf; 1024], 0).unwrap();
        let mut engine = FileEngine::new(
            file,
            FileEngineType::Async,
            Some(DirectIo::new(4096, 512, 8192).unwrap()),
        )
        .unwrap();
        let mem = create_mem();
        let result = engine
            .read(0, &mem, GuestAddress(3), 4608, PendingRequest::default())
            .unwrap();
        assert!(matches!(result, FileEngineOk::Submitted));
        assert_eq!(next_completion(&mut engine, &mem), 1024);
        check_clean_mem(&mem, GuestAddress(4096), 4096);
        check_dirty_mem(&mem, GuestAddress(3), 1024);
        let mut copy = [0; 1024];
        mem.read_slice(&mut copy, GuestAddress(3)).unwrap();
        assert_eq!(copy, [0xbf; 1024]);
    }

    #[test]
    fn test_direct_disk_and_ordered_flush() {
        let Some(backing) = direct_io_test_file() else {
            return;
        };
        for ty in [FileEngineType::Sync, FileEngineType::Async] {
            let fd = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_DIRECT)
                .open(backing.as_path())
                .unwrap();
            let mut engine = FileEngine::from_direct_file(fd, ty, 4096).unwrap();
            let mem = create_mem();
            mem.write_slice(&[0x81; 4096], GuestAddress(1)).unwrap();
            let write = engine
                .write(0, &mem, GuestAddress(1), 4096, PendingRequest::default())
                .unwrap();
            let flush = engine.flush(PendingRequest::default()).unwrap();
            // The direct fsync completes after the staged fixed-file write.
            assert_eq!(completed(&mut engine, &mem, write), 4096);
            assert_eq!(completed(&mut engine, &mem, flush), 0);
            let mem = create_mem();
            let read = engine
                .read(0, &mem, GuestAddress(1), 4096, PendingRequest::default())
                .unwrap();
            assert_eq!(completed(&mut engine, &mem, read), 4096);
            let mut bytes = [0; 4096];
            mem.read_slice(&mut bytes, GuestAddress(1)).unwrap();
            assert_eq!(bytes, [0x81; 4096]);
        }
    }

    #[test]
    fn test_vectored_direct_read_write() {
        for ty in [FileEngineType::Sync, FileEngineType::Async] {
            for (offset, segments) in [
                (0, [(0x4000, 4096), (0x7000, 4096)]),
                (3584, [(0x4001, 127), (0x7003, 897)]),
            ] {
                let mut block = default_block(ty);
                block.metrics = Default::default();
                let file = TempFile::new().unwrap().into_file();
                file.write_all_at(&[0x21; 8192], 0).unwrap();
                block.resources_mut()[0].disk.nsectors = 16;
                block.resources_mut()[0].disk.file_engine =
                    FileEngine::new(file, ty, Some(DirectIo::new(4096, 4096, 8192).unwrap()))
                        .unwrap();

                let mem = default_mem();
                let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
                set_queue(&mut block, 0, vq.create_queue());
                block.set_acked_features(
                    1 << crate::devices::virtio::generated::virtio_blk::VIRTIO_BLK_F_SEG_MAX,
                );
                block.activate(mem.clone(), default_interrupt()).unwrap();

                let count: u32 = segments.iter().map(|(_, len)| len).sum();
                let mut expected = vec![0x21; 8192];
                let mut cursor = usize::try_from(offset).unwrap();
                for (i, (addr, len)) in segments.into_iter().enumerate() {
                    let data = vec![0x55 + u8::try_from(i).unwrap(); len as usize];
                    mem.write_slice(&data, GuestAddress(addr)).unwrap();
                    expected[cursor..cursor + data.len()].copy_from_slice(&data);
                    cursor += data.len();
                }
                for (slot, op) in [(0u16, VIRTIO_BLK_T_OUT), (1u16, VIRTIO_BLK_T_IN)] {
                    let head = slot * 4;
                    let header = 0x2000 + u64::from(slot) * 16;
                    let status = 0x3000 + u64::from(slot);
                    let displacement = u64::from(slot) * 0x8000;
                    vq.dtable[head as usize].set(header, 16, VIRTQ_DESC_F_NEXT, head + 1);
                    for (i, (addr, len)) in segments.into_iter().enumerate() {
                        let idx = head + u16::try_from(i).unwrap() + 1;
                        let flags = VIRTQ_DESC_F_NEXT
                            | if op == VIRTIO_BLK_T_IN {
                                VIRTQ_DESC_F_WRITE
                            } else {
                                0
                            };
                        vq.dtable[idx as usize].set(addr + displacement, len, flags, idx + 1);
                    }
                    vq.dtable[head as usize + 3].set(status, 1, VIRTQ_DESC_F_WRITE, 0);
                    mem.write_obj(RequestHeader::new(op, offset / 512), GuestAddress(header))
                        .unwrap();
                    mem.write_obj(0xffu8, GuestAddress(status)).unwrap();
                    vq.avail.ring[slot as usize].set(head);
                    vq.avail.idx.set(slot + 1);
                    simulate_queue_and_async_completion_events(&mut block, true);
                    assert_eq!(vq.used.idx.get(), slot + 1);
                    assert_eq!(
                        vq.used.ring[slot as usize].get().len,
                        if slot == 0 { 1 } else { count + 1 }
                    );
                    assert_eq!(
                        u32::from(mem.read_obj::<u8>(GuestAddress(status)).unwrap()),
                        VIRTIO_BLK_S_OK
                    );
                }
                let mut disk = [0; 8192];
                block.resources()[0]
                    .disk
                    .file_engine
                    .file()
                    .read_exact_at(&mut disk, 0)
                    .unwrap();
                assert_eq!(disk.as_slice(), expected.as_slice());
                let mut cursor = usize::try_from(offset).unwrap();
                for (addr, len) in segments {
                    let mut actual = vec![0; len as usize];
                    mem.read_slice(&mut actual, GuestAddress(addr + 0x8000))
                        .unwrap();
                    assert_eq!(actual, expected[cursor..cursor + actual.len()]);
                    cursor += actual.len();
                }
            }
        }
    }

    #[test]
    fn test_staged_writes_charge_ops_once() {
        let mut block = default_block(FileEngineType::Async);
        block.metrics = Default::default();
        let file = TempFile::new().unwrap().into_file();
        file.set_len(4096).unwrap();
        block.resources_mut()[0].disk.file_engine = FileEngine::new(
            file,
            FileEngineType::Async,
            Some(DirectIo::new(4096, 512, 4096).unwrap()),
        )
        .unwrap();

        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        let clock = MockClock::new();
        set_rate_limiter(
            &mut block,
            RateLimiter::new_mocked(0, 0, 0, 2, 0, 100, &clock),
        );
        block.activate(mem.clone(), default_interrupt()).unwrap();

        for i in 0..2u16 {
            let head = i * 3;
            let header = 0x1000 + u64::from(i) * 32;
            let status = 0x3000 + u64::from(i);
            let data = 0x4001 + u64::from(i) * 512;
            vq.dtable[usize::from(head)].set(header, 16, VIRTQ_DESC_F_NEXT, head + 1);
            vq.dtable[usize::from(head + 1)].set(data, 512, VIRTQ_DESC_F_NEXT, head + 2);
            vq.dtable[usize::from(head + 2)].set(status, 1, VIRTQ_DESC_F_WRITE, 0);
            mem.write_obj(
                RequestHeader::new(VIRTIO_BLK_T_OUT, u64::from(i)),
                GuestAddress(header),
            )
            .unwrap();
            mem.write_obj(0xffu8, GuestAddress(status)).unwrap();
            vq.avail.ring[usize::from(i)].set(head);
        }
        vq.avail.idx.set(2);
        let FileEngine::Async(engine) = &block.resources()[0].disk.file_engine else {
            unreachable!()
        };
        let ready = Epoll::new().unwrap();
        ready
            .ctl(
                ControlOperation::Add,
                engine.completion_evt().as_raw_fd(),
                EpollEvent::new(EventSet::IN, 0),
            )
            .unwrap();
        simulate_queue_event(&mut block, Some(false));
        assert_eq!(block.lock_rate_limiter().ops().unwrap().budget(), 1);
        for _ in 0..2 {
            // No new guest kicks or explicit ring drains: the staging operation's own
            // kernel completion must wake the queue and release the next request.
            assert_eq!(ready.wait(3000, &mut [EpollEvent::default()]).unwrap(), 1);
            block.process_async_completion_event();
        }
        assert_eq!(vq.used.idx.get(), 2);
        assert_eq!(block.lock_rate_limiter().ops().unwrap().budget(), 0);
        assert!(!block.lock_rate_limiter().is_blocked());
        for status in [0x3000, 0x3001] {
            assert_eq!(
                u32::from(mem.read_obj::<u8>(GuestAddress(status)).unwrap()),
                VIRTIO_BLK_S_OK
            );
        }
    }

    #[test]
    fn test_direct_read_error_and_reset_dirty_tracking() {
        let backing = TempFile::new().unwrap();
        backing.as_file().set_len(4096).unwrap();
        for ty in [FileEngineType::Sync, FileEngineType::Async] {
            // Write-only fd forces a negative read on the zero-copy path. A kernel direct
            // read error cannot certify that none of its destination was modified.
            let fd = OpenOptions::new()
                .write(true)
                .open(backing.as_path())
                .unwrap();
            let mut engine =
                FileEngine::new(fd, ty, Some(DirectIo::new(4096, 512, 8192).unwrap())).unwrap();
            let mem = create_mem();
            let result = engine.read(0, &mem, GuestAddress(0), 8192, PendingRequest::default());
            if let FileEngine::Async(engine) = &mut engine {
                assert!(matches!(result, Ok(FileEngineOk::Submitted)));
                engine.drain(false).unwrap();
                engine.pop(&mem).unwrap().unwrap().result().unwrap_err();
            } else {
                result.unwrap_err();
            }
            check_dirty_mem(&mem, GuestAddress(0), 8192);
        }
        let mem = create_mem();
        let mut engine = FileEngine::new(
            backing.into_file(),
            FileEngineType::Async,
            Some(DirectIo::new(4096, 512, 8192).unwrap()),
        )
        .unwrap();
        engine
            .read(0, &mem, GuestAddress(0), 8192, PendingRequest::default())
            .unwrap();
        // A reset consumes this short CQE without normal guest completion.
        engine.drain(true).unwrap();
        check_dirty_mem(&mem, GuestAddress(0), 4096);
        check_clean_mem(&mem, GuestAddress(4096), 4096);
    }

    #[test]
    fn test_direct_multi_window_transfer() {
        use crate::test_utils::single_region_mem_dirty_tracking;
        const SIZE: usize = 3 * super::direct::BUFFER_SIZE;
        const LEN: usize = 2 * super::direct::BUFFER_SIZE + 512;
        let payload: Vec<u8> = (0..LEN).map(|i| u8::try_from(i % 251).unwrap()).collect();
        for ty in [FileEngineType::Sync, FileEngineType::Async] {
            let file = TempFile::new().unwrap().into_file();
            file.write_all_at(&vec![0xee; SIZE], 0).unwrap();
            let mut engine = FileEngine::new(
                file,
                ty,
                Some(DirectIo::new(4096, 4096, SIZE as u64).unwrap()),
            )
            .unwrap();
            let mem = single_region_mem_dirty_tracking(SIZE);
            mem.write_slice(&payload, GuestAddress(1)).unwrap();
            let n = u32::try_from(LEN).unwrap();
            let result = engine
                .write(512, &mem, GuestAddress(1), n, PendingRequest::default())
                .unwrap();
            assert_eq!(completed(&mut engine, &mem, result), n);
            let mut bytes = vec![0; SIZE];
            engine.file().read_exact_at(&mut bytes, 0).unwrap();
            assert!(bytes[..512].iter().all(|b| *b == 0xee));
            assert_eq!(&bytes[512..512 + LEN], &payload);
            assert!(bytes[512 + LEN..].iter().all(|b| *b == 0xee));

            // Stop in the second window. The returned prefix and dirty bitmap track only
            // the guest data read before the short host transfer.
            let truncated = super::direct::BUFFER_SIZE + 4096;
            engine.file().set_len(truncated as u64).unwrap();
            let mem = single_region_mem_dirty_tracking(SIZE);
            let result = engine
                .read(512, &mem, GuestAddress(0), n, PendingRequest::default())
                .unwrap();
            let copied = completed(&mut engine, &mem, result) as usize;
            assert_eq!(copied, truncated - 512);
            let mut guest = vec![0; copied];
            mem.read_slice(&mut guest, GuestAddress(0)).unwrap();
            assert_eq!(guest, payload[..copied]);
            check_dirty_mem(&mem, GuestAddress(0), u32::try_from(copied).unwrap());
            check_clean_mem(&mem, GuestAddress(truncated as u64), 4096);
        }
    }
}
