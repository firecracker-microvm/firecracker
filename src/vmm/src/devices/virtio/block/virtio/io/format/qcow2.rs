// Copyright (c) 2026 Tencent. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::any::Any;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

use imago::file::File as ImagoFile;
use imago::format::access::FormatAccess;
use imago::format::drivers::PreparedDataMapping;
use imago::qcow2::Qcow2;
use imago::raw::Raw;
use imago::{
    DenyImplicitOpenGate, FormatDriverBuilder, Mapping, Storage, StorageExt, StorageOpenOptions,
};
use vm_memory::{GuestMemoryBackend, GuestMemoryError};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::ioctl::ioctl_with_mut_ref;

vmm_sys_util::ioctl_io_nr!(BLKROGET, 0x12, 94);

use crate::devices::virtio::block::virtio::PendingRequest;
use crate::devices::virtio::block::virtio::device::FileEngineType;
use crate::devices::virtio::block::virtio::io::RequestError;
use crate::io_uring::operation::{OpCode, Operation};
use crate::io_uring::restriction::Restriction;
use crate::io_uring::{IoUring, IoUringError};
use crate::logger::log_dev_preview_warning;
use crate::vstate::memory::{GuestAddress, GuestMemoryMmap};

/// Errors specific to the QCOW2 IO engine.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum Qcow2IoError {
    /// Failed to open QCOW2 image: {0}
    Open(io::Error),
    /// QCOW2 io_uring error: {0}
    IoUring(IoUringError),
    /// QCOW2 completion event error: {0}
    EventFd(io::Error),
    /// Writable or Async QCOW2 images do not support multiple queues.
    MultiQueueNotSupported,
    /// QCOW2 images with multiple queues do not support disk replacement.
    MultiQueuePatchNotSupported,
    /// Explicit QCOW2 backing requires the Sync engine.
    BackingRequiresSync,
    /// QCOW2 read error after {completed} bytes: {source}
    Read { source: io::Error, completed: u32 },
    /// QCOW2 write error: {0}
    Write(io::Error),
    /// QCOW2 discard error: {0}
    Discard(io::Error),
    /// The QCOW2 backend cannot be re-pointed at another file after being opened.
    UnsupportedOperation,
    /// Guest memory error: {0}
    GuestMemory(GuestMemoryError),
    /// QCOW2 metadata writeback error: {0}
    MetadataFlush(io::Error),
    /// QCOW2 sync error: {0}
    Flush(io::Error),
}

const IO_BUFFER_SIZE: usize = 64 * 1024;

/// Single-owner QCOW2 access with an image lock and bounded I/O buffer.
#[derive(Debug)]
pub struct Qcow2FileEngine {
    access: FormatAccess<ImagoFile>,
    io_buffer: Box<[u8]>,
    file_id: (u64, u64),
    async_io: Option<AsyncState>,
}

#[derive(Debug)]
struct AsyncState {
    ring: IoUring<()>,
    completion_evt: EventFd,
    active: Option<AsyncRequest>,
    completed: Option<(PendingRequest, Result<u32, Qcow2IoError>)>,
}

impl Drop for AsyncState {
    fn drop(&mut self) {
        // Ring close releases fixed files asynchronously. Unregister after the owner's drain,
        // including failed image construction, so the lock can be reacquired immediately.
        if let Err(err) = self.ring.unregister_files() {
            // Payloads are quiescent. Closing the ring safely releases references later.
            crate::logger::error!("Failed to release QCOW2 fixed file: {err}");
        }
    }
}

struct AsyncRequest {
    req: PendingRequest,
    mem: GuestMemoryMmap,
    addr: GuestAddress,
    offset: u64,
    count: u32,
    completed: u32,
    write: bool,
    chunk_len: u32,
    host_offset: u64,
    mapping_state: Option<Box<dyn Any + Send>>,
}

impl fmt::Debug for AsyncRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncRequest")
            .field("req", &self.req)
            .field("offset", &self.offset)
            .field("count", &self.count)
            .field("completed", &self.completed)
            .field("write", &self.write)
            .finish_non_exhaustive()
    }
}

impl Qcow2FileEngine {
    /// Open a self-contained regular image, holding a shared or exclusive lock until drop.
    /// Writable images must be flushed before releasing the engine.
    #[cfg(test)]
    pub fn from_file(file: File, path: &Path, read_only: bool) -> Result<Self, Qcow2IoError> {
        Self::from_file_with_engine(file, path, read_only, FileEngineType::Sync, None, None)
    }

    /// Open an image with synchronous metadata and optional io_uring payload transfers.
    /// A replacement may reuse the previously registered completion event.
    pub fn from_file_with_engine(
        file: File,
        path: &Path,
        read_only: bool,
        engine: FileEngineType,
        completion_evt: Option<EventFd>,
        backing_path_on_host: Option<&str>,
    ) -> Result<Self, Qcow2IoError> {
        if backing_path_on_host.is_some() && engine == FileEngineType::Async {
            return Err(Qcow2IoError::BackingRequiresSync);
        }
        let metadata = file.metadata().map_err(Qcow2IoError::Open)?;
        if !metadata.is_file() {
            return Err(Qcow2IoError::Open(io::Error::new(
                io::ErrorKind::InvalidInput,
                "QCOW2 image must be a regular file",
            )));
        }
        if read_only {
            file.try_lock_shared()
        } else {
            file.try_lock()
        }
        .map_err(|err| Qcow2IoError::Open(err.into()))?;
        let async_io = if engine == FileEngineType::Async {
            let completion_evt = match completion_evt {
                Some(evt) => evt,
                None => EventFd::new(libc::EFD_NONBLOCK).map_err(Qcow2IoError::EventFd)?,
            };
            let ring = IoUring::new(
                1,
                vec![&file],
                vec![
                    Restriction::RequireFixedFds,
                    Restriction::AllowUnregisterFiles,
                    Restriction::AllowOpCode(OpCode::Read),
                    Restriction::AllowOpCode(OpCode::Write),
                ],
                Some(completion_evt.as_raw_fd()),
            )
            .map_err(Qcow2IoError::IoUring)?;
            Some(AsyncState {
                ring,
                completion_evt,
                active: None,
                completed: None,
            })
        } else {
            None
        };
        let storage = ImagoFile::from_open_file(
            file,
            StorageOpenOptions::new()
                .filename(path)
                .write(!read_only)
                .direct(false),
        )
        .map_err(Qcow2IoError::Open)?;
        let backing = backing_path_on_host
            .map(|backing_path| {
                let file = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(backing_path)?;
                let meta = file.metadata()?;
                if (!meta.is_file() && !meta.file_type().is_block_device())
                    || (meta.dev(), meta.ino()) == (metadata.dev(), metadata.ino())
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Backing must be a separate immutable raw file or read-only block device",
                    ));
                }
                if meta.file_type().is_block_device() {
                    let mut read_only: libc::c_int = 0;
                    // SAFETY: BLKROGET writes one c_int into a valid pointer for this open FD.
                    if unsafe { ioctl_with_mut_ref(&file, BLKROGET(), &mut read_only) } < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    if read_only != 1 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "QCOW2 block backing must be read-only",
                        ));
                    }
                }
                file.try_lock_shared().map_err(io::Error::from)?;
                let storage = ImagoFile::from_open_file(
                    file,
                    StorageOpenOptions::new()
                        .filename(backing_path)
                        .direct(false),
                )?;
                Ok(FormatAccess::new(Raw::open_image(storage, false)?))
            })
            .transpose()
            .map_err(Qcow2IoError::Open)?;
        let backing_size = backing.as_ref().map(FormatAccess::size);
        let qcow2 = Qcow2::<ImagoFile>::builder(storage)
            .require_self_contained(true)
            .backing(backing)
            .write(!read_only)
            .open(DenyImplicitOpenGate::default())
            .map_err(Qcow2IoError::Open)?;
        let access = FormatAccess::new(qcow2);
        if backing_size.is_some_and(|size| size != access.size() || size % 512 != 0) {
            return Err(Qcow2IoError::Open(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Raw backing size must equal the QCOW2 virtual size and be sector aligned",
            )));
        }

        log_dev_preview_warning("QCOW2 disk images", None);
        Ok(Self {
            access,
            io_buffer: vec![0; IO_BUFFER_SIZE].into_boxed_slice(),
            file_id: (metadata.dev(), metadata.ino()),
            async_io,
        })
    }

    /// Return the event used for kernel and software request completions.
    pub fn completion_evt(&self) -> Option<&EventFd> {
        self.async_io.as_ref().map(|state| &state.completion_evt)
    }

    /// Preserve the registered event descriptor when replacing an image.
    pub fn completion_evt_mut(&mut self) -> Option<&mut EventFd> {
        self.async_io
            .as_mut()
            .map(|state| &mut state.completion_evt)
    }

    /// Return whether an accepted async request still needs completion processing.
    pub fn is_busy(&self) -> bool {
        self.async_io
            .as_ref()
            .is_some_and(|state| state.active.is_some() || state.completed.is_some())
    }

    /// Accept one async transfer, retaining memory and publishing only completed mappings.
    pub fn start_request(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
        req: PendingRequest,
        write: bool,
    ) -> Result<(), RequestError<Qcow2IoError>> {
        assert!(!self.is_busy());
        if let Err(err) = mem.get_slice(addr, count as usize) {
            return Err(RequestError {
                req,
                error: Qcow2IoError::GuestMemory(err),
            });
        }
        let request = AsyncRequest {
            req,
            mem: mem.clone(),
            addr,
            offset,
            count,
            completed: 0,
            write,
            chunk_len: 0,
            host_offset: 0,
            mapping_state: None,
        };
        if offset.checked_add(u64::from(count)).is_none() {
            let error = Self::transfer_error(&request, io::ErrorKind::InvalidInput.into());
            self.finish_request(request, Err(error));
        } else {
            self.advance_request(request);
        }
        Ok(())
    }

    fn transfer_error(request: &AsyncRequest, source: io::Error) -> Qcow2IoError {
        if request.write {
            Qcow2IoError::Write(source)
        } else {
            Qcow2IoError::Read {
                source,
                completed: request.completed,
            }
        }
    }

    // Request processing is entered only in Async mode. One SQE owns the active request,
    // and each mapping is bounded by the remaining range in retained, validated guest memory.
    fn finish_request(&mut self, request: AsyncRequest, result: Result<u32, Qcow2IoError>) {
        let state = self.async_io.as_mut().expect("Async request owns a ring");
        state.completed = Some((request.req, result));
        // Special/zero reads and preparation failures can finish without a kernel CQE.
        if let Err(err) = state.completion_evt.write(1) {
            crate::logger::error!("Failed to signal QCOW2 completion: {err}");
        }
    }

    fn advance_request(&mut self, mut request: AsyncRequest) {
        while request.completed < request.count {
            let offset = request.offset + u64::from(request.completed);
            let len = (request.count - request.completed)
                .min(u32::try_from(IO_BUFFER_SIZE).expect("64 KiB fits in u32"));
            let prepared = if request.write {
                self.access
                    .prepare_data_mapping(offset, u64::from(len), true)
                    .and_then(|mapping| {
                        let end = mapping
                            .offset()
                            .checked_add(mapping.length())
                            .ok_or_else(|| io::Error::other("QCOW2 payload offset overflow"))?;
                        // Registered-FD writes bypass imago's cached length updates.
                        // Grow through Storage before submission, including canceled/short writes.
                        let size = mapping.storage().size()?;
                        if end > size {
                            mapping.storage().write_zeroes(size, end - size)?;
                        }
                        request.host_offset = mapping.offset();
                        request.chunk_len = u32::try_from(mapping.length())
                            .expect("Prepared mapping is bounded by chunk length");
                        request.mapping_state = mapping.into_state();
                        Ok(true)
                    })
            } else {
                self.access
                    .get_mapping(offset, u64::from(len))
                    .and_then(|(mapping, length)| {
                        request.chunk_len = u32::try_from(u64::from(len).min(length))
                            .expect("Mapping length is bounded by u32 request");
                        match mapping {
                            Mapping::Raw { offset, .. } => {
                                request.host_offset = offset;
                                Ok(true)
                            }
                            Mapping::Zero { .. } => {
                                self.io_buffer[..request.chunk_len as usize].fill(0);
                                Ok(false)
                            }
                            Mapping::Special { .. } => {
                                self.access.read(
                                    &mut self.io_buffer[..request.chunk_len as usize],
                                    offset,
                                )?;
                                Ok(false)
                            }
                            _ => Err(io::ErrorKind::UnexpectedEof.into()),
                        }
                    })
            };
            let raw = match prepared {
                Ok(raw) => raw,
                Err(err) => {
                    let error = Self::transfer_error(&request, err);
                    self.finish_request(request, Err(error));
                    return;
                }
            };
            let slice = request
                .mem
                .get_slice(request.addr, request.count as usize)
                .expect("Request retains validated guest memory");
            let chunk = slice
                .subslice(request.completed as usize, request.chunk_len as usize)
                .expect("Mapping is bounded by remaining request bytes");
            if request.write {
                chunk.copy_to(&mut self.io_buffer[..request.chunk_len as usize]);
            } else if !raw {
                chunk.copy_from(&self.io_buffer[..request.chunk_len as usize]);
                request.completed += request.chunk_len;
                continue;
            }
            let operation = if request.write {
                Operation::write(
                    0,
                    self.io_buffer.as_ptr() as usize,
                    request.chunk_len,
                    request.host_offset,
                    (),
                )
            } else {
                Operation::read(
                    0,
                    self.io_buffer.as_mut_ptr() as usize,
                    request.chunk_len,
                    request.host_offset,
                    (),
                )
            };
            let state = self.async_io.as_mut().expect("Async request owns a ring");
            match state.ring.push(operation) {
                Ok(()) => state.active = Some(request),
                Err((err, ())) => self.finish_request(request, Err(Qcow2IoError::IoUring(err))),
            }
            return;
        }
        let count = request.count;
        self.finish_request(request, Ok(count));
    }

    /// Submit the sole pending payload, waiting for it if submission needs recovery.
    pub fn kick_submission_queue(&mut self) {
        if let Some(state) = &mut self.async_io
            && let Err(err) = state.ring.submit()
        {
            // A failed enter can leave the accepted SQE pending without a completion event.
            // The existing wait handles partial submissions and EINTR without freeing it.
            crate::logger::error!("Failed to submit QCOW2 payload, waiting for completion: {err}");
            state
                .ring
                .submit_and_wait_all()
                .map_err(Qcow2IoError::IoUring)
                .unwrap_or_else(|err| {
                    crate::logger::error!(
                        "Failed to stop QCOW2 payload after submission error: {err}"
                    );
                    std::process::abort();
                });
        }
    }

    /// Cancel unfinished guest requests at reset after their kernel payload has stopped.
    pub fn cancel(&mut self) -> Result<(), Qcow2IoError> {
        if let Some(state) = &mut self.async_io {
            state
                .ring
                .submit_and_wait_all()
                .map_err(Qcow2IoError::IoUring)?;
            while state.ring.pop().map_err(Qcow2IoError::IoUring)?.is_some() {}
            // Dropping a prepared mapping defers its allocations' release without metadata I/O.
            state.active.take();
            state.completed.take();
        }
        Ok(())
    }

    fn process_completion(&mut self) -> Result<(), Qcow2IoError> {
        let state = self.async_io.as_mut().expect("Async request owns a ring");
        let Some(cqe) = state.ring.pop().map_err(Qcow2IoError::IoUring)? else {
            return Ok(());
        };
        let mut request = state
            .active
            .take()
            .expect("Sole CQE owns the active request");
        let result = cqe.result().and_then(|count| {
            if count == request.chunk_len {
                Ok(())
            } else {
                Err(if request.write {
                    io::ErrorKind::WriteZero
                } else {
                    io::ErrorKind::UnexpectedEof
                }
                .into())
            }
        });
        let result = result.and_then(|()| {
            if request.write {
                let storage = self.access.inner().collect_storage_dependencies()[0];
                let mapping = match request.mapping_state.take() {
                    Some(state) => PreparedDataMapping::to_commit(
                        storage,
                        request.host_offset,
                        u64::from(request.chunk_len),
                        state,
                    ),
                    None => PreparedDataMapping::existing(
                        storage,
                        request.host_offset,
                        u64::from(request.chunk_len),
                    ),
                };
                self.access.commit_data_mapping(mapping)
            } else {
                request
                    .mem
                    .get_slice(request.addr, request.count as usize)
                    .expect("Request retains validated guest memory")
                    .subslice(request.completed as usize, request.chunk_len as usize)
                    .expect("Mapping is bounded by remaining request bytes")
                    .copy_from(&self.io_buffer[..request.chunk_len as usize]);
                Ok(())
            }
        });
        if let Err(err) = result {
            let error = Self::transfer_error(&request, err);
            self.finish_request(request, Err(error));
        } else {
            request.completed += request.chunk_len;
            self.advance_request(request);
            self.kick_submission_queue();
        }
        Ok(())
    }

    /// Advance completed chunks and return the finished guest request, if any.
    #[allow(clippy::type_complexity)]
    pub fn pop(
        &mut self,
    ) -> Result<Option<(PendingRequest, Result<u32, Qcow2IoError>)>, Qcow2IoError> {
        self.process_completion()?;
        Ok(self
            .async_io
            .as_mut()
            .expect("Async request owns a ring")
            .completed
            .take())
    }

    /// Finish all accepted chunks and optionally discard the guest completion.
    pub fn drain(&mut self, discard: bool) -> Result<(), Qcow2IoError> {
        while self
            .async_io
            .as_ref()
            .is_some_and(|state| state.active.is_some())
        {
            self.async_io
                .as_mut()
                .expect("Async mode checked above")
                .ring
                .submit_and_wait_all()
                .map_err(Qcow2IoError::IoUring)?;
            self.process_completion()?;
        }
        if discard && let Some(state) = &mut self.async_io {
            state.completed.take();
        }
        Ok(())
    }

    /// Compare the opened image's device and inode with another file descriptor.
    pub fn same_file(&self, file: &File) -> io::Result<bool> {
        let metadata = file.metadata()?;
        Ok(self.file_id == (metadata.dev(), metadata.ino()))
    }

    /// Return the virtual disk capacity in bytes.
    pub fn disk_size(&self) -> u64 {
        self.access.size()
    }

    /// Read into guest memory and dirty only completed chunks.
    /// On I/O failure, [`Qcow2IoError::Read`] records the bytes already copied.
    pub fn read(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    ) -> Result<u32, Qcow2IoError> {
        let slice = mem
            .get_slice(addr, count as usize)
            .map_err(Qcow2IoError::GuestMemory)?;
        offset
            .checked_add(u64::from(count))
            .ok_or_else(|| Qcow2IoError::Read {
                source: io::Error::new(io::ErrorKind::InvalidInput, "QCOW2 read offset overflow"),
                completed: 0,
            })?;

        for completed in (0..count).step_by(IO_BUFFER_SIZE) {
            let start = completed as usize;
            let len = (slice.len() - start).min(IO_BUFFER_SIZE);
            self.access
                .read(&mut self.io_buffer[..len], offset + u64::from(completed))
                .map_err(|source| Qcow2IoError::Read { source, completed })?;
            slice
                .subslice(start, len)
                .map_err(|err| Qcow2IoError::GuestMemory(err.into()))?
                .copy_from(&self.io_buffer[..len]);
        }

        Ok(count)
    }

    /// Write guest bytes; an error may follow partially completed writes.
    pub fn write(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    ) -> Result<u32, Qcow2IoError> {
        let slice = mem
            .get_slice(addr, count as usize)
            .map_err(Qcow2IoError::GuestMemory)?;
        offset.checked_add(u64::from(count)).ok_or_else(|| {
            Qcow2IoError::Write(io::Error::new(
                io::ErrorKind::InvalidInput,
                "QCOW2 write offset overflow",
            ))
        })?;

        for completed in (0..count).step_by(IO_BUFFER_SIZE) {
            let start = completed as usize;
            let len = (slice.len() - start).min(IO_BUFFER_SIZE);
            slice
                .subslice(start, len)
                .map_err(|err| Qcow2IoError::GuestMemory(err.into()))?
                .copy_to(&mut self.io_buffer[..len]);
            self.access
                .write(&self.io_buffer[..len], offset + u64::from(completed))
                .map_err(Qcow2IoError::Write)?;
        }

        Ok(count)
    }

    /// Zero the guest range and reclaim unreferenced data where storage permits.
    pub fn discard(&mut self, range: (u64, u32)) -> Result<u32, Qcow2IoError> {
        self.access
            .discard_to_zero(range.0, u64::from(range.1))
            .map_err(Qcow2IoError::Discard)?;
        Ok(range.1)
    }

    /// Publish writable mappings and sync storage; read-only engines do nothing.
    pub fn flush(&self) -> Result<(), Qcow2IoError> {
        if !self.access.inner().writable() {
            return Ok(());
        }
        self.access.flush().map_err(Qcow2IoError::MetadataFlush)?;
        self.access.sync().map_err(Qcow2IoError::Flush)
    }
}

impl Drop for Qcow2FileEngine {
    fn drop(&mut self) {
        if let Err(err) = self.drain(true) {
            // Kernel I/O may still own the staging buffer and a prepared mapping.
            // Continuing teardown would free memory or recycle clusters under that I/O.
            crate::logger::error!("Failed to stop QCOW2 I/O during teardown: {err}");
            std::process::abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::virtio::block::virtio::test_utils::create_test_qcow2;
    use crate::test_utils::single_region_mem_dirty_tracking;
    use crate::vstate::memory::{Bitmap, Bytes, GuestMemoryExtension};

    #[test]
    fn test_qcow2_explicit_backing_validation() {
        use vmm_sys_util::tempfile::TempFile;

        let image = create_test_qcow2();
        let backing = TempFile::new().unwrap();
        let image_path = image.as_path().to_str().unwrap();
        let backing_path = backing.as_path().to_str().unwrap();
        for (path, engine) in [
            (image_path, FileEngineType::Sync),
            (backing_path, FileEngineType::Sync),
            (backing_path, FileEngineType::Async),
            ("/dev/null", FileEngineType::Sync),
        ] {
            let result = Qcow2FileEngine::from_file_with_engine(
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(image_path)
                    .unwrap(),
                image.as_path(),
                false,
                engine,
                None,
                Some(path),
            );
            if engine == FileEngineType::Async {
                assert!(matches!(result, Err(Qcow2IoError::BackingRequiresSync)));
            } else {
                assert!(
                    matches!(result, Err(Qcow2IoError::Open(err)) if err.kind() == io::ErrorKind::InvalidInput)
                );
            }
        }
    }

    #[test]
    fn test_qcow2_async_failed_registration_releases_lock() {
        use std::os::unix::fs::FileExt;

        // Register opcodes 3 and 12 are UNREGISTER_FILES and ENABLE_RINGS.
        // Opcode 0 is unused by this engine, covering failed open with normal unregister.
        for (opcode, invalid) in [(0, true), (3, false), (3, true), (12, false)] {
            let file = create_test_qcow2();
            if invalid {
                file.as_file().write_at(&[0; 4], 0).unwrap();
            }
            std::thread::scope(|scope| {
                scope
                    .spawn(|| {
                        let instructions = [
                            (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 0),
                            (
                                libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                                0,
                                3,
                                u32::try_from(libc::SYS_io_uring_register).unwrap(),
                            ),
                            (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 24),
                            (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 0, 1, opcode),
                            (
                                libc::BPF_RET | libc::BPF_K,
                                0,
                                0,
                                libc::SECCOMP_RET_ERRNO | u32::try_from(libc::EIO).unwrap(),
                            ),
                            (libc::BPF_RET | libc::BPF_K, 0, 0, libc::SECCOMP_RET_ALLOW),
                        ];
                        let filter: crate::seccomp::BpfProgram = instructions
                            .into_iter()
                            .map(|(code, jt, jf, k)| {
                                let code = u16::try_from(code).unwrap().to_ne_bytes();
                                let k = k.to_ne_bytes();
                                u64::from_ne_bytes([
                                    code[0], code[1], jt, jf, k[0], k[1], k[2], k[3],
                                ])
                            })
                            .collect();
                        crate::seccomp::apply_filter(&filter).unwrap();
                        let result = Qcow2FileEngine::from_file_with_engine(
                            std::fs::OpenOptions::new()
                                .read(true)
                                .write(true)
                                .open(file.as_path())
                                .unwrap(),
                            file.as_path(),
                            false,
                            FileEngineType::Async,
                            None,
                            None,
                        );
                        if invalid {
                            assert!(matches!(result, Err(Qcow2IoError::Open(_))));
                        } else if opcode == 12 {
                            assert!(matches!(result,
                                Err(Qcow2IoError::IoUring(IoUringError::Enable(err)))
                                    if err.raw_os_error() == Some(libc::EIO)));
                        } else {
                            drop(result.unwrap());
                        }
                    })
                    .join()
                    .unwrap();
            });
            let reopened = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(file.as_path())
                .unwrap();
            if opcode != 3 {
                reopened.try_lock().unwrap();
            } else {
                // Ring close releases references asynchronously when unregister is unavailable.
                reopened.lock().unwrap();
            }
        }
    }

    #[test]
    fn test_qcow2_async_submit_error_recovers() {
        for errno in [libc::EINTR, libc::EIO] {
            std::thread::spawn(move || {
                let file = create_test_qcow2();
                let mem = single_region_mem_dirty_tracking(4096);
                mem.write_slice(&[0xa7; 512], GuestAddress(0)).unwrap();
                let mut engine = Qcow2FileEngine::from_file_with_engine(
                    std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(file.as_path())
                        .unwrap(),
                    file.as_path(),
                    false,
                    FileEngineType::Async,
                    None,
                    None,
                )
                .unwrap();
                engine
                    .start_request(
                        512,
                        &mem,
                        GuestAddress(0),
                        512,
                        PendingRequest::default(),
                        true,
                    )
                    .unwrap();
                // Fail non-waiting enter, allowing the recovery wait (argument 2) to succeed.
                let instructions = [
                    (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 0),
                    (
                        libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                        0,
                        3,
                        u32::try_from(libc::SYS_io_uring_enter).unwrap(),
                    ),
                    (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 32),
                    (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 0, 1, 0),
                    (
                        libc::BPF_RET | libc::BPF_K,
                        0,
                        0,
                        libc::SECCOMP_RET_ERRNO | u32::try_from(errno).unwrap(),
                    ),
                    (libc::BPF_RET | libc::BPF_K, 0, 0, libc::SECCOMP_RET_ALLOW),
                ];
                let filter: crate::seccomp::BpfProgram = instructions
                    .into_iter()
                    .map(|(code, jt, jf, k)| {
                        let code = u16::try_from(code).unwrap().to_ne_bytes();
                        let k = k.to_ne_bytes();
                        u64::from_ne_bytes([code[0], code[1], jt, jf, k[0], k[1], k[2], k[3]])
                    })
                    .collect();
                crate::seccomp::apply_filter(&filter).unwrap();
                engine.kick_submission_queue();
                assert_eq!(engine.pop().unwrap().unwrap().1.unwrap(), 512);
                engine.flush().unwrap();
                engine.read(512, &mem, GuestAddress(0), 512).unwrap();
                let mut actual = [0; 512];
                mem.read_slice(&mut actual, GuestAddress(0)).unwrap();
                assert_eq!(actual, [0xa7; 512]);
            })
            .join()
            .unwrap();
        }
    }

    #[test]
    fn test_qcow2_async_ordering_dirty_tracking_and_short_read() {
        let file = create_test_qcow2();
        let count = 2 * IO_BUFFER_SIZE + 512;
        let mem = single_region_mem_dirty_tracking(count + 8192);
        let addr = GuestAddress(4096);
        let mut engine = Qcow2FileEngine::from_file_with_engine(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(file.as_path())
                .unwrap(),
            file.as_path(),
            false,
            FileEngineType::Async,
            None,
            None,
        )
        .unwrap();
        let data = vec![0xa7; count];
        mem.write_slice(&data, addr).unwrap();
        engine
            .start_request(
                512,
                &mem,
                addr,
                u32::try_from(count).unwrap(),
                PendingRequest::default(),
                true,
            )
            .unwrap();
        assert!(engine.is_busy());
        engine.drain(false).unwrap();
        assert!(engine.is_busy());
        assert_eq!(
            engine.pop().unwrap().unwrap().1.unwrap(),
            u32::try_from(count).unwrap()
        );
        assert!(!engine.is_busy());
        engine.discard((IO_BUFFER_SIZE as u64, 512)).unwrap();
        engine.flush().unwrap();
        let mut expected = data;
        expected[IO_BUFFER_SIZE - 512..IO_BUFFER_SIZE].fill(0);
        mem.write_slice(&vec![0; count], addr).unwrap();
        mem.reset_dirty();
        engine
            .start_request(
                512,
                &mem,
                addr,
                u32::try_from(count).unwrap(),
                PendingRequest::default(),
                false,
            )
            .unwrap();
        engine.drain(false).unwrap();
        assert_eq!(
            engine.pop().unwrap().unwrap().1.unwrap(),
            u32::try_from(count).unwrap()
        );
        let mut actual = vec![0; count];
        mem.read_slice(&mut actual, addr).unwrap();
        assert_eq!(actual, expected);
        let slice = mem.get_slice(GuestAddress(0), count + 8192).unwrap();
        assert!(!slice.bitmap().dirty_at(0));
        assert!(slice.bitmap().dirty_at(4096));
        assert!(slice.bitmap().dirty_at(4096 + count - 1));
        assert!(!slice.bitmap().dirty_at(count + 8192 - 1));

        let (mapping, _) = engine
            .access
            .get_mapping(512 + 2 * IO_BUFFER_SIZE as u64, 512)
            .unwrap();
        let Mapping::Raw { offset, .. } = mapping else {
            panic!("Expected allocated data")
        };
        file.as_file().set_len(offset + 511).unwrap();
        mem.write_slice(&vec![0x5d; count], addr).unwrap();
        mem.reset_dirty();
        engine
            .start_request(
                512,
                &mem,
                addr,
                u32::try_from(count).unwrap(),
                PendingRequest::default(),
                false,
            )
            .unwrap();
        engine.drain(false).unwrap();
        let Err(Qcow2IoError::Read { source, completed }) = engine.pop().unwrap().unwrap().1 else {
            panic!("Expected short read");
        };
        assert_eq!(source.kind(), io::ErrorKind::UnexpectedEof);
        assert!(completed > 0);
        assert!(completed < u32::try_from(count).unwrap());
        mem.read_slice(&mut actual, addr).unwrap();
        assert_eq!(
            &actual[..completed as usize],
            &expected[..completed as usize]
        );
        assert!(
            actual[completed as usize..]
                .iter()
                .all(|byte| *byte == 0x5d)
        );
        let slice = mem.get_slice(addr, count).unwrap();
        assert!(slice.bitmap().dirty_at(completed as usize - 1));
        assert!(!slice.bitmap().dirty_at(completed as usize));
        engine
            .start_request(u64::MAX, &mem, addr, 512, PendingRequest::default(), false)
            .unwrap();
        assert!(matches!(
            engine.pop().unwrap().unwrap().1,
            Err(Qcow2IoError::Read { completed: 0, .. })
        ));
    }

    #[test]
    fn test_qcow2_async_failed_and_cancelled_payload_preserves_mapping() {
        let file = create_test_qcow2();
        let mem = single_region_mem_dirty_tracking(4096);
        mem.write_slice(&[0xa7; 512], GuestAddress(0)).unwrap();
        let mut engine = Qcow2FileEngine::from_file_with_engine(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(file.as_path())
                .unwrap(),
            file.as_path(),
            false,
            FileEngineType::Async,
            None,
            None,
        )
        .unwrap();
        let read_only = File::open(file.as_path()).unwrap();
        let state = engine.async_io.as_mut().unwrap();
        state.ring.unregister_files().unwrap();
        state.ring = IoUring::new(
            1,
            vec![&read_only],
            vec![
                Restriction::RequireFixedFds,
                Restriction::AllowUnregisterFiles,
                Restriction::AllowOpCode(OpCode::Write),
            ],
            Some(state.completion_evt.as_raw_fd()),
        )
        .unwrap();
        engine
            .start_request(
                512,
                &mem,
                GuestAddress(0),
                512,
                PendingRequest::default(),
                true,
            )
            .unwrap();
        let failed_host_offset = engine
            .async_io
            .as_ref()
            .unwrap()
            .active
            .as_ref()
            .unwrap()
            .host_offset;
        engine.drain(false).unwrap();
        let Err(Qcow2IoError::Write(error)) = engine.pop().unwrap().unwrap().1 else {
            panic!("Expected write failure");
        };
        assert_eq!(error.raw_os_error(), Some(libc::EBADF));
        engine.flush().unwrap();
        engine.read(512, &mem, GuestAddress(0), 512).unwrap();
        let mut actual = [0; 512];
        mem.read_slice(&mut actual, GuestAddress(0)).unwrap();
        assert_eq!(actual, [0; 512]);

        let state = engine.async_io.as_mut().unwrap();
        state.ring.unregister_files().unwrap();
        state.ring = IoUring::new(
            1,
            vec![file.as_file()],
            vec![
                Restriction::RequireFixedFds,
                Restriction::AllowUnregisterFiles,
                Restriction::AllowOpCode(OpCode::Write),
            ],
            Some(state.completion_evt.as_raw_fd()),
        )
        .unwrap();
        mem.write_slice(&[0x5d; 512], GuestAddress(0)).unwrap();
        engine
            .start_request(
                512,
                &mem,
                GuestAddress(0),
                512,
                PendingRequest::default(),
                true,
            )
            .unwrap();
        assert_eq!(
            engine
                .async_io
                .as_ref()
                .unwrap()
                .active
                .as_ref()
                .unwrap()
                .host_offset,
            failed_host_offset
        );
        engine.drain(false).unwrap();
        assert_eq!(engine.pop().unwrap().unwrap().1.unwrap(), 512);
        let cancelled_offset = 2 * IO_BUFFER_SIZE as u64;
        mem.write_slice(&[0xa7; 512], GuestAddress(0)).unwrap();
        engine
            .start_request(
                cancelled_offset,
                &mem,
                GuestAddress(0),
                512,
                PendingRequest::default(),
                true,
            )
            .unwrap();
        let cancelled_host = engine
            .async_io
            .as_ref()
            .unwrap()
            .active
            .as_ref()
            .unwrap()
            .host_offset;
        engine.cancel().unwrap();
        engine
            .read(cancelled_offset, &mem, GuestAddress(0), 512)
            .unwrap();
        mem.read_slice(&mut actual, GuestAddress(0)).unwrap();
        assert_eq!(actual, [0; 512]);
        engine.flush().unwrap();
        mem.write_slice(&[0x5d; 512], GuestAddress(0)).unwrap();
        engine
            .start_request(
                cancelled_offset,
                &mem,
                GuestAddress(0),
                512,
                PendingRequest::default(),
                true,
            )
            .unwrap();
        assert_eq!(
            engine
                .async_io
                .as_ref()
                .unwrap()
                .active
                .as_ref()
                .unwrap()
                .host_offset,
            cancelled_host
        );
        engine.drain(false).unwrap();
        assert_eq!(engine.pop().unwrap().unwrap().1.unwrap(), 512);
        engine
            .read(cancelled_offset, &mem, GuestAddress(0), 512)
            .unwrap();
        mem.read_slice(&mut actual, GuestAddress(0)).unwrap();
        assert_eq!(actual, [0x5d; 512]);
        engine.flush().unwrap();
    }

    #[test]
    fn test_qcow2_sync_dirty_tracking_and_short_read() {
        let file = create_test_qcow2();
        let count = 2 * IO_BUFFER_SIZE + 512;
        let addr = GuestAddress(4096);
        let mem = single_region_mem_dirty_tracking(count + 8192);
        let data = vec![0xa7; count];
        mem.write_slice(&data, addr).unwrap();
        let mut engine = Qcow2FileEngine::from_file(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(file.as_path())
                .unwrap(),
            file.as_path(),
            false,
        )
        .unwrap();
        assert_eq!(
            engine
                .write(512, &mem, addr, u32::try_from(count).unwrap())
                .unwrap(),
            u32::try_from(count).unwrap()
        );
        engine.flush().unwrap();
        drop(engine);

        let mut engine =
            Qcow2FileEngine::from_file(File::open(file.as_path()).unwrap(), file.as_path(), true)
                .unwrap();
        mem.write_slice(&vec![0; count], addr).unwrap();
        mem.reset_dirty();
        assert_eq!(
            engine
                .read(512, &mem, addr, u32::try_from(count).unwrap())
                .unwrap(),
            u32::try_from(count).unwrap()
        );
        let mut actual = vec![0; count];
        mem.read_slice(&mut actual, addr).unwrap();
        assert_eq!(actual, data);
        let slice = mem.get_slice(GuestAddress(0), count + 8192).unwrap();
        assert!(!slice.bitmap().dirty_at(0));
        assert!(slice.bitmap().dirty_at(4096));
        assert!(slice.bitmap().dirty_at(4096 + count - 1));
        assert!(!slice.bitmap().dirty_at(count + 8192 - 1));
        assert!(matches!(
            engine.write(0, &mem, addr, 512),
            Err(Qcow2IoError::Write(_))
        ));

        let completed = 2 * IO_BUFFER_SIZE;
        let (mapping, _) = engine
            .access
            .get_mapping(512 + completed as u64, 512)
            .unwrap();
        let imago::Mapping::Raw { offset, .. } = mapping else {
            panic!("Expected allocated data");
        };
        file.as_file().set_len(offset + 511).unwrap();
        mem.write_slice(&vec![0x5d; count], addr).unwrap();
        mem.reset_dirty();
        let Err(Qcow2IoError::Read {
            source,
            completed: actual_completed,
        }) = engine.read(512, &mem, addr, u32::try_from(count).unwrap())
        else {
            panic!("Expected short-read error");
        };
        assert_eq!(source.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(actual_completed as usize, completed);
        mem.read_slice(&mut actual, addr).unwrap();
        assert_eq!(&actual[..completed], &data[..completed]);
        assert!(actual[completed..].iter().all(|byte| *byte == 0x5d));
        let slice = mem.get_slice(addr, count).unwrap();
        assert!(slice.bitmap().dirty_at(completed - 1));
        assert!(!slice.bitmap().dirty_at(completed));
        mem.reset_dirty();
        assert!(matches!(
            engine.read(u64::MAX, &mem, GuestAddress(0), 512),
            Err(Qcow2IoError::Read { completed: 0, .. })
        ));
        assert!(matches!(
            engine.read(0, &mem, GuestAddress(count as u64 + 8192), 512),
            Err(Qcow2IoError::GuestMemory(_))
        ));
        assert!(
            !mem.get_slice(GuestAddress(0), count + 8192)
                .unwrap()
                .bitmap()
                .dirty_at(0)
        );
    }
}
