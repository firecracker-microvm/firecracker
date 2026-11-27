// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::fs::File;
use std::os::fd::RawFd;
use std::os::unix::io::AsRawFd;

use vm_memory::{Bytes, GuestMemoryBackend, GuestMemoryError};
use vmm_sys_util::eventfd::EventFd;

use super::direct::{BUFFER_SIZE, DirectIo};
use super::vectored::{IoVecs, mark_read_dirty};
use super::{DataSegment, FileEngineOk, RequestError, RequestOk};
use crate::devices::virtio::block::virtio::{IO_URING_NUM_ENTRIES, PendingRequest};
use crate::io_uring::operation::{Cqe, OpCode, Operation};
use crate::io_uring::restriction::Restriction;
use crate::io_uring::{IoUring, IoUringError};
use crate::logger::log_dev_preview_warning;
use crate::vstate::memory::{
    GuestAddress, GuestMemoryExtension, GuestMemoryMmap, with_plugged_slice,
};

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum AsyncIoError {
    /// Not implemented
    NotImplemented,
    /// Direct I/O staging buffer still in use
    BounceInFlight,
    /// IO: {0}
    IO(std::io::Error),
    /// IoUring: {0}
    IoUring(IoUringError),
    /// Submit: {0}
    Submit(std::io::Error),
    /// SyncAll: {0}
    SyncAll(std::io::Error),
    /// EventFd: {0}
    EventFd(std::io::Error),
    /// GuestMemory: {0}
    GuestMemory(GuestMemoryError),
}

#[derive(Debug)]
pub struct AsyncFileEngine {
    file: File,
    ring: IoUring<WrappedRequest>,
    completion_evt: EventFd,
    // The ring is dropped before its staging buffer.
    pub(super) direct: Option<DirectIo>,
    bounce_in_flight: bool,
    used_vectors: bool,
    // ActiveState keeps one memory map from activation until reset. Reset discards CQEs
    // after dropping ActiveState, so keep the map for dirty tracking on that path too.
    direct_read_mem: Option<GuestMemoryMmap>,
}

#[derive(Debug)]
pub struct WrappedRequest {
    // A read writes into the guest, possibly via the direct staging buffer.
    addr: Option<GuestAddress>,
    bounced: bool,
    // A negative zero-copy direct completion can leave an unknown part of this range dirty.
    direct_read_len: u32,
    req: PendingRequest,
    vector: Option<VectorRequest>,
}

#[derive(Debug)]
struct VectorRequest {
    // The kernel can import the iovec array after this operation is submitted.
    _iovecs: IoVecs,
    mem: GuestMemoryMmap,
    read_segments: Vec<DataSegment>,
}

impl WrappedRequest {
    fn mark_vector_dirty(&self, count: u32, failed: bool) {
        if let Some(vector) = &self.vector {
            mark_read_dirty(
                &vector.mem,
                &vector.read_segments,
                if failed { self.req.data_len() } else { count },
            );
        }
    }

    fn mark_read_dirty(&self, mem: &GuestMemoryMmap, count: u32, failed: bool) {
        if let Some(addr) = self.addr {
            mem.mark_dirty(
                addr,
                if failed { self.direct_read_len } else { count } as usize,
            );
        }
    }
}

impl AsyncFileEngine {
    fn new_ring(
        file: &File,
        completion_fd: RawFd,
        direct: bool,
    ) -> Result<IoUring<WrappedRequest>, IoUringError> {
        let mut restrictions = vec![
            Restriction::RequireFixedFds,
            Restriction::AllowOpCode(OpCode::Read),
            Restriction::AllowOpCode(OpCode::Write),
            Restriction::AllowOpCode(OpCode::Readv),
            Restriction::AllowOpCode(OpCode::Writev),
            Restriction::AllowOpCode(OpCode::Fsync),
        ];
        if direct {
            restrictions.push(Restriction::AllowDrain);
        }
        IoUring::new(
            u32::from(IO_URING_NUM_ENTRIES),
            vec![file],
            restrictions,
            Some(completion_fd),
        )
    }

    pub(super) fn from_file(
        file: File,
        direct: Option<DirectIo>,
    ) -> Result<AsyncFileEngine, AsyncIoError> {
        log_dev_preview_warning("Async file IO", Option::None);

        let completion_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(AsyncIoError::EventFd)?;
        let ring = Self::new_ring(&file, completion_evt.as_raw_fd(), direct.is_some())
            .map_err(AsyncIoError::IoUring)?;

        Ok(AsyncFileEngine {
            file,
            ring,
            completion_evt,
            direct,
            bounce_in_flight: false,
            used_vectors: false,
            direct_read_mem: None,
        })
    }

    pub(super) fn update_file(
        &mut self,
        file: File,
        direct: Option<DirectIo>,
    ) -> Result<(), AsyncIoError> {
        // The worker must publish old completions, including staged reads, before
        // discarding their ring and replacing the backing.
        if self.ring.num_ops() != 0 {
            return Err(AsyncIoError::IO(std::io::Error::other("I/O still pending")));
        }
        let ring = Self::new_ring(&file, self.completion_evt.as_raw_fd(), direct.is_some())
            .map_err(AsyncIoError::IoUring)?;

        self.file = file;
        self.ring = ring;
        self.direct = direct;
        self.used_vectors = false;
        self.direct_read_mem = None;
        Ok(())
    }

    pub fn file(&self) -> &File {
        &self.file
    }

    pub(crate) fn has_staged_request(&self) -> bool {
        self.bounce_in_flight
    }

    pub fn completion_evt(&self) -> &EventFd {
        &self.completion_evt
    }

    pub(super) fn transfer(
        &mut self,
        write: bool,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
        req: PendingRequest,
    ) -> Result<FileEngineOk, RequestError<AsyncIoError>> {
        let slice = match mem.get_slice(addr, count as usize) {
            Ok(slice) => slice,
            Err(err) => {
                return Err(RequestError {
                    req,
                    error: AsyncIoError::GuestMemory(err),
                });
            }
        };
        let mut ptr = slice.ptr_guard_mut().as_ptr() as usize;
        let mut bounced = false;
        if let Some(direct) = &mut self.direct {
            if let Err(err) = direct.check_range(offset, count) {
                return Err(RequestError {
                    req,
                    error: AsyncIoError::IO(err),
                });
            }
            let aligned_span = direct.aligned_span(offset, count);
            if count != 0 && (!aligned_span || !direct.aligned_buffer(ptr)) {
                if self.bounce_in_flight {
                    // Queue retry is driven by the staging operation's completion event.
                    return Err(RequestError {
                        req,
                        error: AsyncIoError::BounceInFlight,
                    });
                }
                if !aligned_span || count as usize > BUFFER_SIZE {
                    // Drain earlier positioned writes before reading neighboring bytes.
                    // Retain their CQEs for guest completion. A direct drive has one queue.
                    if let Err(err) = self.ring.submit_and_wait_all() {
                        return Err(RequestError {
                            req,
                            error: AsyncIoError::IoUring(err),
                        });
                    }
                    return match direct.transfer(&mut self.file, write, offset, mem, addr, count) {
                        Ok(count) => Ok(FileEngineOk::Executed(RequestOk { req, count })),
                        Err(err) => Err(RequestError {
                            req,
                            error: AsyncIoError::IO(err),
                        }),
                    };
                }
                let buffer = &mut direct.buffer().0[..count as usize];
                if write
                    && let Err(err) = with_plugged_slice(mem, addr, buffer.len(), |slice| {
                        slice.read_slice(buffer, 0)
                    })
                {
                    return Err(RequestError {
                        req,
                        error: AsyncIoError::GuestMemory(err),
                    });
                }
                ptr = buffer.as_mut_ptr() as usize;
                bounced = true;
            }
        }
        let direct_read = !write && self.direct.is_some() && !bounced;
        let data = WrappedRequest {
            direct_read_len: if direct_read { count } else { 0 },
            addr: (!write).then_some(addr),
            bounced,
            req,
            vector: None,
        };
        let op = if write && self.direct.as_ref().is_some_and(|d| d.write_through) {
            Operation::write_through(0, ptr, count, offset, data)
        } else if write {
            Operation::write(0, ptr, count, offset, data)
        } else {
            Operation::read(0, ptr, count, offset, data)
        };
        self.ring.push(op).map_err(|(err, data)| RequestError {
            req: data.req,
            error: AsyncIoError::IoUring(err),
        })?;
        if direct_read {
            self.direct_read_mem.get_or_insert_with(|| mem.clone());
        }
        self.bounce_in_flight |= bounced;
        Ok(FileEngineOk::Submitted)
    }

    pub(super) fn transfer_vectored(
        &mut self,
        write: bool,
        offset: u64,
        mem: &GuestMemoryMmap,
        segments: Vec<DataSegment>,
        req: PendingRequest,
    ) -> Result<FileEngineOk, RequestError<AsyncIoError>> {
        let iovecs = match IoVecs::new(mem, &segments) {
            Ok(iovecs) => iovecs,
            Err(err) => {
                return Err(RequestError {
                    req,
                    error: AsyncIoError::GuestMemory(err),
                });
            }
        };
        let count = req.data_len();
        if let Some(direct) = &mut self.direct {
            if let Err(err) = direct.check_range(offset, count) {
                return Err(RequestError {
                    req,
                    error: AsyncIoError::IO(err),
                });
            }
            if iovecs.needs_bounce(direct, offset) {
                if self.bounce_in_flight {
                    return Err(RequestError {
                        req,
                        error: AsyncIoError::BounceInFlight,
                    });
                }
                // One direct queue, with all earlier writes complete before a staged RMW.
                if let Err(err) = self.ring.submit_and_wait_all() {
                    return Err(RequestError {
                        req,
                        error: AsyncIoError::IoUring(err),
                    });
                }
                return match direct.transfer_segments(
                    &mut self.file,
                    write,
                    offset,
                    mem,
                    &segments,
                    count,
                ) {
                    Ok(count) => Ok(FileEngineOk::Executed(RequestOk { req, count })),
                    Err(err) => Err(RequestError {
                        req,
                        error: AsyncIoError::IO(err),
                    }),
                };
            }
        }

        let ptr = iovecs.as_slice().as_ptr() as usize;
        let len = u32::try_from(iovecs.as_slice().len()).expect("bounded by seg_max");
        let data = WrappedRequest {
            addr: None,
            bounced: false,
            direct_read_len: 0,
            req,
            vector: Some(VectorRequest {
                _iovecs: iovecs,
                mem: mem.clone(),
                read_segments: if write { Vec::new() } else { segments },
            }),
        };
        let op = if write {
            let op = Operation::writev(0, ptr, len, offset, data);
            if self.direct.as_ref().is_some_and(|d| d.write_through) {
                op.with_dsync()
            } else {
                op
            }
        } else {
            Operation::readv(0, ptr, len, offset, data)
        };
        self.ring.push(op).map_err(|(err, data)| RequestError {
            req: data.req,
            error: AsyncIoError::IoUring(err),
        })?;
        self.used_vectors = true;
        Ok(FileEngineOk::Submitted)
    }

    pub fn push_flush(&mut self, req: PendingRequest) -> Result<(), RequestError<AsyncIoError>> {
        let data = WrappedRequest {
            addr: None,
            bounced: false,
            direct_read_len: 0,
            req,
            vector: None,
        };
        let mut op = Operation::fsync(0, data);
        if self.direct.is_some() {
            // Include earlier writes submitted to this queue even if their CQEs have
            // not arrived yet. The drain also orders later requests after this flush.
            op = op.drain_before();
        }
        self.ring.push(op).map_err(|(err, data)| RequestError {
            req: data.req,
            error: AsyncIoError::IoUring(err),
        })
    }

    pub fn discard(&mut self, _range: (u64, u32)) -> Result<u32, AsyncIoError> {
        Err(AsyncIoError::NotImplemented)
    }

    pub fn kick_submission_queue(&mut self) -> Result<(), AsyncIoError> {
        self.ring
            .submit()
            .map(|_| ())
            .map_err(AsyncIoError::IoUring)
    }

    pub fn drain(&mut self, discard_cqes: bool) -> Result<(), AsyncIoError> {
        self.ring
            .submit_and_wait_all()
            .map_err(AsyncIoError::IoUring)?;

        if discard_cqes {
            // Drain the completion queue so that we may deallocate the user_data fields.
            while let Some(cqe) = self.do_pop()? {
                let failed = cqe.result().is_err();
                let count = cqe.count();
                let data = cqe.user_data();
                data.mark_vector_dirty(count, failed);
                if data.direct_read_len != 0 {
                    data.mark_read_dirty(
                        self.direct_read_mem.as_ref().expect("active direct read"),
                        count,
                        failed,
                    );
                }
            }
            self.direct_read_mem = None;
            self.bounce_in_flight = false;
        }

        Ok(())
    }

    pub fn drain_and_flush(&mut self, discard_cqes: bool) -> Result<(), AsyncIoError> {
        self.drain(discard_cqes)?;

        // Sync data out to physical media on host.
        // We don't need to call flush first since all the ops are performed through io_uring
        // and Rust shouldn't manage any data in its internal buffers.
        self.file.sync_all().map_err(AsyncIoError::SyncAll)?;

        Ok(())
    }

    fn do_pop(&mut self) -> Result<Option<Cqe<WrappedRequest>>, AsyncIoError> {
        self.ring.pop().map_err(AsyncIoError::IoUring)
    }

    pub fn pop(
        &mut self,
        mem: &GuestMemoryMmap,
    ) -> Result<Option<Cqe<PendingRequest>>, AsyncIoError> {
        let Some(cqe) = self.do_pop()? else {
            return Ok(None);
        };
        let count = cqe.count();
        let failed = cqe.result().is_err();
        let mut copy_error = false;
        let cqe = cqe.map_user_data(|data| {
            data.mark_vector_dirty(count, failed);
            if data.bounced {
                self.bounce_in_flight = false;
                if count != 0
                    && let Some(addr) = data.addr
                {
                    let direct = self
                        .direct
                        .as_mut()
                        .expect("staged I/O belongs to a direct drive");
                    // The slot may have been unplugged since submission. Copy only the bytes
                    // returned by the read and mark them dirty.
                    let buffer = &direct.buffer().0[..count as usize];
                    copy_error = with_plugged_slice(mem, addr, buffer.len(), |slice| {
                        slice.write_slice(buffer, 0)
                    })
                    .is_err();
                }
            } else {
                data.mark_read_dirty(mem, count, failed);
            }
            data.req
        });
        if copy_error {
            return Ok(Some(Cqe::new(-libc::EFAULT, cqe.user_data())));
        }
        Ok(Some(cqe))
    }
}

impl Drop for AsyncFileEngine {
    fn drop(&mut self) {
        // Staging memory and iovec tables must outlive the kernel's references.
        if (self.bounce_in_flight || self.used_vectors && self.ring.num_ops() != 0)
            && let Err(err) = self.ring.submit_and_wait_all()
        {
            crate::logger::error!("Could not drain block I/O on drop: {err}");
            self.ring.forget_pending_data();
            if self.bounce_in_flight {
                std::mem::forget(self.direct.take());
            }
        }
    }
}
