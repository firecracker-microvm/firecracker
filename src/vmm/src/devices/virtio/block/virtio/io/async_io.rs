// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::fs::File;
use std::os::fd::RawFd;
use std::os::unix::io::AsRawFd;

use vm_memory::{Bytes, GuestMemoryBackend, GuestMemoryError};
use vmm_sys_util::eventfd::EventFd;

use super::direct::{BUFFER_SIZE, DirectIo};
use super::{FileEngineOk, RequestError, RequestOk};
use crate::devices::virtio::block::virtio::{IO_URING_NUM_ENTRIES, PendingRequest};
use crate::io_uring::operation::{Cqe, OpCode, Operation};
use crate::io_uring::restriction::Restriction;
use crate::io_uring::{IoUring, IoUringError};
use crate::logger::log_dev_preview_warning;
use crate::vstate::memory::{GuestAddress, GuestMemoryExtension, GuestMemoryMmap};

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
    direct: Option<DirectIo>,
    bounce_in_flight: bool,
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
}

impl WrappedRequest {
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
            direct_read_mem: None,
        })
    }

    pub(super) fn update_file(
        &mut self,
        file: File,
        direct: Option<DirectIo>,
    ) -> Result<(), AsyncIoError> {
        // The worker must publish old direct completions, including staged reads,
        // before discarding their ring and replacing the backing.
        if self.direct.is_some() && self.ring.num_ops() != 0 {
            return Err(AsyncIoError::IO(std::io::Error::other(
                "direct I/O still pending",
            )));
        }
        let ring = Self::new_ring(&file, self.completion_evt.as_raw_fd(), direct.is_some())
            .map_err(AsyncIoError::IoUring)?;

        self.file = file;
        self.ring = ring;
        self.direct = direct;
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
                if write && let Err(err) = mem.read_slice(buffer, addr) {
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
        };
        let op = if write {
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

    pub fn push_flush(&mut self, req: PendingRequest) -> Result<(), RequestError<AsyncIoError>> {
        let data = WrappedRequest {
            addr: None,
            bounced: false,
            direct_read_len: 0,
            req,
        };
        let mut op = Operation::fsync(0, data);
        if self.direct.is_some() {
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
            if data.bounced {
                self.bounce_in_flight = false;
                if let Some(addr) = data.addr {
                    let direct = self
                        .direct
                        .as_mut()
                        .expect("staged I/O belongs to a direct drive");
                    // get_slice validated the entire destination at submission. Only copy
                    // successful bytes, including a short read's prefix, and mark them dirty.
                    copy_error = mem
                        .write_slice(&direct.buffer().0[..count as usize], addr)
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
        // Staged memory belongs to the engine. Await the kernel before freeing it,
        // including when the device is discarded without delivering its CQEs.
        if self.bounce_in_flight
            && let Err(err) = self.ring.submit_and_wait_all()
        {
            // The kernel may still reference this allocation. Preserve its lifetime even
            // if a fatal drain error occurs while unwinding a test or tearing down a drive.
            crate::logger::error!("Could not drain direct I/O staging buffer on drop: {err}");
            std::mem::forget(self.direct.take());
        }
    }
}
