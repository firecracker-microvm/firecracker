// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::convert::From;
use std::io::{self, Seek, SeekFrom, Write};
use std::result;

use logger::{IncMetric, METRICS};
use virtio_gen::virtio_blk::*;
use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemoryError, GuestMemoryMmap};

use super::super::DescriptorChain;
use super::device::{CacheType, DiskProperties};
use super::{Error, SECTOR_SHIFT, SECTOR_SIZE};

#[derive(Debug)]
pub enum IoErrStatus {
    BadRequest(Error),
    Flush(io::Error),
    // Read(num_used_bytes, GuestMemoryError)
    Read(u32, GuestMemoryError),
    Seek(io::Error),
    SyncAll(io::Error),
    Write(GuestMemoryError),
}

#[derive(Debug)]
pub enum ErrStatus {
    IoErr(IoErrStatus),
    Unsupported(u32),
}

#[derive(Debug)]
pub enum Status {
    // Ok(num_used_bytes)
    Ok(u32),
    Err(ErrStatus),
}

impl Status {
    pub fn from_result(result: result::Result<u32, ErrStatus>) -> Status {
        match result {
            Ok(status) => Status::Ok(status),
            Err(status) => Status::Err(status),
        }
    }

    pub fn virtio_blk_status(&self) -> u32 {
        match self {
            Status::Ok(_) => VIRTIO_BLK_S_OK,
            Status::Err(status) => match status {
                ErrStatus::IoErr(_) => VIRTIO_BLK_S_IOERR,
                ErrStatus::Unsupported(_) => VIRTIO_BLK_S_UNSUPP,
            },
        }
    }

    pub fn num_used_bytes(&self) -> u32 {
        let num_used_bytes = match self {
            Status::Ok(num_used_bytes) => *num_used_bytes,
            Status::Err(status) => match status {
                ErrStatus::IoErr(io_err) => match io_err {
                    IoErrStatus::Read(num_used_bytes, _) => *num_used_bytes,
                    _ => 0,
                },
                ErrStatus::Unsupported(_) => 0,
            },
        };
        // account for the status byte
        num_used_bytes + 1
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RequestType {
    In,
    Out,
    Flush,
    GetDeviceID,
    Unsupported(u32),
}

impl From<u32> for RequestType {
    fn from(value: u32) -> Self {
        match value {
            VIRTIO_BLK_T_IN => RequestType::In,
            VIRTIO_BLK_T_OUT => RequestType::Out,
            VIRTIO_BLK_T_FLUSH => RequestType::Flush,
            VIRTIO_BLK_T_GET_ID => RequestType::GetDeviceID,
            t => RequestType::Unsupported(t),
        }
    }
}

pub struct Request {
    pub request_type: RequestType,
    pub data_len: u32,
    pub status_addr: GuestAddress,
    sector: u64,
    data_addr: GuestAddress,
}

/// The request header represents the mandatory fields of each block device request.
///
/// A request header contains the following fields:
///   * request_type: an u32 value mapping to a read, write or flush operation.
///   * reserved: 32 bits are reserved for future extensions of the Virtio Spec.
///   * sector: an u64 value representing the offset where a read/write is to occur.
///
/// The header simplifies reading the request from memory as all request follow
/// the same memory layout.
#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct RequestHeader {
    request_type: u32,
    _reserved: u32,
    sector: u64,
}

// Safe because RequestHeader only contains plain data.
unsafe impl ByteValued for RequestHeader {}

impl RequestHeader {
    pub fn new(request_type: u32, sector: u64) -> RequestHeader {
        RequestHeader {
            request_type,
            _reserved: 0,
            sector,
        }
    }
    /// Reads the request header from GuestMemoryMmap starting at `addr`.
    ///
    /// Virtio 1.0 specifies that the data is transmitted by the driver in little-endian
    /// format. Firecracker currently runs only on little endian platforms so we don't
    /// need to do an explicit little endian read as all reads are little endian by default.
    /// When running on a big endian platform, this code should not compile, and support
    /// for explicit little endian reads is required.
    #[cfg(target_endian = "little")]
    fn read_from(memory: &GuestMemoryMmap, addr: GuestAddress) -> result::Result<Self, Error> {
        let request_header: RequestHeader = memory.read_obj(addr).map_err(Error::GuestMemory)?;
        Ok(request_header)
    }
}

impl Request {
    pub fn parse(
        avail_desc: &DescriptorChain,
        mem: &GuestMemoryMmap,
    ) -> result::Result<Request, Error> {
        // The head contains the request type which MUST be readable.
        if avail_desc.is_write_only() {
            return Err(Error::UnexpectedWriteOnlyDescriptor);
        }

        let request_header = RequestHeader::read_from(mem, avail_desc.addr)?;
        let mut req = Request {
            request_type: RequestType::from(request_header.request_type),
            sector: request_header.sector,
            data_addr: GuestAddress(0),
            data_len: 0,
            status_addr: GuestAddress(0),
        };

        let data_desc;
        let status_desc;
        let desc = avail_desc
            .next_descriptor()
            .ok_or(Error::DescriptorChainTooShort)?;

        if !desc.has_next() {
            status_desc = desc;
            // Only flush requests are allowed to skip the data descriptor.
            if req.request_type != RequestType::Flush {
                return Err(Error::DescriptorChainTooShort);
            }
        } else {
            data_desc = desc;
            status_desc = data_desc
                .next_descriptor()
                .ok_or(Error::DescriptorChainTooShort)?;

            if data_desc.is_write_only() && req.request_type == RequestType::Out {
                return Err(Error::UnexpectedWriteOnlyDescriptor);
            }
            if !data_desc.is_write_only() && req.request_type == RequestType::In {
                return Err(Error::UnexpectedReadOnlyDescriptor);
            }
            if !data_desc.is_write_only() && req.request_type == RequestType::GetDeviceID {
                return Err(Error::UnexpectedReadOnlyDescriptor);
            }

            req.data_addr = data_desc.addr;
            req.data_len = data_desc.len;
        }

        // The status MUST always be writable.
        if !status_desc.is_write_only() {
            return Err(Error::UnexpectedReadOnlyDescriptor);
        }

        if status_desc.len < 1 {
            return Err(Error::DescriptorLengthTooSmall);
        }

        req.status_addr = status_desc.addr;

        Ok(req)
    }

    fn execute_seek(&self, disk: &mut DiskProperties) -> result::Result<(), ErrStatus> {
        // TODO: perform this logic at request parsing level in the future.
        // Check that the data length is a multiple of 512 as specified in the virtio standard.
        if u64::from(self.data_len) % SECTOR_SIZE != 0 {
            return Err(ErrStatus::IoErr(IoErrStatus::BadRequest(
                Error::InvalidDataLength,
            )));
        }
        let top_sector = self
            .sector
            .checked_add(u64::from(self.data_len) >> SECTOR_SHIFT)
            .ok_or(ErrStatus::IoErr(IoErrStatus::BadRequest(
                Error::InvalidOffset,
            )))?;
        if top_sector > disk.nsectors() {
            return Err(ErrStatus::IoErr(IoErrStatus::BadRequest(
                Error::InvalidOffset,
            )));
        }

        disk.file_mut()
            .seek(SeekFrom::Start(self.sector << SECTOR_SHIFT))
            .map_err(|e| ErrStatus::IoErr(IoErrStatus::Seek(e)))?;

        Ok(())
    }

    pub(crate) fn execute(
        &self,
        disk: &mut DiskProperties,
        mem: &GuestMemoryMmap,
    ) -> result::Result<u32, ErrStatus> {
        let cache_type = disk.cache_type();

        match self.request_type {
            RequestType::In => {
                self.execute_seek(disk)?;
                mem.read_exact_from(self.data_addr, disk.file_mut(), self.data_len as usize)
                    .map(|_| {
                        METRICS.block.read_bytes.add(self.data_len as usize);
                        METRICS.block.read_count.inc();
                        self.data_len
                    })
                    .map_err(|e| {
                        let mut num_used_bytes = self.data_len;
                        if let GuestMemoryError::PartialBuffer { completed, .. } = e {
                            METRICS.block.read_bytes.add(completed);
                            // It's safe to cast to u32 since completed < data_len.
                            num_used_bytes = completed as u32;
                        }
                        ErrStatus::IoErr(IoErrStatus::Read(num_used_bytes, e))
                    })
            }
            RequestType::Out => {
                self.execute_seek(disk)?;
                mem.write_all_to(self.data_addr, disk.file_mut(), self.data_len as usize)
                    .map(|_| {
                        METRICS.block.write_bytes.add(self.data_len as usize);
                        METRICS.block.write_count.inc();
                        0
                    })
                    .map_err(|e| {
                        if let GuestMemoryError::PartialBuffer { completed, .. } = e {
                            METRICS.block.write_bytes.add(completed);
                        }
                        ErrStatus::IoErr(IoErrStatus::Write(e))
                    })
            }
            RequestType::Flush => {
                match cache_type {
                    CacheType::Writeback => {
                        // flush() first to force any cached data out.
                        disk.file_mut()
                            .flush()
                            .map_err(|e| ErrStatus::IoErr(IoErrStatus::Flush(e)))?;
                        // Sync data out to physical media on host.
                        disk.file_mut()
                            .sync_all()
                            .map_err(|e| ErrStatus::IoErr(IoErrStatus::SyncAll(e)))?;
                        METRICS.block.flush_count.inc();
                    }
                    CacheType::Unsafe => {
                        // This is a noop.
                    }
                };
                Ok(0)
            }
            RequestType::GetDeviceID => {
                let disk_id = disk.image_id();
                if (self.data_len as usize) < disk_id.len() {
                    return Err(ErrStatus::IoErr(IoErrStatus::BadRequest(
                        Error::InvalidOffset,
                    )));
                }
                mem.write_slice(disk_id, self.data_addr)
                    .map(|_| VIRTIO_BLK_ID_BYTES)
                    .map_err(|e| ErrStatus::IoErr(IoErrStatus::Write(e)))
            }
            RequestType::Unsupported(op) => Err(ErrStatus::Unsupported(op)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::virtio::queue::tests::*;
    use crate::virtio::test_utils::VirtQueue;
    use vm_memory::{Address, GuestAddress, GuestMemory};

    #[test]
    fn test_read_request_header() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let addr = GuestAddress(0);
        let sector = 123_454_321;

        // Test that all supported request types are read correctly from memory.
        let supported_request_types = vec![
            VIRTIO_BLK_T_IN,
            VIRTIO_BLK_T_OUT,
            VIRTIO_BLK_T_FLUSH,
            VIRTIO_BLK_T_GET_ID,
        ];

        for request_type in supported_request_types {
            let expected_header = RequestHeader::new(request_type, sector);
            mem.write_obj::<RequestHeader>(expected_header, addr)
                .unwrap();

            let actual_header = RequestHeader::read_from(&mem, addr).unwrap();
            assert_eq!(actual_header.request_type, expected_header.request_type);
            assert_eq!(actual_header.sector, expected_header.sector);
        }

        // Test that trying to read a request header that goes outside of the
        // memory boundary fails.
        assert!(RequestHeader::read_from(&mem, GuestAddress(0x1000)).is_err());
    }

    #[test]
    fn test_request_type_from() {
        assert_eq!(RequestType::from(VIRTIO_BLK_T_IN), RequestType::In);
        assert_eq!(RequestType::from(VIRTIO_BLK_T_OUT), RequestType::Out);
        assert_eq!(RequestType::from(VIRTIO_BLK_T_FLUSH), RequestType::Flush);
        assert_eq!(
            RequestType::from(VIRTIO_BLK_T_GET_ID),
            RequestType::GetDeviceID
        );
        assert_eq!(RequestType::from(42), RequestType::Unsupported(42));
    }

    #[test]
    fn test_status() {
        {
            let status = Status::from_result(Ok(10));
            assert_eq!(status.virtio_blk_status(), VIRTIO_BLK_S_OK);
            assert_eq!(status.num_used_bytes(), 11);
        }

        {
            let status = Status::from_result(Err(ErrStatus::IoErr(IoErrStatus::BadRequest(
                Error::InvalidOffset,
            ))));
            assert_eq!(status.virtio_blk_status(), VIRTIO_BLK_S_IOERR);
            assert_eq!(status.num_used_bytes(), 1);
        }

        {
            let status = Status::from_result(Err(ErrStatus::IoErr(IoErrStatus::Flush(
                io::Error::from_raw_os_error(42),
            ))));
            assert_eq!(status.virtio_blk_status(), VIRTIO_BLK_S_IOERR);
            assert_eq!(status.num_used_bytes(), 1);
        }

        {
            let status = Status::from_result(Err(ErrStatus::IoErr(IoErrStatus::Read(
                0,
                GuestMemoryError::InvalidBackendAddress,
            ))));
            assert_eq!(status.virtio_blk_status(), VIRTIO_BLK_S_IOERR);
            assert_eq!(status.num_used_bytes(), 1);
        }

        {
            let status = Status::from_result(Err(ErrStatus::IoErr(IoErrStatus::Read(
                10,
                GuestMemoryError::PartialBuffer {
                    expected: 10,
                    completed: 20,
                },
            ))));
            assert_eq!(status.virtio_blk_status(), VIRTIO_BLK_S_IOERR);
            assert_eq!(status.num_used_bytes(), 11);
        }

        {
            let status = Status::from_result(Err(ErrStatus::IoErr(IoErrStatus::Seek(
                io::Error::from_raw_os_error(42),
            ))));
            assert_eq!(status.virtio_blk_status(), VIRTIO_BLK_S_IOERR);
            assert_eq!(status.num_used_bytes(), 1);
        }

        {
            let status = Status::from_result(Err(ErrStatus::IoErr(IoErrStatus::Write(
                GuestMemoryError::InvalidBackendAddress,
            ))));
            assert_eq!(status.virtio_blk_status(), VIRTIO_BLK_S_IOERR);
            assert_eq!(status.num_used_bytes(), 1);
        }

        {
            let status = Status::from_result(Err(ErrStatus::Unsupported(0)));
            assert_eq!(status.virtio_blk_status(), VIRTIO_BLK_S_UNSUPP);
            assert_eq!(status.num_used_bytes(), 1);
        }
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_parse() {
        let m = &GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vq = VirtQueue::new(GuestAddress(0), &m, 16);

        assert!(vq.end().0 < 0x1000);

        let request_type_descriptor = 0;
        let data_descriptor = 1;
        let status_descriptor = 2;

        vq.avail.ring[0].set(0);
        vq.avail.idx.set(1);

        {
            let mut q = vq.create_queue();
            // Write only request type descriptor.
            vq.dtable[request_type_descriptor].set(0x1000, 0x1000, VIRTQ_DESC_F_WRITE, 1);
            let request_header = RequestHeader::new(VIRTIO_BLK_T_OUT, 114);
            m.write_obj::<RequestHeader>(request_header, GuestAddress(0x1000))
                .unwrap();
            assert!(matches!(
                Request::parse(&q.pop(m).unwrap(), m),
                Err(Error::UnexpectedWriteOnlyDescriptor)
            ));
        }

        {
            let mut q = vq.create_queue();
            // Chain too short: no data_descriptor.
            vq.dtable[request_type_descriptor].flags.set(0);
            assert!(matches!(
                Request::parse(&q.pop(m).unwrap(), m),
                Err(Error::DescriptorChainTooShort)
            ));
        }

        {
            let mut q = vq.create_queue();
            // Chain too short: no status descriptor.
            vq.dtable[request_type_descriptor]
                .flags
                .set(VIRTQ_DESC_F_NEXT);
            vq.dtable[data_descriptor].set(0x2000, 0x1000, 0, 2);
            assert!(matches!(
                Request::parse(&q.pop(m).unwrap(), m),
                Err(Error::DescriptorChainTooShort)
            ));
        }

        {
            let mut q = vq.create_queue();
            // Write only data for OUT.
            vq.dtable[data_descriptor]
                .flags
                .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
            vq.dtable[status_descriptor].set(0x3000, 0, 0, 0);
            assert!(matches!(
                Request::parse(&q.pop(m).unwrap(), m),
                Err(Error::UnexpectedWriteOnlyDescriptor)
            ));
        }

        {
            let mut q = vq.create_queue();
            // Read only data for GetDeviceID.
            m.write_obj::<u32>(VIRTIO_BLK_T_GET_ID, GuestAddress(0x1000))
                .unwrap();
            vq.dtable[data_descriptor].flags.set(VIRTQ_DESC_F_NEXT);
            assert!(matches!(
                Request::parse(&q.pop(m).unwrap(), m),
                Err(Error::UnexpectedReadOnlyDescriptor)
            ));
        }

        {
            let mut q = vq.create_queue();
            // Read only data for IN.
            m.write_obj::<u32>(VIRTIO_BLK_T_IN, GuestAddress(0x1000))
                .unwrap();
            vq.dtable[data_descriptor].flags.set(VIRTQ_DESC_F_NEXT);
            assert!(matches!(
                Request::parse(&q.pop(m).unwrap(), m),
                Err(Error::UnexpectedReadOnlyDescriptor)
            ));
        }

        {
            let mut q = vq.create_queue();
            // Status descriptor not writable.
            vq.dtable[data_descriptor]
                .flags
                .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
            assert!(matches!(
                Request::parse(&q.pop(m).unwrap(), m),
                Err(Error::UnexpectedReadOnlyDescriptor)
            ));
        }

        {
            let mut q = vq.create_queue();
            // Status descriptor too small.
            vq.dtable[status_descriptor].flags.set(VIRTQ_DESC_F_WRITE);
            assert!(matches!(
                Request::parse(&q.pop(m).unwrap(), m),
                Err(Error::DescriptorLengthTooSmall)
            ));
        }

        {
            let mut q = vq.create_queue();
            // Fix status descriptor length.
            vq.dtable[status_descriptor].len.set(0x1000);
            // Invalid guest address for the status descriptor.
            // Parsing will still succeed as the operation that
            // will fail happens when executing the request.
            vq.dtable[status_descriptor]
                .addr
                .set(m.last_addr().raw_value());
            assert!(Request::parse(&q.pop(m).unwrap(), m).is_ok());
        }

        {
            let mut q = vq.create_queue();
            // Restore status descriptor.
            vq.dtable[status_descriptor].set(0x3000, 0x1000, VIRTQ_DESC_F_WRITE, 0);
            // Invalid guest address for the data descriptor.
            // Parsing will still succeed as the operation that
            // will fail happens when executing the request.
            vq.dtable[data_descriptor]
                .addr
                .set(m.last_addr().raw_value());
            assert!(Request::parse(&q.pop(m).unwrap(), m).is_ok());
        }

        {
            let mut q = vq.create_queue();
            // Restore data descriptor.
            vq.dtable[data_descriptor].addr.set(0x2000);
            // Should be OK now.
            let r = Request::parse(&q.pop(m).unwrap(), m).unwrap();
            assert_eq!(r.request_type, RequestType::In);
            assert_eq!(r.sector, 114);
            assert_eq!(r.data_addr, GuestAddress(0x2000));
            assert_eq!(r.data_len, 0x1000);
            assert_eq!(r.status_addr, GuestAddress(0x3000));
        }
    }
}
