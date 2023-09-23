// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::convert::From;

use utils::vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemoryError, GuestMemoryMmap};
pub use virtio_gen::virtio_blk::{
    VIRTIO_BLK_ID_BYTES, VIRTIO_BLK_S_IOERR, VIRTIO_BLK_S_OK, VIRTIO_BLK_S_UNSUPP,
    VIRTIO_BLK_T_FLUSH, VIRTIO_BLK_T_GET_ID, VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT,
};

use super::super::DescriptorChain;
use super::{io as block_io, BlockError, SECTOR_SHIFT};
use crate::devices::virtio::block::device::DiskProperties;
use crate::devices::virtio::SECTOR_SIZE;
use crate::logger::{error, IncMetric, METRICS};
use crate::rate_limiter::{RateLimiter, TokenType};

#[derive(Debug, derive_more::From)]
pub enum IoErr {
    GetId(GuestMemoryError),
    PartialTransfer { completed: u32, expected: u32 },
    FileEngine(block_io::BlockIoError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

#[derive(Debug)]
pub enum ProcessingResult {
    Submitted,
    Throttled,
    Executed(FinishedRequest),
}

#[derive(Debug)]
pub struct FinishedRequest {
    pub num_bytes_to_mem: u32,
    pub desc_idx: u16,
}

#[derive(Debug)]
enum Status {
    Ok { num_bytes_to_mem: u32 },
    IoErr { num_bytes_to_mem: u32, err: IoErr },
    Unsupported { op: u32 },
}

impl Status {
    fn from_data(data_len: u32, transferred_data_len: u32, data_to_mem: bool) -> Status {
        let num_bytes_to_mem = match data_to_mem {
            true => transferred_data_len,
            false => 0,
        };

        match transferred_data_len == data_len {
            true => Status::Ok { num_bytes_to_mem },
            false => Status::IoErr {
                num_bytes_to_mem,
                err: IoErr::PartialTransfer {
                    completed: transferred_data_len,
                    expected: data_len,
                },
            },
        }
    }
}

#[derive(Debug)]
pub struct PendingRequest {
    r#type: RequestType,
    data_len: u32,
    status_addr: GuestAddress,
    desc_idx: u16,
}

impl PendingRequest {
    fn write_status_and_finish(self, status: &Status, mem: &GuestMemoryMmap) -> FinishedRequest {
        let (num_bytes_to_mem, status_code) = match status {
            Status::Ok { num_bytes_to_mem } => (*num_bytes_to_mem, VIRTIO_BLK_S_OK),
            Status::IoErr {
                num_bytes_to_mem,
                err,
            } => {
                METRICS.block.invalid_reqs_count.inc();
                error!(
                    "Failed to execute {:?} virtio block request: {:?}",
                    self.r#type, err
                );
                (*num_bytes_to_mem, VIRTIO_BLK_S_IOERR)
            }
            Status::Unsupported { op } => {
                METRICS.block.invalid_reqs_count.inc();
                error!("Received unsupported virtio block request: {}", op);
                (0, VIRTIO_BLK_S_UNSUPP)
            }
        };

        let num_bytes_to_mem = mem
            .write_obj(status_code as u8, self.status_addr)
            .map(|_| {
                // Account for the status byte
                num_bytes_to_mem + 1
            })
            .unwrap_or_else(|err| {
                error!("Failed to write virtio block status: {:?}", err);
                // If we can't write the status, discard the virtio descriptor
                0
            });

        FinishedRequest {
            num_bytes_to_mem,
            desc_idx: self.desc_idx,
        }
    }

    pub fn finish(self, mem: &GuestMemoryMmap, res: Result<u32, IoErr>) -> FinishedRequest {
        let status = match (res, self.r#type) {
            (Ok(transferred_data_len), RequestType::In) => {
                let status = Status::from_data(self.data_len, transferred_data_len, true);
                METRICS.block.read_bytes.add(transferred_data_len as usize);
                if let Status::Ok { .. } = status {
                    METRICS.block.read_count.inc();
                }
                status
            }
            (Ok(transferred_data_len), RequestType::Out) => {
                let status = Status::from_data(self.data_len, transferred_data_len, false);
                METRICS.block.write_bytes.add(transferred_data_len as usize);
                if let Status::Ok { .. } = status {
                    METRICS.block.write_count.inc();
                }
                status
            }
            (Ok(_), RequestType::Flush) => {
                METRICS.block.flush_count.inc();
                Status::Ok {
                    num_bytes_to_mem: 0,
                }
            }
            (Ok(transferred_data_len), RequestType::GetDeviceID) => {
                Status::from_data(self.data_len, transferred_data_len, true)
            }
            (_, RequestType::Unsupported(op)) => Status::Unsupported { op },
            (Err(err), _) => Status::IoErr {
                num_bytes_to_mem: 0,
                err,
            },
        };

        self.write_status_and_finish(&status, mem)
    }
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
#[derive(Debug, Copy, Clone, Default)]
#[repr(C)]
pub struct RequestHeader {
    request_type: u32,
    _reserved: u32,
    sector: u64,
}

// SAFETY: Safe because RequestHeader only contains plain data.
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
    fn read_from(memory: &GuestMemoryMmap, addr: GuestAddress) -> Result<Self, BlockError> {
        let request_header: RequestHeader =
            memory.read_obj(addr).map_err(BlockError::GuestMemory)?;
        Ok(request_header)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    pub r#type: RequestType,
    pub data_len: u32,
    pub status_addr: GuestAddress,
    sector: u64,
    data_addr: GuestAddress,
}

impl Request {
    pub fn parse(
        avail_desc: &DescriptorChain,
        mem: &GuestMemoryMmap,
        num_disk_sectors: u64,
    ) -> Result<Request, BlockError> {
        // The head contains the request type which MUST be readable.
        if avail_desc.is_write_only() {
            return Err(BlockError::UnexpectedWriteOnlyDescriptor);
        }

        let request_header = RequestHeader::read_from(mem, avail_desc.addr)?;
        let mut req = Request {
            r#type: RequestType::from(request_header.request_type),
            sector: request_header.sector,
            data_addr: GuestAddress(0),
            data_len: 0,
            status_addr: GuestAddress(0),
        };

        let data_desc;
        let status_desc;
        let desc = avail_desc
            .next_descriptor()
            .ok_or(BlockError::DescriptorChainTooShort)?;

        if !desc.has_next() {
            status_desc = desc;
            // Only flush requests are allowed to skip the data descriptor.
            if req.r#type != RequestType::Flush {
                return Err(BlockError::DescriptorChainTooShort);
            }
        } else {
            data_desc = desc;
            status_desc = data_desc
                .next_descriptor()
                .ok_or(BlockError::DescriptorChainTooShort)?;

            if data_desc.is_write_only() && req.r#type == RequestType::Out {
                return Err(BlockError::UnexpectedWriteOnlyDescriptor);
            }
            if !data_desc.is_write_only() && req.r#type == RequestType::In {
                return Err(BlockError::UnexpectedReadOnlyDescriptor);
            }
            if !data_desc.is_write_only() && req.r#type == RequestType::GetDeviceID {
                return Err(BlockError::UnexpectedReadOnlyDescriptor);
            }

            req.data_addr = data_desc.addr;
            req.data_len = data_desc.len;
        }

        // check request validity
        match req.r#type {
            RequestType::In | RequestType::Out => {
                // Check that the data length is a multiple of 512 as specified in the virtio
                // standard.
                if u64::from(req.data_len) % SECTOR_SIZE != 0 {
                    return Err(BlockError::InvalidDataLength);
                }
                let top_sector = req
                    .sector
                    .checked_add(u64::from(req.data_len) >> SECTOR_SHIFT)
                    .ok_or(BlockError::InvalidOffset)?;
                if top_sector > num_disk_sectors {
                    return Err(BlockError::InvalidOffset);
                }
            }
            RequestType::GetDeviceID => {
                if req.data_len < VIRTIO_BLK_ID_BYTES {
                    return Err(BlockError::InvalidDataLength);
                }
            }
            _ => {}
        }

        // The status MUST always be writable.
        if !status_desc.is_write_only() {
            return Err(BlockError::UnexpectedReadOnlyDescriptor);
        }

        if status_desc.len < 1 {
            return Err(BlockError::DescriptorLengthTooSmall);
        }

        req.status_addr = status_desc.addr;

        Ok(req)
    }

    pub(crate) fn rate_limit(&self, rate_limiter: &mut RateLimiter) -> bool {
        // If limiter.consume() fails it means there is no more TokenType::Ops
        // budget and rate limiting is in effect.
        if !rate_limiter.consume(1, TokenType::Ops) {
            return true;
        }
        // Exercise the rate limiter only if this request is of data transfer type.
        if self.r#type == RequestType::In || self.r#type == RequestType::Out {
            // If limiter.consume() fails it means there is no more TokenType::Bytes
            // budget and rate limiting is in effect.
            if !rate_limiter.consume(u64::from(self.data_len), TokenType::Bytes) {
                // Revert the OPS consume().
                rate_limiter.manual_replenish(1, TokenType::Ops);
                return true;
            }
        }

        false
    }

    fn offset(&self) -> u64 {
        self.sector << SECTOR_SHIFT
    }

    fn to_pending_request(&self, desc_idx: u16) -> PendingRequest {
        PendingRequest {
            r#type: self.r#type,
            data_len: self.data_len,
            status_addr: self.status_addr,
            desc_idx,
        }
    }

    pub(crate) fn process(
        self,
        disk: &mut DiskProperties,
        desc_idx: u16,
        mem: &GuestMemoryMmap,
    ) -> ProcessingResult {
        let pending = self.to_pending_request(desc_idx);
        let res = match self.r#type {
            RequestType::In => disk.file_engine_mut().read(
                self.offset(),
                mem,
                self.data_addr,
                self.data_len,
                pending,
            ),
            RequestType::Out => disk.file_engine_mut().write(
                self.offset(),
                mem,
                self.data_addr,
                self.data_len,
                pending,
            ),
            RequestType::Flush => disk.file_engine_mut().flush(pending),
            RequestType::GetDeviceID => {
                let res = mem
                    .write_slice(disk.image_id(), self.data_addr)
                    .map(|_| VIRTIO_BLK_ID_BYTES)
                    .map_err(IoErr::GetId);
                return ProcessingResult::Executed(pending.finish(mem, res));
            }
            RequestType::Unsupported(_) => {
                return ProcessingResult::Executed(pending.finish(mem, Ok(0)));
            }
        };

        match res {
            Ok(block_io::FileEngineOk::Submitted) => ProcessingResult::Submitted,
            Ok(block_io::FileEngineOk::Executed(res)) => {
                ProcessingResult::Executed(res.user_data.finish(mem, Ok(res.count)))
            }
            Err(err) => {
                if err.error.is_throttling_err() {
                    ProcessingResult::Throttled
                } else {
                    ProcessingResult::Executed(
                        err.user_data.finish(mem, Err(IoErr::FileEngine(err.error))),
                    )
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]

    use utils::vm_memory::test_utils::create_anon_guest_memory;
    use utils::vm_memory::{Address, GuestAddress, GuestMemory};

    use super::*;
    use crate::devices::virtio::test_utils::{default_mem, single_region_mem, VirtQueue};
    use crate::devices::virtio::{Queue, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};

    const NUM_DISK_SECTORS: u64 = 1024;

    #[test]
    fn test_read_request_header() {
        let mem = single_region_mem(0x1000);
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

    impl<'a, 'b> RequestDescriptorChain<'a, 'b> {
        fn check_parse_err(&self, _e: BlockError) {
            let mut q = self.driver_queue.create_queue();
            let memory = self.driver_queue.memory();

            assert!(matches!(
                Request::parse(&q.pop(memory).unwrap(), memory, NUM_DISK_SECTORS),
                Err(_e)
            ));
        }

        fn check_parse(&self, check_data: bool) {
            let mut q = self.driver_queue.create_queue();
            let memory = self.driver_queue.memory();
            let request =
                Request::parse(&q.pop(memory).unwrap(), memory, NUM_DISK_SECTORS).unwrap();
            let expected_header = self.header();

            assert_eq!(
                request.r#type,
                RequestType::from(expected_header.request_type)
            );
            assert_eq!(request.sector, expected_header.sector);

            if check_data {
                assert_eq!(request.data_addr.raw_value(), self.data_desc.addr.get());
                assert_eq!(request.data_len, self.data_desc.len.get());
            }

            assert_eq!(request.status_addr.raw_value(), self.status_desc.addr.get());
        }
    }

    #[test]
    fn test_parse_generic() {
        let mem = &default_mem();
        let queue = VirtQueue::new(GuestAddress(0), mem, 16);
        let chain = RequestDescriptorChain::new(&queue);
        let request_header = RequestHeader::new(100, 114);
        chain.set_header(request_header);

        // Write only request type descriptor.
        chain.header_desc.flags.set(VIRTQ_DESC_F_WRITE);
        chain.check_parse_err(BlockError::UnexpectedWriteOnlyDescriptor);

        // Chain too short: no DATA_DESCRIPTOR.
        chain.header_desc.flags.set(0);
        chain.check_parse_err(BlockError::DescriptorChainTooShort);

        // Chain too short: no status descriptor.
        chain.header_desc.flags.set(VIRTQ_DESC_F_NEXT);
        chain.data_desc.flags.set(0);
        chain.check_parse_err(BlockError::DescriptorChainTooShort);

        // Status descriptor not writable.
        chain.data_desc.flags.set(VIRTQ_DESC_F_NEXT);
        chain.status_desc.flags.set(0);
        chain.check_parse_err(BlockError::UnexpectedReadOnlyDescriptor);

        // Status descriptor too small.
        chain.status_desc.flags.set(VIRTQ_DESC_F_WRITE);
        chain.status_desc.len.set(0);
        chain.check_parse_err(BlockError::DescriptorLengthTooSmall);

        // Fix status descriptor length.
        chain.status_desc.len.set(0x1000);

        // Invalid guest address for the status descriptor. Parsing will still succeed
        // as the operation that will fail happens when executing the request.
        chain.status_desc.addr.set(mem.last_addr().raw_value());
        chain.check_parse(true);

        // Fix status descriptor addr.
        chain.status_desc.addr.set(0x3000);

        // Invalid guest address for the data descriptor. Parsing will still succeed
        // as the operation that will fail happens when executing the request.
        chain.data_desc.addr.set(mem.last_addr().raw_value());
        chain.check_parse(true);

        // Fix data descriptor addr.
        chain.data_desc.addr.set(0x2000);
        chain.check_parse(true);
    }

    #[test]
    fn test_parse_in() {
        let mem = &default_mem();
        let queue = VirtQueue::new(GuestAddress(0), mem, 16);
        let chain = RequestDescriptorChain::new(&queue);

        let mut request_header = RequestHeader::new(VIRTIO_BLK_T_IN, 99);
        chain.set_header(request_header);

        // Read only data descriptor for IN.
        chain.data_desc.flags.set(VIRTQ_DESC_F_NEXT);
        chain.check_parse_err(BlockError::UnexpectedReadOnlyDescriptor);

        // data_len is not multiple of 512 for IN.
        chain
            .data_desc
            .flags
            .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
        chain.data_desc.len.set(513);
        chain.check_parse_err(BlockError::InvalidDataLength);

        // sector is to big.
        request_header.sector = NUM_DISK_SECTORS;
        chain.data_desc.len.set(512);
        chain.set_header(request_header);
        chain.check_parse_err(BlockError::InvalidOffset);

        // Fix data descriptor.
        request_header.sector = NUM_DISK_SECTORS - 1;
        chain.set_header(request_header);
        chain.check_parse(true);
    }

    #[test]
    fn test_parse_out() {
        let mem = &default_mem();
        let queue = VirtQueue::new(GuestAddress(0), mem, 16);
        let chain = RequestDescriptorChain::new(&queue);

        let mut request_header = RequestHeader::new(VIRTIO_BLK_T_OUT, 100);
        chain.set_header(request_header);

        // Write only data descriptor for OUT.
        chain
            .data_desc
            .flags
            .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
        chain.check_parse_err(BlockError::UnexpectedWriteOnlyDescriptor);

        // data_len is not multiple of 512 for IN.
        chain.data_desc.flags.set(VIRTQ_DESC_F_NEXT);
        chain.data_desc.len.set(1000);
        chain.check_parse_err(BlockError::InvalidDataLength);

        // sector is to big.
        request_header.sector = NUM_DISK_SECTORS - 1;
        chain.data_desc.len.set(1024);
        chain.set_header(request_header);
        chain.check_parse_err(BlockError::InvalidOffset);

        // Fix header descriptor.
        request_header.sector = NUM_DISK_SECTORS - 2;
        chain.set_header(request_header);
        chain.check_parse(true);
    }

    #[test]
    fn test_parse_flush() {
        let mem = &default_mem();
        let queue = VirtQueue::new(GuestAddress(0), mem, 16);
        let chain = RequestDescriptorChain::new(&queue);

        // Flush request with a data descriptor.
        let request_header = RequestHeader::new(VIRTIO_BLK_T_FLUSH, 50);
        chain.set_header(request_header);
        chain.check_parse(true);

        // Flush request without a data descriptor.
        chain.header_desc.next.set(2);
        chain.check_parse(false);
    }

    #[test]
    fn test_parse_get_id() {
        let mem = &default_mem();
        let queue = VirtQueue::new(GuestAddress(0), mem, 16);
        let chain = RequestDescriptorChain::new(&queue);

        let request_header = RequestHeader::new(VIRTIO_BLK_T_GET_ID, 15);
        chain.set_header(request_header);

        // Read only data descriptor for GetDeviceId.
        chain.data_desc.flags.set(VIRTQ_DESC_F_NEXT);
        chain.check_parse_err(BlockError::UnexpectedReadOnlyDescriptor);

        // data_len is < VIRTIO_BLK_ID_BYTES for GetDeviceID.
        chain
            .data_desc
            .flags
            .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
        chain.data_desc.len.set(VIRTIO_BLK_ID_BYTES - 1);
        chain.check_parse_err(BlockError::InvalidDataLength);

        chain.data_desc.len.set(VIRTIO_BLK_ID_BYTES);
        chain.check_parse(true);
    }

    use std::convert::TryInto;

    /// -------------------------------------
    /// BEGIN PROPERTY BASED TESTING
    use proptest::arbitrary::Arbitrary;
    use proptest::prelude::*;
    use proptest::strategy::{Map, Strategy, TupleUnion};

    use crate::devices::virtio::block::test_utils::RequestDescriptorChain;

    // Implements a "strategy" for producing arbitrary values of RequestType.
    // This can also be generated by a derive macro from `proptest_derive`, but the crate
    // is currently experimental.
    // Since we are dealing with a very complex type we need to turn off the clippy
    // warning.
    #[allow(clippy::type_complexity)]
    impl Arbitrary for RequestType {
        type Parameters = <u32 as Arbitrary>::Parameters;
        // Tuple union will hold the strategies that we use to generate the request type.
        // The first element is the weight of the strategy, the second is a function that
        // returns the strategy value.
        type Strategy = TupleUnion<(
            (u32, std::sync::Arc<fn() -> Self>),
            (u32, std::sync::Arc<fn() -> Self>),
            (u32, std::sync::Arc<fn() -> Self>),
            (u32, std::sync::Arc<fn() -> Self>),
            (
                u32,
                std::sync::Arc<Map<<u32 as Arbitrary>::Strategy, fn(u32) -> Self>>,
            ),
        )>;

        fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
            // All strategies have the same weight, there is no reson currently to skew
            // the rations to increase the odds of a specific request type.
            TupleUnion::new((
                (1u32, std::sync::Arc::new(|| RequestType::In {})),
                (1u32, std::sync::Arc::new(|| RequestType::Out {})),
                (1u32, std::sync::Arc::new(|| RequestType::Flush {})),
                (1u32, std::sync::Arc::new(|| RequestType::GetDeviceID {})),
                (
                    1u32,
                    std::sync::Arc::new(Strategy::prop_map(any::<u32>(), |id| {
                        // Random unsupported requests for our implementation start at
                        // VIRTIO_BLK_T_GET_ID + 1 = 9.
                        // This can be further refined to include unsupported requests ids < 9.
                        RequestType::Unsupported(id.checked_add(9).unwrap_or(9))
                    })),
                ),
            ))
        }
    }

    impl From<RequestType> for u32 {
        fn from(request_type: RequestType) -> u32 {
            match request_type {
                RequestType::In => VIRTIO_BLK_T_IN,
                RequestType::Out => VIRTIO_BLK_T_OUT,
                RequestType::Flush => VIRTIO_BLK_T_FLUSH,
                RequestType::GetDeviceID => VIRTIO_BLK_T_GET_ID,
                RequestType::Unsupported(id) => id,
            }
        }
    }

    // Returns flags based on the request type.
    fn request_type_flags(request_type: RequestType) -> u16 {
        match request_type {
            RequestType::In => VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE,
            RequestType::Out => VIRTQ_DESC_F_NEXT,
            RequestType::Flush => VIRTQ_DESC_F_NEXT,
            RequestType::GetDeviceID => VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE,
            RequestType::Unsupported(_) => VIRTQ_DESC_F_NEXT,
        }
    }

    #[allow(clippy::let_with_type_underscore)]
    fn random_request_parse(
    ) -> impl Strategy<Value = (Result<Request, BlockError>, GuestMemoryMmap, Queue)> {
        // In this strategy we are going to generate random Requests/Errors and map them
        // to an input descriptor chain.
        //
        // We will check that Request::parse() arrives at the same result after
        // parsing the descriptor chain. Input properties are validated and commented below.
        (
            any::<u64>(),         // random data buffer sparsity factor
            any::<u32>(),         // data_len
            any::<u64>(),         // sector
            any::<RequestType>(), // request type
            any::<[bool; 10]>(),  // coin
        )
            .prop_map(|(sparsity, data_len, sector, request_type, coins)| {
                (
                    sparsity,
                    data_len,
                    sector,
                    request_type,
                    request_type.into(),
                    coins,
                )
            })
            .prop_map(
                |(sparsity, data_len, sector, request_type, virtio_request_id, coins)| {
                    do_random_request_parse(
                        sparsity,
                        data_len,
                        sector,
                        request_type,
                        virtio_request_id,
                        &coins,
                    )
                },
            )
    }

    fn do_random_request_parse(
        sparsity: u64,
        data_len: u32,
        sector: u64,
        request_type: RequestType,
        virtio_request_id: u32,
        coins_arr: &[bool],
    ) -> (Result<Request, BlockError>, GuestMemoryMmap, Queue) {
        let coins = &mut coins_arr.iter();

        // Randomize descriptor addresses. Assumed page size as max buffer len.
        let base_addr = sparsity & 0x0000_FFFF_FFFF_F000; // 48 bit base, page aligned.
        let max_desc_len = 0x1000;

        // First addr starts at page base + 1.
        let req_type_addr = GuestAddress(base_addr).checked_add(0x1000).unwrap();

        // Use first 4 bits of randomness to shift the gap size between this descriptor
        // and the next one.
        let mut next_desc_dist = max_desc_len + (0x1000 << (sparsity & 0xF));
        let data_addr = req_type_addr.checked_add(next_desc_dist).unwrap();

        // Use next 4 bits of randomness to shift gap size between this descriptor
        // and the next one.
        next_desc_dist = max_desc_len + (0x1000 << ((sparsity & 0xF0) >> 4));
        let status_addr = data_addr.checked_add(next_desc_dist).unwrap();

        let mem_end = status_addr.checked_add(max_desc_len).unwrap();
        let mem: GuestMemoryMmap = create_anon_guest_memory(
            &[(
                GuestAddress(base_addr),
                (mem_end.0 - base_addr).try_into().unwrap(),
            )],
            false,
        )
        .unwrap();

        let vq = VirtQueue::new(GuestAddress(base_addr), &mem, 16);
        let chain = RequestDescriptorChain::new(&vq);
        let q = vq.create_queue();

        // Make sure that data_len is a multiple of 512
        // and that 512 <= data_len <= (4096 + 512).
        let valid_data_len = ((data_len & 4096) | (SECTOR_SIZE as u32 - 1)) + 1;
        let sectors_len = u64::from(valid_data_len) / SECTOR_SIZE;
        // Craft a random request with the randomized parameters.
        let mut request = Request {
            r#type: request_type,
            data_len: valid_data_len,
            status_addr,
            sector: sector & (NUM_DISK_SECTORS - sectors_len),
            data_addr,
        };
        let mut request_header = RequestHeader::new(virtio_request_id, request.sector);

        chain.header_desc.addr.set(req_type_addr.0);
        chain.header_desc.len.set(max_desc_len as u32);
        chain.set_header(request_header);

        // Flush requests have no data desc.
        if request.r#type == RequestType::Flush {
            request.data_addr = GuestAddress(0);
            request.data_len = 0;
            chain.header_desc.next.set(2);
        } else {
            chain.data_desc.set(
                request.data_addr.0,
                request.data_len,
                request_type_flags(request.r#type),
                2,
            );
        }

        chain
            .status_desc
            .set(request.status_addr.0, 1, VIRTQ_DESC_F_WRITE, 0);

        // Flip a coin - should we generate a valid request or an error.
        if *coins.next().unwrap() {
            return (Ok(request), mem, q);
        }

        // This is the initial correct value.
        let data_desc_flags = &chain.data_desc.flags;

        // Flip coin - corrupt the status desc len.
        if *coins.next().unwrap() {
            chain.status_desc.len.set(0);
            return (Err(BlockError::DescriptorLengthTooSmall), mem, q);
        }

        // Flip coin - corrupt data desc next flag.
        // Exception: flush requests do not have data desc.
        if *coins.next().unwrap() && request.r#type != RequestType::Flush {
            data_desc_flags.set(data_desc_flags.get() & !VIRTQ_DESC_F_NEXT);
            return (Err(BlockError::DescriptorChainTooShort), mem, q);
        }

        // Flip coin - req type desc is write only.
        if *coins.next().unwrap() {
            let hdr_desc_flags = &chain.header_desc.flags;
            hdr_desc_flags.set(hdr_desc_flags.get() | VIRTQ_DESC_F_WRITE);
            return (Err(BlockError::UnexpectedWriteOnlyDescriptor), mem, q);
        }

        // Corrupt data desc accessibility
        if *coins.next().unwrap() {
            match request.r#type {
                // Readonly buffer is writable.
                RequestType::Out => {
                    data_desc_flags.set(data_desc_flags.get() | VIRTQ_DESC_F_WRITE);
                    return (Err(BlockError::UnexpectedWriteOnlyDescriptor), mem, q);
                }
                // Writeable buffer is readonly.
                RequestType::In | RequestType::GetDeviceID => {
                    data_desc_flags.set(data_desc_flags.get() & !VIRTQ_DESC_F_WRITE);
                    return (Err(BlockError::UnexpectedReadOnlyDescriptor), mem, q);
                }
                _ => {}
            };
        }

        // Flip coin - Corrupt data_len
        if *coins.next().unwrap() {
            match request.r#type {
                RequestType::In | RequestType::Out => {
                    // data_len is not a multiple of 512
                    chain
                        .data_desc
                        .len
                        .set(valid_data_len + (data_len % 511) + 1);
                    return (Err(BlockError::InvalidDataLength), mem, q);
                }
                RequestType::GetDeviceID => {
                    // data_len is < VIRTIO_BLK_ID_BYTES
                    chain
                        .data_desc
                        .len
                        .set(data_len & (VIRTIO_BLK_ID_BYTES - 1));
                    return (Err(BlockError::InvalidDataLength), mem, q);
                }
                _ => {}
            };
        }

        // Flip coin - Corrupt sector
        if *coins.next().unwrap() {
            match request.r#type {
                RequestType::In | RequestType::Out => {
                    request_header.sector = (sector | NUM_DISK_SECTORS) + 1;
                    chain.set_header(request_header);
                    return (Err(BlockError::InvalidOffset), mem, q);
                }
                _ => {}
            };
        }

        // Simulate no status descriptor.
        chain.header_desc.flags.set(0);
        (Err(BlockError::DescriptorChainTooShort), mem, q)
    }

    macro_rules! assert_err {
        ($expression:expr, $($pattern:tt)+) => {
            match $expression {
                $($pattern)+ => (),
                ref err =>  {
                    println!("expected `{}` but got `{:?}`", stringify!($($pattern)+), err);
                    prop_assert!(false)
                }
            }
        }
    }

    #[test]
    fn parse_random_requests() {
        let cfg = ProptestConfig::with_cases(1000);
        proptest!(cfg, |(mut request in random_request_parse())| {
            let result = Request::parse(&request.2.pop(&request.1).unwrap(), &request.1, NUM_DISK_SECTORS);
            match result {
                Ok(r) => prop_assert!(r == request.0.unwrap()),
                Err(err) => {
                    // Avoiding implementation of PartialEq which requires that even more types like
                    // GuestMemoryError implement it.
                    match request.0.unwrap_err() {
                        BlockError::DescriptorChainTooShort => assert_err!(err, BlockError::DescriptorChainTooShort),
                        BlockError::DescriptorLengthTooSmall => assert_err!(err, BlockError::DescriptorLengthTooSmall),
                        BlockError::InvalidDataLength => assert_err!(err, BlockError::InvalidDataLength),
                        BlockError::InvalidOffset => assert_err!(err, BlockError::InvalidOffset),
                        BlockError::UnexpectedWriteOnlyDescriptor => assert_err!(err, BlockError::UnexpectedWriteOnlyDescriptor),
                        BlockError::UnexpectedReadOnlyDescriptor => assert_err!(err, BlockError::UnexpectedReadOnlyDescriptor),
                        _ => unreachable!()
                    }
                }
            }
        });
    }
}
