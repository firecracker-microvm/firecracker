// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//

//! `VsockPacket` provides a thin wrapper over the buffers exchanged via virtio queues.
//! There are two components to a vsock packet, each using its own descriptor in a
//! virtio queue:
//! - the packet header; and
//! - the packet data/buffer.
//! There is a 1:1 relation between descriptor chains and packets: the first (chain head) holds
//! the header, and an optional second descriptor holds the data. The second descriptor is only
//! present for data packets (VSOCK_OP_RW).
//!
//! `VsockPacket` wraps these two buffers and provides direct access to the data stored
//! in guest memory. This is done to avoid unnecessarily copying data from guest memory
//! to temporary buffers, before passing it on to the vsock backend.

use std::fmt::Debug;

use vm_memory::volatile_memory::Error;
use vm_memory::{GuestMemoryError, ReadVolatile, WriteVolatile};

use super::{defs, VsockError};
use crate::devices::virtio::iovec::{IoVecBuffer, IoVecBufferMut};
use crate::devices::virtio::queue::DescriptorChain;
use crate::vstate::memory::ByteValued;

// The vsock packet header is defined by the C struct:
//
// ```C
//     le64 src_cid;
//     le64 dst_cid;
//     le32 src_port;
//     le32 dst_port;
//     le32 len;
//     le16 type;
//     le16 op;
//     le32 flags;
//     le32 buf_alloc;
//     le32 fwd_cnt;
// } __attribute__((packed));
// ```
// We create a rust structure that mirrors it.
// The mirroring struct is only used privately by `VsockPacket`, that offers getter and setter
// methods, for each struct field, that will also handle the correct endianess.

#[repr(packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct VsockPacketHeader {
    // Source CID.
    src_cid: u64,
    // Destination CID.
    dst_cid: u64,
    // Source port.
    src_port: u32,
    // Destination port.
    dst_port: u32,
    // Data length (in bytes) - may be 0, if there is no data buffer.
    len: u32,
    // Socket type. Currently, only connection-oriented streams are defined by the vsock protocol.
    type_: u16,
    // Operation ID - one of the VSOCK_OP_* values; e.g.
    // - VSOCK_OP_RW: a data packet;
    // - VSOCK_OP_REQUEST: connection request;
    // - VSOCK_OP_RST: forcefull connection termination;
    // etc (see `super::defs::uapi` for the full list).
    op: u16,
    // Additional options (flags) associated with the current operation (`op`).
    // Currently, only used with shutdown requests (VSOCK_OP_SHUTDOWN).
    flags: u32,
    // Size (in bytes) of the packet sender receive buffer (for the connection to which this packet
    // belongs).
    buf_alloc: u32,
    // Number of bytes the sender has received and consumed (for the connection to which this
    // packet belongs). For instance, for our Unix backend, this counter would be the total
    // number of bytes we have successfully written to a backing Unix socket.
    fwd_cnt: u32,
}

/// The vsock packet header struct size (the struct is packed).
pub const VSOCK_PKT_HDR_SIZE: u32 = 44;

// SAFETY: `VsockPacketHeader` is a POD and contains no padding.
unsafe impl ByteValued for VsockPacketHeader {}

/// Enum representing either a TX (e.g. read-only) or RX (e.g. write-only) buffer
///
/// Read and write permissions are statically enforced by using the correct `IoVecBuffer[Mut]`
/// abstraction
#[derive(Debug)]
pub enum VsockPacketBuffer {
    /// Buffer holds a read-only guest-to-host (TX) packet
    Tx(IoVecBuffer),
    /// Buffer holds a write-only host-to-guest (RX) packet
    Rx(IoVecBufferMut),
}

/// Struct describing a single vsock packet.
///
/// Encapsulates the virtio descriptor chain containing the packet through the `IoVecBuffer[Mut]`
/// abstractions.
#[derive(Debug)]
pub struct VsockPacket {
    /// A copy of the vsock packet's 44-byte header, held in hypervisor memory
    /// to minimize the number of accesses to guest memory. Can be written back
    /// to geust memory using [`VsockPacket::commit_hdr`] (only for RX buffers).
    hdr: VsockPacketHeader,
    /// The raw buffer, as it is contained in guest memory (containing both
    /// header and payload)
    buffer: VsockPacketBuffer,
}

impl VsockPacket {
    /// Create the packet wrapper from a TX virtq chain head.
    ///
    /// ## Errors
    /// Returns
    /// - [`VsockError::UnreadableDescriptor`] if the provided descriptor chain contains any
    ///   descriptor not marked as writable.
    /// - [`VsockError::DescChainTooShortForHeader`] if the descriptor chain's total buffer length
    ///   is insufficient to hold the 44 byte vsock header
    /// - [`VsockError::InvalidPktLen`] if the contained vsock header describes a vsock packet whose
    ///   length would exceed [`defs::MAX_PKT_BUR_SIZE`].
    /// - [`VsockError::DescChainTooShortForPacket`] if the contained vsock header describes a vsock
    ///   packet whose length exceeds the descriptor chain's actual total buffer length.
    pub fn from_tx_virtq_head(chain: DescriptorChain) -> Result<Self, VsockError> {
        // SAFETY: This descriptor chain is only loaded once
        // virtio requests are handled sequentially so no two IoVecBuffers
        // are live at the same time, meaning this has exclusive ownership over the memory
        let buffer = unsafe { IoVecBuffer::from_descriptor_chain(chain)? };

        let mut hdr = VsockPacketHeader::default();
        match buffer.read_exact_volatile_at(hdr.as_mut_slice(), 0) {
            Ok(()) => (),
            Err(Error::PartialBuffer { completed, .. }) => {
                return Err(VsockError::DescChainTooShortForHeader(completed))
            }
            Err(err) => return Err(VsockError::GuestMemoryMmap(err.into())),
        }

        if hdr.len > defs::MAX_PKT_BUF_SIZE {
            return Err(VsockError::InvalidPktLen(hdr.len));
        }

        if hdr.len > buffer.len() - VSOCK_PKT_HDR_SIZE {
            return Err(VsockError::DescChainTooShortForPacket(
                buffer.len(),
                hdr.len,
            ));
        }

        Ok(VsockPacket {
            hdr,
            buffer: VsockPacketBuffer::Tx(buffer),
        })
    }

    /// Create the packet wrapper from an RX virtq chain head.
    ///
    /// ## Errors
    /// Returns [`VsockError::DescChainTooShortForHeader`] if the descriptor chain's total buffer
    /// length is insufficient to hold the 44 byte vsock header
    pub fn from_rx_virtq_head(chain: DescriptorChain) -> Result<Self, VsockError> {
        // SAFETY: This descriptor chain is only loaded into one buffer.
        let buffer = unsafe { IoVecBufferMut::from_descriptor_chain(chain)? };

        if buffer.len() < VSOCK_PKT_HDR_SIZE {
            return Err(VsockError::DescChainTooShortForHeader(buffer.len() as usize));
        }

        Ok(Self {
            // On the Rx path the header has to be filled by Firecracker. The guest only provides
            // a write-only memory area that Firecracker can write the header into. So we initialize
            // the local copy with zeros, we write to it whenever we need to, and we only commit it
            // to the guest memory once, before marking the RX descriptor chain as used.
            hdr: VsockPacketHeader::default(),
            buffer: VsockPacketBuffer::Rx(buffer),
        })
    }

    /// Provides in-place access to the local copy of the vsock packet header.
    pub fn hdr(&self) -> &VsockPacketHeader {
        &self.hdr
    }

    /// Writes the local copy of the packet header to the guest memory.
    ///
    /// ## Errors
    /// The function returns [`VsockError::UnwritableDescriptor`] if this [`VsockPacket`]
    /// contains a guest-to-host (TX) packet. It returned [`VsockError::InvalidPktLen`] if the
    /// packet's payload as described by this [`VsockPacket`] would exceed
    /// [`defs::MAX_PKT_BUF_SIZE`].
    pub fn commit_hdr(&mut self) -> Result<(), VsockError> {
        match self.buffer {
            VsockPacketBuffer::Tx(_) => Err(VsockError::UnwritableDescriptor),
            VsockPacketBuffer::Rx(ref mut buffer) => {
                if self.hdr.len > defs::MAX_PKT_BUF_SIZE {
                    return Err(VsockError::InvalidPktLen(self.hdr.len));
                }

                buffer
                    .write_all_volatile_at(self.hdr.as_slice(), 0)
                    .map_err(GuestMemoryError::from)
                    .map_err(VsockError::GuestMemoryMmap)
            }
        }
    }

    /// Returns the total length of this [`VsockPacket`]'s buffer (e.g. the amount of data bytes
    /// contained in this packet).
    ///
    /// Return value will equal the total length of the underlying descriptor chain's buffers,
    /// minus the length of the vsock header.
    pub fn buf_size(&self) -> usize {
        let chain_length = match self.buffer {
            VsockPacketBuffer::Tx(ref iovec_buf) => iovec_buf.len(),
            VsockPacketBuffer::Rx(ref iovec_buf) => iovec_buf.len(),
        };
        (chain_length - VSOCK_PKT_HDR_SIZE) as usize
    }

    pub fn read_at_offset_from<T: ReadVolatile + Debug>(
        &mut self,
        src: &mut T,
        offset: usize,
        count: usize,
    ) -> Result<usize, VsockError> {
        match self.buffer {
            VsockPacketBuffer::Tx(_) => Err(VsockError::UnwritableDescriptor),
            VsockPacketBuffer::Rx(ref mut buffer) => {
                if count
                    > (buffer.len() as usize)
                        .saturating_sub(VSOCK_PKT_HDR_SIZE as usize)
                        .saturating_sub(offset)
                {
                    return Err(VsockError::GuestMemoryBounds);
                }

                buffer
                    .write_volatile_at(src, offset + VSOCK_PKT_HDR_SIZE as usize, count)
                    .map_err(|err| VsockError::GuestMemoryMmap(GuestMemoryError::from(err)))
            }
        }
    }

    pub fn write_from_offset_to<T: WriteVolatile + Debug>(
        &self,
        dst: &mut T,
        offset: usize,
        count: usize,
    ) -> Result<usize, VsockError> {
        match self.buffer {
            VsockPacketBuffer::Tx(ref buffer) => {
                if count
                    > (buffer.len() as usize)
                        .saturating_sub(VSOCK_PKT_HDR_SIZE as usize)
                        .saturating_sub(offset)
                {
                    return Err(VsockError::GuestMemoryBounds);
                }

                buffer
                    .read_volatile_at(dst, offset + VSOCK_PKT_HDR_SIZE as usize, count)
                    .map_err(|err| VsockError::GuestMemoryMmap(GuestMemoryError::from(err)))
            }
            VsockPacketBuffer::Rx(_) => Err(VsockError::UnreadableDescriptor),
        }
    }

    pub fn src_cid(&self) -> u64 {
        u64::from_le(self.hdr.src_cid)
    }

    pub fn set_src_cid(&mut self, cid: u64) -> &mut Self {
        self.hdr.src_cid = cid.to_le();
        self
    }

    pub fn dst_cid(&self) -> u64 {
        u64::from_le(self.hdr.dst_cid)
    }

    pub fn set_dst_cid(&mut self, cid: u64) -> &mut Self {
        self.hdr.dst_cid = cid.to_le();
        self
    }

    pub fn src_port(&self) -> u32 {
        u32::from_le(self.hdr.src_port)
    }

    pub fn set_src_port(&mut self, port: u32) -> &mut Self {
        self.hdr.src_port = port.to_le();
        self
    }

    pub fn dst_port(&self) -> u32 {
        u32::from_le(self.hdr.dst_port)
    }

    pub fn set_dst_port(&mut self, port: u32) -> &mut Self {
        self.hdr.dst_port = port.to_le();
        self
    }

    pub fn len(&self) -> u32 {
        u32::from_le(self.hdr.len)
    }

    pub fn set_len(&mut self, len: u32) -> &mut Self {
        self.hdr.len = len.to_le();
        self
    }

    pub fn type_(&self) -> u16 {
        u16::from_le(self.hdr.type_)
    }

    pub fn set_type(&mut self, type_: u16) -> &mut Self {
        self.hdr.type_ = type_.to_le();
        self
    }

    pub fn op(&self) -> u16 {
        u16::from_le(self.hdr.op)
    }

    pub fn set_op(&mut self, op: u16) -> &mut Self {
        self.hdr.op = op.to_le();
        self
    }

    pub fn flags(&self) -> u32 {
        u32::from_le(self.hdr.flags)
    }

    pub fn set_flags(&mut self, flags: u32) -> &mut Self {
        self.hdr.flags = flags.to_le();
        self
    }

    pub fn set_flag(&mut self, flag: u32) -> &mut Self {
        self.set_flags(self.flags() | flag);
        self
    }

    pub fn buf_alloc(&self) -> u32 {
        u32::from_le(self.hdr.buf_alloc)
    }

    pub fn set_buf_alloc(&mut self, buf_alloc: u32) -> &mut Self {
        self.hdr.buf_alloc = buf_alloc.to_le();
        self
    }

    pub fn fwd_cnt(&self) -> u32 {
        u32::from_le(self.hdr.fwd_cnt)
    }

    pub fn set_fwd_cnt(&mut self, fwd_cnt: u32) -> &mut Self {
        self.hdr.fwd_cnt = fwd_cnt.to_le();
        self
    }
}

#[cfg(test)]
mod tests {
    use vm_memory::Bytes;

    use super::*;
    use crate::devices::virtio::queue::VIRTQ_DESC_F_WRITE;
    use crate::devices::virtio::test_utils::VirtqDesc as GuestQDesc;
    use crate::devices::virtio::vsock::defs::MAX_PKT_BUF_SIZE;
    use crate::devices::virtio::vsock::device::{RXQ_INDEX, TXQ_INDEX};
    use crate::devices::virtio::vsock::test_utils::TestContext;
    use crate::vstate::memory::{GuestAddress, GuestMemoryMmap};

    macro_rules! create_context {
        ($test_ctx:ident, $handler_ctx:ident) => {
            let $test_ctx = TestContext::new();
            let mut $handler_ctx = $test_ctx.create_event_handler_context();
            // For TX packets, hdr.len should be set to a valid value.
            set_pkt_len(4096, &$handler_ctx.guest_txvq.dtable[0], &$test_ctx.mem);
        };
    }

    macro_rules! expect_asm_error {
        (tx, $test_ctx:expr, $handler_ctx:expr, $err:pat) => {
            expect_asm_error!($test_ctx, $handler_ctx, $err, from_tx_virtq_head, TXQ_INDEX);
        };
        (rx, $test_ctx:expr, $handler_ctx:expr, $err:pat) => {
            expect_asm_error!($test_ctx, $handler_ctx, $err, from_rx_virtq_head, RXQ_INDEX);
        };
        ($test_ctx:expr, $handler_ctx:expr, $err:pat, $ctor:ident, $vq_index:ident) => {
            let result = VsockPacket::$ctor(
                $handler_ctx.device.queues[$vq_index]
                    .pop(&$test_ctx.mem)
                    .unwrap(),
            );
            assert!(matches!(result, Err($err)), "{:?}", result)
        };
    }

    fn set_pkt_len(len: u32, guest_desc: &GuestQDesc, mem: &GuestMemoryMmap) {
        let hdr_addr = GuestAddress(guest_desc.addr.get());
        let mut hdr: VsockPacketHeader = mem.read_obj(hdr_addr).unwrap();
        hdr.len = len.to_le();
        mem.write_obj(hdr, hdr_addr).unwrap();
    }

    #[test]
    fn test_packet_hdr_size() {
        assert_eq!(
            VSOCK_PKT_HDR_SIZE as usize,
            std::mem::size_of::<VsockPacketHeader>(),
        );
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_tx_packet_assembly() {
        // Test case: successful TX packet assembly as linux < 6.1 would build them.
        {
            create_context!(test_ctx, handler_ctx);

            let pkt = VsockPacket::from_tx_virtq_head(
                handler_ctx.device.queues[TXQ_INDEX]
                    .pop(&test_ctx.mem)
                    .unwrap(),
            )
            .unwrap();

            assert_eq!(
                TryInto::<u32>::try_into(pkt.buf_size()).unwrap(),
                handler_ctx.guest_txvq.dtable[1].len.get()
            );
        }

        // Test case: error on write-only hdr descriptor.
        {
            create_context!(test_ctx, handler_ctx);
            handler_ctx.guest_txvq.dtable[0]
                .flags
                .set(VIRTQ_DESC_F_WRITE);
            expect_asm_error!(tx, test_ctx, handler_ctx, VsockError::UnreadableDescriptor);
        }

        // Test case: header descriptor has insufficient space to hold the packet header.
        {
            create_context!(test_ctx, handler_ctx);
            handler_ctx.guest_txvq.dtable[0]
                .len
                .set(VSOCK_PKT_HDR_SIZE - 1);
            handler_ctx.guest_txvq.dtable[1].len.set(0);
            expect_asm_error!(
                tx,
                test_ctx,
                handler_ctx,
                VsockError::DescChainTooShortForHeader(_)
            );
        }

        // Test case: zero-length TX packet.
        {
            create_context!(test_ctx, handler_ctx);
            set_pkt_len(0, &handler_ctx.guest_txvq.dtable[0], &test_ctx.mem);
            VsockPacket::from_tx_virtq_head(
                handler_ctx.device.queues[TXQ_INDEX]
                    .pop(&test_ctx.mem)
                    .unwrap(),
            )
            .unwrap();
        }

        // Test case: TX packet has more data than we can handle.
        {
            create_context!(test_ctx, handler_ctx);
            set_pkt_len(
                MAX_PKT_BUF_SIZE + 1,
                &handler_ctx.guest_txvq.dtable[0],
                &test_ctx.mem,
            );
            expect_asm_error!(tx, test_ctx, handler_ctx, VsockError::InvalidPktLen(_));
        }

        // Test case:
        // - packet header advertises some data length; and
        // - the data descriptor is missing.
        {
            create_context!(test_ctx, handler_ctx);
            set_pkt_len(1024, &handler_ctx.guest_txvq.dtable[0], &test_ctx.mem);
            handler_ctx.guest_txvq.dtable[0].flags.set(0);
            expect_asm_error!(
                tx,
                test_ctx,
                handler_ctx,
                VsockError::DescChainTooShortForPacket(44, 1024)
            );
        }

        // Test case: error on write-only buf descriptor.
        {
            create_context!(test_ctx, handler_ctx);
            handler_ctx.guest_txvq.dtable[1]
                .flags
                .set(VIRTQ_DESC_F_WRITE);
            expect_asm_error!(tx, test_ctx, handler_ctx, VsockError::UnreadableDescriptor);
        }

        // Test case: the buffer descriptor cannot fit all the data advertised by the the
        // packet header `len` field.
        {
            create_context!(test_ctx, handler_ctx);
            set_pkt_len(8 * 1024, &handler_ctx.guest_txvq.dtable[0], &test_ctx.mem);
            handler_ctx.guest_txvq.dtable[1].len.set(4 * 1024);
            expect_asm_error!(
                tx,
                test_ctx,
                handler_ctx,
                VsockError::DescChainTooShortForPacket(4140, 8192)
            );
        }
    }

    #[test]
    fn test_rx_packet_assembly() {
        // Test case: successful RX packet assembly.
        {
            create_context!(test_ctx, handler_ctx);
            let pkt = VsockPacket::from_rx_virtq_head(
                handler_ctx.device.queues[RXQ_INDEX]
                    .pop(&test_ctx.mem)
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                pkt.buf_size(),
                handler_ctx.guest_rxvq.dtable[1].len.get() as usize
            );
        }

        // Test case: read-only RX packet header.
        {
            create_context!(test_ctx, handler_ctx);
            handler_ctx.guest_rxvq.dtable[0].flags.set(0);
            expect_asm_error!(rx, test_ctx, handler_ctx, VsockError::UnwritableDescriptor);
        }

        // Test case: RX descriptor chain cannot fit packet header
        {
            create_context!(test_ctx, handler_ctx);
            handler_ctx.guest_rxvq.dtable[0]
                .len
                .set(VSOCK_PKT_HDR_SIZE - 1);
            handler_ctx.guest_rxvq.dtable[1].len.set(0);
            expect_asm_error!(
                rx,
                test_ctx,
                handler_ctx,
                VsockError::DescChainTooShortForHeader(_)
            );
        }
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_packet_hdr_accessors() {
        const SRC_CID: u64 = 1;
        const DST_CID: u64 = 2;
        const SRC_PORT: u32 = 3;
        const DST_PORT: u32 = 4;
        const LEN: u32 = 5;
        const TYPE: u16 = 6;
        const OP: u16 = 7;
        const FLAGS: u32 = 8;
        const BUF_ALLOC: u32 = 9;
        const FWD_CNT: u32 = 10;

        create_context!(test_ctx, handler_ctx);
        let mut pkt = VsockPacket::from_rx_virtq_head(
            handler_ctx.device.queues[RXQ_INDEX]
                .pop(&test_ctx.mem)
                .unwrap(),
        )
        .unwrap();

        // Test field accessors.
        pkt.set_src_cid(SRC_CID)
            .set_dst_cid(DST_CID)
            .set_src_port(SRC_PORT)
            .set_dst_port(DST_PORT)
            .set_len(LEN)
            .set_type(TYPE)
            .set_op(OP)
            .set_flags(FLAGS)
            .set_buf_alloc(BUF_ALLOC)
            .set_fwd_cnt(FWD_CNT);

        assert_eq!(pkt.src_cid(), SRC_CID);
        assert_eq!(pkt.dst_cid(), DST_CID);
        assert_eq!(pkt.src_port(), SRC_PORT);
        assert_eq!(pkt.dst_port(), DST_PORT);
        assert_eq!(pkt.len(), LEN);
        assert_eq!(pkt.type_(), TYPE);
        assert_eq!(pkt.op(), OP);
        assert_eq!(pkt.flags(), FLAGS);
        assert_eq!(pkt.buf_alloc(), BUF_ALLOC);
        assert_eq!(pkt.fwd_cnt(), FWD_CNT);

        // Test individual flag setting.
        let flags = pkt.flags() | 0b1000;
        pkt.set_flag(0b1000);
        assert_eq!(pkt.flags(), flags);

        pkt.hdr = VsockPacketHeader::default();
        assert_eq!(pkt.src_cid(), 0);
        assert_eq!(pkt.dst_cid(), 0);
        assert_eq!(pkt.src_port(), 0);
        assert_eq!(pkt.dst_port(), 0);
        assert_eq!(pkt.len(), 0);
        assert_eq!(pkt.type_(), 0);
        assert_eq!(pkt.op(), 0);
        assert_eq!(pkt.flags(), 0);
        assert_eq!(pkt.buf_alloc(), 0);
        assert_eq!(pkt.fwd_cnt(), 0);
    }

    #[test]
    fn test_packet_buf() {
        create_context!(test_ctx, handler_ctx);
        // create_context gives us an rx descriptor chain and a tx descriptor chain pointing to the
        // same area of memory. We need both a rx-view and a tx-view into the packet, as tx-queue
        // buffers are read only, while rx queue buffers are write-only
        let mut pkt = VsockPacket::from_rx_virtq_head(
            handler_ctx.device.queues[RXQ_INDEX]
                .pop(&test_ctx.mem)
                .unwrap(),
        )
        .unwrap();
        let pkt2 = VsockPacket::from_tx_virtq_head(
            handler_ctx.device.queues[TXQ_INDEX]
                .pop(&test_ctx.mem)
                .unwrap(),
        )
        .unwrap();

        let buf_desc = &mut handler_ctx.guest_rxvq.dtable[1];
        assert_eq!(pkt.buf_size(), buf_desc.len.get() as usize);
        let zeros = vec![0_u8; pkt.buf_size()];
        let data: Vec<u8> = (0..pkt.buf_size())
            .map(|i| ((i as u64) & 0xff) as u8)
            .collect();
        for offset in 0..pkt.buf_size() {
            buf_desc.set_data(&zeros);

            let mut expected_data = zeros[..offset].to_vec();
            expected_data.extend_from_slice(&data[..pkt.buf_size() - offset]);

            pkt.read_at_offset_from(&mut data.as_slice(), offset, pkt.buf_size() - offset)
                .unwrap();

            buf_desc.check_data(&expected_data);

            let mut buf = vec![0; pkt.buf_size()];
            pkt2.write_from_offset_to(&mut buf.as_mut_slice(), offset, pkt.buf_size() - offset)
                .unwrap();
            assert_eq!(&buf[..pkt.buf_size() - offset], &expected_data[offset..]);
        }

        let oob_cases = vec![
            (1, pkt.buf_size()),
            (pkt.buf_size(), 1),
            (usize::MAX, 1),
            (1, usize::MAX),
        ];
        let mut buf = vec![0; pkt.buf_size()];
        for (offset, count) in oob_cases {
            let res = pkt.read_at_offset_from(&mut data.as_slice(), offset, count);
            assert!(matches!(res, Err(VsockError::GuestMemoryBounds)));
            let res = pkt2.write_from_offset_to(&mut buf.as_mut_slice(), offset, count);
            assert!(matches!(res, Err(VsockError::GuestMemoryBounds)));
        }
    }
}
