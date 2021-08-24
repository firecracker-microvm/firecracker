// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//

/// `VsockPacket` provides a thin wrapper over the buffers exchanged via virtio queues.
/// There are two components to a vsock packet, each using its own descriptor in a
/// virtio queue:
/// - the packet header; and
/// - the packet data/buffer.
/// There is a 1:1 relation between descriptor chains and packets: the first (chain head) holds
/// the header, and an optional second descriptor holds the data. The second descriptor is only
/// present for data packets (VSOCK_OP_RW).
///
/// `VsockPacket` wraps these two buffers and provides direct access to the data stored
/// in guest memory. This is done to avoid unnecessarily copying data from guest memory
/// to temporary buffers, before passing it on to the vsock backend.
use std::io::{Read, Write};

use vm_memory::{
    self, Address, ByteValued, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap,
    GuestMemoryRegion, GuestRegionMmap, MemoryRegionAddress,
};

use super::super::DescriptorChain;
use super::defs;
use super::{Result, VsockError};

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
    // Number of bytes the sender has received and consumed (for the connection to which this packet
    // belongs). For instance, for our Unix backend, this counter would be the total number of bytes
    // we have successfully written to a backing Unix socket.
    fwd_cnt: u32,
}

/// The vsock packet header struct size (the struct is packed).
pub const VSOCK_PKT_HDR_SIZE: usize = 44;

unsafe impl ByteValued for VsockPacketHeader {}

/// The vsock packet, implemented as a wrapper over a virtq descriptor chain:
/// - the chain head, holding the packet header; and
/// - (an optional) data/buffer descriptor, only present for data packets (VSOCK_OP_RW).
pub struct VsockPacket {
    hdr_addr: GuestAddress,
    // For performance purposes we hold a local copy of the Packet header.
    // This reduces the number of calls to `vm-memory` to a minimum:
    // 1 write for Rx and 1 read for Tx, plus 1 `check_range` call for each.
    hdr: VsockPacketHeader,
    buf_addr: Option<GuestAddress>,
    buf_size: usize,
}

impl VsockPacket {
    fn check_desc_write_only(desc: &DescriptorChain, expected_write_only: bool) -> Result<()> {
        if desc.is_write_only() != expected_write_only {
            return match desc.is_write_only() {
                true => Err(VsockError::UnreadableDescriptor),
                false => Err(VsockError::UnwritableDescriptor),
            };
        }

        Ok(())
    }

    fn check_hdr_desc(hdr_desc: &DescriptorChain, expected_write_only: bool) -> Result<()> {
        Self::check_desc_write_only(hdr_desc, expected_write_only)?;

        // Validate the packet header address
        if !hdr_desc.mem.check_range(hdr_desc.addr, VSOCK_PKT_HDR_SIZE) {
            return Err(VsockError::GuestMemoryBounds);
        }

        // The packet header should fit inside the head descriptor.
        if hdr_desc.len < VSOCK_PKT_HDR_SIZE as u32 {
            return Err(VsockError::HdrDescTooSmall(hdr_desc.len));
        }

        Ok(())
    }

    fn init_buf(&mut self, hdr_desc: &DescriptorChain, expected_write_only: bool) -> Result<()> {
        let buf_desc = hdr_desc
            .next_descriptor()
            .ok_or(VsockError::BufDescMissing)?;
        let buf_size = buf_desc.len as usize;

        Self::check_desc_write_only(&buf_desc, expected_write_only)?;

        // Validate the packet buf address
        if !buf_desc
            .mem
            .check_range(buf_desc.addr, buf_desc.len as usize)
        {
            return Err(VsockError::GuestMemoryBounds);
        }

        self.buf_addr = Some(buf_desc.addr);
        self.buf_size = buf_size;

        Ok(())
    }

    /// Create the packet wrapper from a TX virtq chain head.
    ///
    /// The chain head is expected to hold valid packet header data. A following packet buffer
    /// descriptor can optionally end the chain. Bounds and pointer checks are performed when
    /// creating the wrapper.
    pub fn from_tx_virtq_head(hdr_desc: &DescriptorChain) -> Result<Self> {
        Self::check_hdr_desc(hdr_desc, false)?;

        // Validate the packet header address
        if !hdr_desc.mem.check_range(hdr_desc.addr, VSOCK_PKT_HDR_SIZE) {
            return Err(VsockError::GuestMemoryBounds);
        }

        let mut pkt = Self {
            hdr_addr: hdr_desc.addr,
            // On the Tx path the header is provided by the guest and is read only for Firecracker.
            // So we read it here once and we work with the local copy from now on.
            hdr: hdr_desc
                .mem
                .read_obj(hdr_desc.addr)
                .map_err(VsockError::GuestMemoryMmap)?,
            buf_addr: None,
            buf_size: 0,
        };

        // No point looking for a data/buffer descriptor, if the packet is zero-lengthed.
        if pkt.len() == 0 {
            return Ok(pkt);
        }

        // Reject weirdly-sized packets.
        pkt.check_len()?;

        pkt.init_buf(hdr_desc, false)?;

        // The data buffer should be large enough to fit the size of the data, as described by
        // the header descriptor.
        if pkt.buf_size < pkt.len() as usize {
            return Err(VsockError::BufDescTooSmall);
        }

        Ok(pkt)
    }

    /// Create the packet wrapper from an RX virtq chain head.
    ///
    /// There must be two descriptors in the chain, both writable: a header descriptor and a data
    /// descriptor. Bounds and pointer checks are performed when creating the wrapper.
    pub fn from_rx_virtq_head(hdr_desc: &DescriptorChain) -> Result<Self> {
        Self::check_hdr_desc(hdr_desc, true)?;

        let mut pkt = Self {
            hdr_addr: hdr_desc.addr,
            // On the Rx path the header has to be filled by Firecracker. The guest only provides
            // a write-only memory area that Firecracker can write the header into. So we initialize
            // the local copy with zeros, we write to it whenever we need to, and we only commit it
            // to the guest memory once, before marking the RX descriptor chain as used.
            hdr: VsockPacketHeader::default(),
            buf_addr: None,
            buf_size: 0,
        };

        pkt.init_buf(hdr_desc, true)?;

        Ok(pkt)
    }

    /// Provides in-place access to the local copy of the vsock packet header.
    pub fn hdr(&self) -> &VsockPacketHeader {
        &self.hdr
    }

    /// Writes the local copy of the packet header to the guest memory.
    pub fn commit_hdr(&self, mem: &GuestMemoryMmap) -> Result<()> {
        // Reject weirdly-sized packets.
        self.check_len()?;

        mem.write_obj(self.hdr, self.hdr_addr)
            .map_err(VsockError::GuestMemoryMmap)
    }

    /// Verifies packet length against `MAX_PKT_BUF_SIZE` limit.
    pub fn check_len(&self) -> Result<()> {
        if self.len() > defs::MAX_PKT_BUF_SIZE as u32 {
            return Err(VsockError::InvalidPktLen(self.len()));
        }

        Ok(())
    }

    pub fn buf_size(&self) -> usize {
        self.buf_size
    }

    /// Gets the GuestRegion and the MemoryRegionAddress where the buf starts.
    ///
    /// As they are currently implemented, `GuestMemory::write_to()` and `GuestMemory::read_from()`
    /// have 2 significant disadvantages:
    /// 1. Performance: They process chunks of length 4K and they copy data to an auxiliary buffer.
    /// 2. Error handling: They don't handle `EWOULDBLOCK` correctly. So for example if it manages to
    ///    write 1K bytes out of 10K and then receives `EWOULDBLOCK`, it returns a
    ///    `GuestMemory::IoError`. On the Rx path we read from a stream, but we don't know its
    ///    length. We just try to write as much as possible. This is guaranteed to lead to an
    ///    `EWOULDBLOCK` error eventually.
    /// This makes them unusable. But the entire buffer should be placed inside a single
    /// `GuestRegion`. Also `GuestRegion::write_to()` and `GuestRegion::read_from()` don't have
    /// the problems mentioned above. So we will read/write directly to/from the `GuestRegion`.
    ///
    /// TODO: use `GuestMemory::write_to()` and `GuestMemory::read_from()` when they are stable
    /// enough:
    /// 1. https://github.com/rust-vmm/vm-memory/pull/125 should be merged.
    /// 2. The `EWOULDBLOCK` scenario should be fixed.
    fn buf_region_addr<'a>(
        &self,
        mem: &'a GuestMemoryMmap,
        offset: usize,
        count: usize,
    ) -> Result<(&'a GuestRegionMmap, MemoryRegionAddress)> {
        // Check that the desired slice is inside the buf.
        self.buf_size
            .checked_sub(offset)
            .and_then(|remaining_size| remaining_size.checked_sub(count))
            .ok_or(VsockError::GuestMemoryBounds)?;

        let buf_addr = self.buf_addr.ok_or(VsockError::PktBufMissing)?;
        buf_addr
            .checked_add(offset as u64)
            .and_then(|offset_addr| mem.to_region_addr(offset_addr))
            .and_then(|(region, region_addr)| {
                region.checked_offset(region_addr, count.checked_sub(1)?)?;
                Some((region, region_addr))
            })
            .ok_or(VsockError::GuestMemoryBounds)
    }

    pub fn read_at_offset_from<F: Read>(
        &mut self,
        mem: &GuestMemoryMmap,
        offset: usize,
        src: &mut F,
        count: usize,
    ) -> Result<usize> {
        let (region, region_addr) = self.buf_region_addr(mem, offset, count)?;
        region
            .read_from(region_addr, src, count)
            .map_err(VsockError::GuestMemoryMmap)
    }

    pub fn write_from_offset_to<F: Write>(
        &self,
        mem: &GuestMemoryMmap,
        offset: usize,
        dst: &mut F,
        count: usize,
    ) -> Result<usize> {
        let (region, region_addr) = self.buf_region_addr(mem, offset, count)?;
        region
            .write_to(region_addr, dst, count)
            .map_err(VsockError::GuestMemoryMmap)
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

    use std::io::Cursor;

    use vm_memory::{GuestAddress, GuestMemoryMmap};

    use super::*;
    use crate::virtio::test_utils::VirtqDesc as GuestQDesc;
    use crate::virtio::vsock::defs::MAX_PKT_BUF_SIZE;
    use crate::virtio::vsock::device::{RXQ_INDEX, TXQ_INDEX};
    use crate::virtio::vsock::test_utils::TestContext;
    use crate::virtio::VIRTQ_DESC_F_WRITE;

    macro_rules! create_context {
        ($test_ctx:ident, $handler_ctx:ident) => {
            let $test_ctx = TestContext::new();
            let mut $handler_ctx = $test_ctx.create_event_handler_context();
            // For TX packets, hdr.len should be set to a valid value.
            set_pkt_len(1024, &$handler_ctx.guest_txvq.dtable[0], &$test_ctx.mem);
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
            match VsockPacket::$ctor(
                &$handler_ctx.device.queues[$vq_index]
                    .pop(&$test_ctx.mem)
                    .unwrap(),
            ) {
                Err($err) => (),
                Ok(_) => panic!("Packet assembly should've failed!"),
                Err(other) => panic!("Packet assembly failed with: {:?}", other),
            }
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
        assert_eq!(VSOCK_PKT_HDR_SIZE, std::mem::size_of::<VsockPacketHeader>());
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_tx_packet_assembly() {
        // Test case: successful TX packet assembly.
        {
            create_context!(test_ctx, handler_ctx);

            let pkt = VsockPacket::from_tx_virtq_head(
                &handler_ctx.device.queues[TXQ_INDEX]
                    .pop(&test_ctx.mem)
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                pkt.buf_size(),
                handler_ctx.guest_txvq.dtable[1].len.get() as usize
            );
            assert_eq!(
                pkt.buf_addr.unwrap().0,
                handler_ctx.guest_txvq.dtable[1].addr.get()
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
                .set(VSOCK_PKT_HDR_SIZE as u32 - 1);
            expect_asm_error!(tx, test_ctx, handler_ctx, VsockError::HdrDescTooSmall(_));
        }

        // Test case: zero-length TX packet.
        {
            create_context!(test_ctx, handler_ctx);
            set_pkt_len(0, &handler_ctx.guest_txvq.dtable[0], &test_ctx.mem);
            let pkt = VsockPacket::from_tx_virtq_head(
                &handler_ctx.device.queues[TXQ_INDEX]
                    .pop(&test_ctx.mem)
                    .unwrap(),
            )
            .unwrap();
            assert!(pkt.buf_addr.is_none());
        }

        // Test case: TX packet has more data than we can handle.
        {
            create_context!(test_ctx, handler_ctx);
            set_pkt_len(
                MAX_PKT_BUF_SIZE as u32 + 1,
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
            expect_asm_error!(tx, test_ctx, handler_ctx, VsockError::BufDescMissing);
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
            expect_asm_error!(tx, test_ctx, handler_ctx, VsockError::BufDescTooSmall);
        }
    }

    #[test]
    fn test_rx_packet_assembly() {
        // Test case: successful RX packet assembly.
        {
            create_context!(test_ctx, handler_ctx);
            let pkt = VsockPacket::from_rx_virtq_head(
                &handler_ctx.device.queues[RXQ_INDEX]
                    .pop(&test_ctx.mem)
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                pkt.buf_size,
                handler_ctx.guest_rxvq.dtable[1].len.get() as usize
            );
            assert_eq!(
                pkt.buf_addr.unwrap().0,
                handler_ctx.guest_rxvq.dtable[1].addr.get()
            );
        }

        // Test case: read-only RX packet header.
        {
            create_context!(test_ctx, handler_ctx);
            handler_ctx.guest_rxvq.dtable[0].flags.set(0);
            expect_asm_error!(rx, test_ctx, handler_ctx, VsockError::UnwritableDescriptor);
        }

        // Test case: RX descriptor head cannot fit the entire packet header.
        {
            create_context!(test_ctx, handler_ctx);
            handler_ctx.guest_rxvq.dtable[0]
                .len
                .set(VSOCK_PKT_HDR_SIZE as u32 - 1);
            expect_asm_error!(rx, test_ctx, handler_ctx, VsockError::HdrDescTooSmall(_));
        }

        // Test case: RX descriptor chain is missing the packet buffer descriptor.
        {
            create_context!(test_ctx, handler_ctx);
            handler_ctx.guest_rxvq.dtable[0]
                .flags
                .set(VIRTQ_DESC_F_WRITE);
            expect_asm_error!(rx, test_ctx, handler_ctx, VsockError::BufDescMissing);
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
            &handler_ctx.device.queues[RXQ_INDEX]
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
        let mut pkt = VsockPacket::from_rx_virtq_head(
            &handler_ctx.device.queues[RXQ_INDEX]
                .pop(&test_ctx.mem)
                .unwrap(),
        )
        .unwrap();

        let buf_desc = &mut handler_ctx.guest_rxvq.dtable[1];
        assert_eq!(pkt.buf_size(), buf_desc.len.get() as usize);
        assert_eq!(pkt.buf_addr.unwrap().raw_value(), buf_desc.addr.get());

        let mut buf = vec![];
        let zeros = vec![0_u8; pkt.buf_size()];
        let data: Vec<u8> = (0..pkt.buf_size()).map(|i| (i % 0x100) as u8).collect();
        for offset in 0..pkt.buf_size() {
            buf_desc.set_data(&zeros);

            let mut expected_data = zeros[..offset].to_vec();
            expected_data.extend_from_slice(&data[..pkt.buf_size() - offset]);

            pkt.read_at_offset_from(
                &test_ctx.mem,
                offset,
                &mut Cursor::new(data.clone()),
                pkt.buf_size() - offset,
            )
            .unwrap();
            buf_desc.check_data(&expected_data);

            buf.clear();
            pkt.write_from_offset_to(&test_ctx.mem, offset, &mut buf, pkt.buf_size() - offset)
                .unwrap();
            assert_eq!(buf.as_slice(), &expected_data[offset..]);
        }

        let oob_cases = vec![
            (1, pkt.buf_size()),
            (pkt.buf_size(), 1),
            (usize::MAX, 1),
            (1, usize::MAX),
        ];
        for (offset, count) in oob_cases {
            assert!(pkt
                .read_at_offset_from(&test_ctx.mem, offset, &mut Cursor::new(data.clone()), count,)
                .is_err());
            assert!(pkt
                .write_from_offset_to(&test_ctx.mem, offset, &mut buf, count)
                .is_err());
        }
    }

    #[test]
    fn test_buf_region_addr_edge_cases() {
        let mut test_ctx = TestContext::new();

        test_ctx.mem = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0), 500),
            (GuestAddress(500), 100),
            (GuestAddress(600), 100),
        ])
        .unwrap();

        let edge_cases = vec![
            // valid packet, but offset = buf_size
            (GuestAddress(100), 100, 100, 0),
            // valid packet, but offset > buf_size
            (GuestAddress(100), 100, 101, 0),
            // valid packet, but offset + count > buf_size
            (GuestAddress(100), 100, 50, 51),
            // packet that crosses into the Gap
            (GuestAddress(450), 100, 0, 100),
            // packet that crosses over the Gap
            (GuestAddress(450), 200, 0, 200),
        ];
        for (buf_addr, buf_size, offset, count) in edge_cases {
            let pkt = VsockPacket {
                hdr_addr: GuestAddress(0),
                hdr: Default::default(),
                buf_addr: Some(buf_addr),
                buf_size,
            };
            assert!(pkt.buf_region_addr(&test_ctx.mem, offset, count).is_err());
        }
    }
}
