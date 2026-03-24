// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
use std::fmt::Debug;
/// The main job of `VsockConnection` is to forward data traffic, back and forth, between a
/// guest-side AF_VSOCK socket and a host-side generic `Read + Write + AsRawFd` stream, while
/// also managing its internal state.
/// To that end, `VsockConnection` implements:
/// - `VsockChannel` for:
///   - moving data from the host stream to a guest-provided RX buffer, via `recv_pkt()`; and
///   - moving data from a guest-provided TX buffer to the host stream, via `send_pkt()`; and
///   - updating its internal state, by absorbing control packets (anything other than
///     VSOCK_OP_RW).
/// - `VsockEpollListener` for getting notified about the availability of data or free buffer
///   space at the host stream.
///
/// Note: there is a certain asymmetry to the RX and TX data flows:
///       - RX transfers do not need any data buffering, since data is read straight from the
///         host stream and into the guest-provided RX buffer;
///       - TX transfers may require some data to be buffered by `VsockConnection`, if the host
///         peer can't keep up with reading the data that we're writing. This is because, once
///         the guest driver provides some data in a virtio TX buffer, the vsock device must
///         consume it.  If that data can't be forwarded straight to the host stream, we'll
///         have to store it in a buffer (and flush it at a later time). Vsock flow control
///         ensures that our TX buffer doesn't overflow.
// The code in this file is best read with a fresh memory of the vsock protocol inner-workings.
// To help with that, here is a
//
// Short primer on the vsock protocol
// ----------------------------------
//
// 1. Establishing a connection A vsock connection is considered established after a two-way
//    handshake:
//    - the initiating peer sends a connection request packet (`hdr.op` == VSOCK_OP_REQUEST);
//      then
//    - the listening peer sends back a connection response packet (`hdr.op` ==
//      VSOCK_OP_RESPONSE).
//
// 2. Terminating a connection When a peer wants to shut down an established connection, it
//    sends a VSOCK_OP_SHUTDOWN packet. Two header flags are used with VSOCK_OP_SHUTDOWN,
//    indicating the sender's intention:
//    - VSOCK_FLAGS_SHUTDOWN_RCV: the sender will receive no more data for this connection; and
//    - VSOCK_FLAGS_SHUTDOWN_SEND: the sender will send no more data for this connection.
//    After a shutdown packet, the receiving peer will have some protocol-undefined time to
//    flush its buffers, and then forcefully terminate the connection by sending back an RST
//    packet. If the shutdown-initiating peer doesn't receive this RST packet during a timeout
//    period, it will send one itself, thus terminating the connection.
//    Note: a peer can send more than one VSOCK_OP_SHUTDOWN packets. However, read/write
//          indications cannot be undone. E.g. once a "no-more-sending" promise was made, it
//          cannot be taken back.  That is, `hdr.flags` will be ORed between subsequent
//          VSOCK_OP_SHUTDOWN packets.
//
// 3. Flow control Before sending a data packet (VSOCK_OP_RW), the sender must make sure that
//    the receiver has enough free buffer space to store that data. If this condition is not
//    respected, the receiving peer's behaviour is undefined. In this implementation, we
//    forcefully terminate the connection by sending back a VSOCK_OP_RST packet. Note: all
//    buffer space information is computed and stored on a per-connection basis. Peers keep
//    each other informed about the free buffer space they have by filling in two packet header
//    members with each packet they send:
//    - `hdr.buf_alloc`: the total buffer space the peer has allocated for receiving data; and
//    - `hdr.fwd_cnt`: the total number of bytes the peer has successfully flushed out of its
//      buffer.
//    One can figure out how much space its peer has available in its buffer by inspecting the
//    difference between how much it has sent to the peer and how much the peer has flushed out
//    (i.e.  "forwarded", in the vsock spec terminology):
//    `peer_free = peer_buf_alloc - (total_bytes_sent_to_peer - peer_fwd_cnt)`.
//    Note: the above requires that peers constantly keep each other informed on their buffer
//          space situation. However, since there are no receipt acknowledgement packets
//          defined for the vsock protocol, packet flow can often be unidirectional (just one
//          peer sending data to another), so the sender's information about the receiver's
//          buffer space can get quickly outdated. The vsock protocol defines two solutions to
//          this problem:
//          1. The sender can explicitly ask for a buffer space (i.e. "credit") update from its
//             peer, via a VSOCK_OP_CREDIT_REQUEST packet, to which it will get a
//             VSOCK_OP_CREDIT_UPDATE response (or any response will do, really, since credit
//             information must be included in any packet);
//          2. The receiver can be proactive, and send VSOCK_OP_CREDIT_UPDATE packet, whenever
//             it thinks its peer's information is out of date.
//          Our implementation uses the proactive approach.
use std::io::{Cursor, Error, ErrorKind, Write};
use std::num::Wrapping;
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

use vm_memory::io::{ReadVolatile, WriteVolatile};
use vm_memory::{GuestMemoryError, VolatileMemory, VolatileSlice};
use vmm_sys_util::epoll::EventSet;

use super::super::defs::uapi;
use super::super::{VsockChannel, VsockEpollListener, VsockError};
use super::txbuf::TxBuf;
use super::{ConnState, PendingRx, PendingRxSet, VsockCsmError, defs};
use crate::devices::virtio::vsock::VsockUnixBackendError;
use crate::devices::virtio::vsock::metrics::METRICS;
use crate::devices::virtio::vsock::packet::{VsockPacketHeader, VsockPacketRx, VsockPacketTx};
use crate::devices::virtio::vsock::unix::{IncomingLength, ReadResult};
use crate::logger::{IncMetric, debug, error, info, warn};
use crate::utils::wrap_usize_to_u32;
use crate::vmm_config::vsock::VsockType;

/// Trait that vsock connection backends need to implement.
///
/// Used as an alias for `ReadVolatile + Write + WriteVolatile + AsRawFd`
/// (sadly, trait aliases are not supported,
/// <https://github.com/rust-lang/rfcs/pull/1733#issuecomment-243840014>).
pub trait VsockConnectionBackend: ReadVolatile + Write + WriteVolatile + AsRawFd {}

const DEFAULT_CONN_BUFFER_SIZE: usize = (64 * 1024);

/// A self-managing connection object, that handles communication between a guest-side AF_VSOCK
/// socket and a host-side `ReadVolatile + Write + WriteVolatile + AsRawFd` stream.
#[derive(Debug)]
pub struct VsockConnection<S: VsockConnectionBackend> {
    /// The current connection state.
    state: ConnState,
    /// The local CID. Most of the time this will be the constant `2` (the vsock host CID).
    local_cid: u64,
    /// The peer (guest) CID.
    peer_cid: u64,
    /// The local (host) port.
    local_port: u32,
    /// The peer (guest) port.
    peer_port: u32,
    /// The (connected) host-side stream.
    stream: S,
    /// The TX buffer for this connection.
    tx_buf: TxBuf,
    /// Total number of bytes that have been successfully written to `self.stream`, either
    /// directly, or flushed from `self.tx_buf`.
    fwd_cnt: Wrapping<u32>,
    /// The amount of buffer space that the peer (guest) has allocated for this connection.
    peer_buf_alloc: u32,
    /// The total number of bytes that the peer has forwarded away.
    peer_fwd_cnt: Wrapping<u32>,
    /// The total number of bytes sent to the peer (guest vsock driver)
    rx_cnt: Wrapping<u32>,
    /// Our `self.fwd_cnt`, as last sent to the peer. This is used to provide proactive credit
    /// updates, and let the peer know it's OK to send more data.
    last_fwd_cnt_to_peer: Wrapping<u32>,
    /// The set of pending RX packet indications that `recv_pkt()` will use to fill in a
    /// packet for the peer (guest).
    pending_rx: PendingRxSet,
    /// Instant when this connection should be scheduled for immediate termination, due to some
    /// timeout condition having been fulfilled.
    expiry: Option<Instant>,
    /// The type of the underlying socket connection
    vsock_type: VsockType,
    /// Intermediate buffer for bytes received from the AF_UNIX
    connection_buffer: Option<Cursor<Vec<u8>>>,
    /// The amount of bytes we wrote into the intermediate connection buffer
    conn_buf_size: usize,
}

impl<S: VsockConnectionBackend + Debug> VsockConnection<S> {
    fn recv_into(
        &mut self,
        pkt: &mut VsockPacketRx,
        max_len: u32,
    ) -> Result<ReadResult, VsockError> {
        match self.vsock_type {
            VsockType::Stream => {
                let stream_bytes_read = pkt.read_at_offset_from(&mut self.stream, 0, max_len)?;
                Ok(ReadResult::new(stream_bytes_read, false))
            }
            VsockType::Seqpacket => {
                if self.connection_buffer.is_none() {
                    let incoming_msg_size = self.stream.incoming_len().map_err(|e| {
                        VsockError::VsockUdsBackend(VsockUnixBackendError::UnixRead(e))
                    })?;

                    if incoming_msg_size > pkt.buf_size() as usize {
                        self.handle_new_packet_large(
                            pkt,
                            max_len,
                            u32::try_from(incoming_msg_size).unwrap_or(u32::MAX),
                        )
                    } else {
                        self.handle_new_packet_small(pkt, max_len)
                    }
                } else {
                    self.handle_connection_buffer_has_data(pkt, max_len)
                }
            }
        }
    }

    fn handle_new_packet_large(
        &mut self,
        pkt: &mut VsockPacketRx,
        max_len: u32,
        incoming_msg_len: u32,
    ) -> Result<ReadResult, VsockError> {
        if incoming_msg_len as usize > self.conn_buf_size {
            return Err(VsockError::MessageTooLong(
                u32::try_from(self.conn_buf_size).unwrap_or(u32::MAX),
                incoming_msg_len,
            ));
        }

        let mut backing_vector = vec![0u8; incoming_msg_len as usize];
        {
            // SAFETY: `backing_vector` is a valid Vec<u8> and we hold a mutable reference to it,
            // guaranteeing exclusive access for the duration of this call.
            let mut vol_slice = unsafe {
                VolatileSlice::new(backing_vector.as_mut_ptr(), incoming_msg_len as usize)
            };
            self.stream
                .read_volatile(&mut vol_slice)
                .map_err(VsockError::VolatileMemory)?;
        }

        let mut cursor = Cursor::new(backing_vector);
        let b = pkt.read_at_offset_from(&mut cursor, 0, max_len)?;
        self.connection_buffer = Some(cursor);

        Ok(ReadResult::new(b, true))
    }

    fn handle_new_packet_small(
        &mut self,
        pkt: &mut VsockPacketRx,
        max_len: u32,
    ) -> Result<ReadResult, VsockError> {
        let b = pkt.read_at_offset_from(&mut self.stream, 0, max_len)?;
        // packet is small enough to fit into a single descriptor, set EOM/EOR directly.
        pkt.hdr.set_msg_eom().set_msg_eor();
        Ok(ReadResult::new(b, false))
    }

    fn handle_connection_buffer_has_data(
        &mut self,
        pkt: &mut VsockPacketRx,
        max_len: u32,
    ) -> Result<ReadResult, VsockError> {
        let Some(ref mut conn_buf) = self.connection_buffer else {
            return Err(VsockError::PktBufMissing);
        };

        let conn_buffer_rem = u32::try_from(conn_buf.get_ref().len() as u64 - conn_buf.position())
            .unwrap_or(u32::MAX);

        let b = pkt.read_at_offset_from(conn_buf, 0, max_len.min(conn_buffer_rem))?;

        // set MSG_EOM/EOR if we finished the buffer and mark should
        // retrigger as false. or mark should retrigger to true to
        // make another read happen
        let done = conn_buf.position() >= conn_buf.get_ref().len() as u64;
        if done {
            self.connection_buffer = None;
            pkt.hdr.set_msg_eom().set_msg_eor();
            Ok(ReadResult::new(b, false))
        } else {
            Ok(ReadResult::new(b, true))
        }
    }
}

impl<S> VsockChannel for VsockConnection<S>
where
    S: VsockConnectionBackend + Debug,
{
    /// Fill in a vsock packet, to be delivered to our peer (the guest driver).
    ///
    /// As per the `VsockChannel` trait, this should only be called when there is data to be
    /// fetched from the channel (i.e. `has_pending_rx()` is true). Otherwise, it will error
    /// out with `VsockError::NoData`.
    /// Pending RX indications are set by other mutable actions performed on the channel. For
    /// instance, `send_pkt()` could set an Rst indication, if called with a VSOCK_OP_SHUTDOWN
    /// packet, or `notify()` could set a Rw indication (a data packet can be fetched from the
    /// channel), if data was ready to be read from the host stream.
    ///
    /// Returns:
    /// - `Ok(())`: the packet has been successfully filled in and is ready for delivery;
    /// - `Err(VsockError::NoData)`: there was no data available with which to fill in the packet;
    /// - `Err(VsockError::PktBufMissing)`: the packet would've been filled in with data, but it is
    ///   missing the data buffer.
    fn recv_pkt(&mut self, pkt: &mut VsockPacketRx) -> Result<ReadResult, VsockError> {
        // Perform some generic initialization that is the same for any packet operation (e.g.
        // source, destination, credit, etc).
        self.init_pkt_hdr(&mut pkt.hdr);
        METRICS.rx_packets_count.inc();

        // If forceful termination is pending, there's no point in checking for anything else.
        // It's dead, Jim.
        if self.pending_rx.remove(PendingRx::Rst) {
            pkt.hdr.set_op(uapi::VSOCK_OP_RST);
            return Ok(ReadResult::default());
        }

        // Next up: if we're due a connection confirmation, that's all we need to know to fill
        // in this packet.
        if self.pending_rx.remove(PendingRx::Response) {
            self.state = ConnState::Established;
            pkt.hdr.set_op(uapi::VSOCK_OP_RESPONSE);
            return Ok(ReadResult::default());
        }

        // Same thing goes for locally-initiated connections that need to yield a connection
        // request.
        if self.pending_rx.remove(PendingRx::Request) {
            self.expiry =
                Some(Instant::now() + Duration::from_millis(defs::CONN_REQUEST_TIMEOUT_MS));
            pkt.hdr.set_op(uapi::VSOCK_OP_REQUEST);
            return Ok(ReadResult::default());
        }

        if self.pending_rx.remove(PendingRx::Rw) {
            // We're due to produce a data packet, by reading the data from the host-side
            // Unix socket.

            match self.state {
                // A data packet is only valid for established connections, and connections for
                // which our peer has initiated a graceful shutdown, but can still receive data.
                ConnState::Established | ConnState::PeerClosed(false, _) => (),
                _ => {
                    // Any other connection state is invalid at this point, and we need to kill it
                    // with fire.
                    pkt.hdr.set_op(uapi::VSOCK_OP_RST);
                    return Ok(ReadResult::default());
                }
            }

            // Oh wait, before we start bringing in the big data, can our peer handle receiving so
            // much bytey goodness?
            if self.need_credit_update_from_peer() {
                self.last_fwd_cnt_to_peer = self.fwd_cnt;
                pkt.hdr.set_op(uapi::VSOCK_OP_CREDIT_REQUEST);
                return Ok(ReadResult::default());
            }

            // The maximum amount of data we can read in is limited by both the RX buffer size and
            // the peer available buffer space.
            let max_len = std::cmp::min(pkt.buf_size(), self.peer_avail_credit());

            let recv_res = self.recv_into(pkt, max_len);
            match recv_res {
                Ok(res) => {
                    if res.bytes_read == 0 {
                        // A 0-length read means the host stream was closed down. In that case,
                        // we'll ask our peer to shut down the connection. We can neither send nor
                        // receive any more data.
                        self.state = ConnState::LocalClosed;
                        self.expiry = Some(
                            Instant::now() + Duration::from_millis(defs::CONN_SHUTDOWN_TIMEOUT_MS),
                        );
                        pkt.hdr
                            .set_op(uapi::VSOCK_OP_SHUTDOWN)
                            .set_flag(uapi::VSOCK_FLAGS_SHUTDOWN_RCV)
                            .set_flag(uapi::VSOCK_FLAGS_SHUTDOWN_SEND);
                    } else {
                        // On a successful data read, we fill in the packet with the RW op, and
                        // length of the read data.
                        // Safe to unwrap because read_cnt is no more than max_len, which is bounded
                        // by self.peer_avail_credit(), a u32 internally.
                        pkt.hdr.set_op(uapi::VSOCK_OP_RW).set_len(res.bytes_read);
                        METRICS.rx_bytes_count.add(res.bytes_read as u64);
                    }
                    self.rx_cnt += Wrapping(pkt.hdr.len());
                    self.last_fwd_cnt_to_peer = self.fwd_cnt;

                    // the read was buffered into an intermediate vector and this
                    // means there is still data to process but no fd event will
                    // kick off. manually push a a PendingRx queue entry
                    if res.should_retrigger {
                        self.pending_rx.insert(PendingRx::Rw);
                    }
                    return Ok(res);
                }
                Err(VsockError::GuestMemoryMmap(GuestMemoryError::IOError(err)))
                    if err.kind() == ErrorKind::WouldBlock =>
                {
                    // This shouldn't actually happen (receiving EWOULDBLOCK after EPOLLIN), but
                    // apparently it does, so we need to handle it gracefully.
                    warn!(
                        "vsock: unexpected EWOULDBLOCK while reading from backing stream: lp={}, \
                         pp={}, err={:?}",
                        self.local_port, self.peer_port, err
                    );
                }
                Err(err) => {
                    // We are not expecting any other errors when reading from the underlying
                    // stream. If any show up, we'll immediately kill this connection.
                    METRICS.rx_read_fails.inc();
                    error!(
                        "vsock: error reading from backing stream: lp={}, pp={}, err={:?}",
                        self.local_port, self.peer_port, err
                    );
                    pkt.hdr.set_op(uapi::VSOCK_OP_RST);
                    self.last_fwd_cnt_to_peer = self.fwd_cnt;
                    return Ok(ReadResult::default());
                }
            };
        }

        // A credit update is basically a no-op, so we should only waste a perfectly fine RX
        // buffer on it if we really have nothing else to say, hence we check for this RX
        // indication last.
        if self.pending_rx.remove(PendingRx::CreditUpdate) && !self.has_pending_rx() {
            pkt.hdr.set_op(uapi::VSOCK_OP_CREDIT_UPDATE);
            self.last_fwd_cnt_to_peer = self.fwd_cnt;
            return Ok(ReadResult::default());
        }

        // We've already checked for all conditions that would have produced a packet, so
        // if we got to here, we don't know how to yield one.
        Err(VsockError::NoData)
    }

    /// Deliver a guest-generated packet to this connection.
    ///
    /// This forwards the data in RW packets to the host stream, and absorbs control packets,
    /// using them to manage the internal connection state.
    ///
    /// Returns:
    /// always `Ok(())`: the packet has been consumed;
    fn send_pkt(&mut self, pkt: &VsockPacketTx) -> Result<(), VsockError> {
        // Update the peer credit information.
        self.peer_buf_alloc = pkt.hdr.buf_alloc();
        self.peer_fwd_cnt = Wrapping(pkt.hdr.fwd_cnt());
        METRICS.tx_packets_count.inc();

        match self.state {
            // Most frequent case: this is an established connection that needs to forward some
            // data to the host stream. Also works for a connection that has begun shutting
            // down, but the peer still has some data to send.
            ConnState::Established | ConnState::PeerClosed(_, false)
                if pkt.hdr.op() == uapi::VSOCK_OP_RW =>
            {
                if pkt.buf_size() == 0 {
                    info!(
                        "vsock: dropping empty data packet from guest (lp={}, pp={}",
                        self.local_port, self.peer_port
                    );
                    return Ok(());
                }

                // Unwrapping here is safe, since we just checked `pkt.buf()` above.
                if let Err(err) = self.send_bytes(pkt) {
                    // If we can't write to the host stream, that's an unrecoverable error, so
                    // we'll terminate this connection.
                    warn!(
                        "vsock: error writing to local stream (lp={}, pp={}): {:?}",
                        self.local_port, self.peer_port, err
                    );
                    self.kill();
                    return Ok(());
                }

                // We might've just consumed some data. If that's the case, we might need to
                // update the peer on our buffer space situation, so that it can keep sending
                // data packets our way.
                if self.peer_needs_credit_update() {
                    self.pending_rx.insert(PendingRx::CreditUpdate);
                }
            }

            // Next up: receiving a response / confirmation for a host-initiated connection.
            // We'll move to an Established state, and pass on the good news through the host
            // stream.
            ConnState::LocalInit if pkt.hdr.op() == uapi::VSOCK_OP_RESPONSE => {
                self.expiry = None;
                self.state = ConnState::Established;
            }

            // The peer wants to shut down an established connection.  If they have nothing
            // more to send nor receive, and we don't have to wait to drain our TX buffer, we
            // can schedule an RST packet (to terminate the connection on the next recv call).
            // Otherwise, we'll arm the kill timer.
            ConnState::Established if pkt.hdr.op() == uapi::VSOCK_OP_SHUTDOWN => {
                let recv_off = pkt.hdr.flags() & uapi::VSOCK_FLAGS_SHUTDOWN_RCV != 0;
                let send_off = pkt.hdr.flags() & uapi::VSOCK_FLAGS_SHUTDOWN_SEND != 0;
                self.state = ConnState::PeerClosed(recv_off, send_off);
                if recv_off && send_off {
                    if self.tx_buf.is_empty() {
                        self.pending_rx.insert(PendingRx::Rst);
                    } else {
                        self.expiry = Some(
                            Instant::now() + Duration::from_millis(defs::CONN_SHUTDOWN_TIMEOUT_MS),
                        );
                    }
                }
            }

            // The peer wants to update a shutdown request, with more receive/send indications.
            // The same logic as above applies.
            ConnState::PeerClosed(ref mut recv_off, ref mut send_off)
                if pkt.hdr.op() == uapi::VSOCK_OP_SHUTDOWN =>
            {
                *recv_off = *recv_off || (pkt.hdr.flags() & uapi::VSOCK_FLAGS_SHUTDOWN_RCV != 0);
                *send_off = *send_off || (pkt.hdr.flags() & uapi::VSOCK_FLAGS_SHUTDOWN_SEND != 0);
                if *recv_off && *send_off && self.tx_buf.is_empty() {
                    self.pending_rx.insert(PendingRx::Rst);
                }
            }

            // A credit update from our peer is valid only in a state which allows data
            // transfer towards the peer.
            ConnState::Established | ConnState::PeerInit | ConnState::PeerClosed(false, _)
                if pkt.hdr.op() == uapi::VSOCK_OP_CREDIT_UPDATE =>
            {
                // Nothing to do here; we've already updated peer credit.
            }

            // A credit request from our peer is valid only in a state which allows data
            // transfer from the peer. We'll respond with a credit update packet.
            ConnState::Established | ConnState::PeerInit | ConnState::PeerClosed(_, false)
                if pkt.hdr.op() == uapi::VSOCK_OP_CREDIT_REQUEST =>
            {
                self.pending_rx.insert(PendingRx::CreditUpdate);
            }

            _ => {
                debug!(
                    "vsock: dropping invalid TX pkt for connection: state={:?}, pkt.hdr={:?}",
                    self.state, pkt.hdr
                );
            }
        };

        Ok(())
    }

    /// Check if the connection has any pending packet addressed to the peer.
    fn has_pending_rx(&self) -> bool {
        !self.pending_rx.is_empty()
    }
}

impl<S> AsRawFd for VsockConnection<S>
where
    S: VsockConnectionBackend + Debug,
{
    /// Get the file descriptor that this connection wants polled.
    ///
    /// The connection is interested in being notified about EPOLLIN / EPOLLOUT events on the
    /// host stream.
    fn as_raw_fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }
}

impl<S> VsockEpollListener for VsockConnection<S>
where
    S: VsockConnectionBackend + Debug,
{
    /// Get the event set that this connection is interested in.
    ///
    /// A connection will want to be notified when:
    /// - data is available to be read from the host stream, so that it can store an RW pending RX
    ///   indication; and
    /// - data can be written to the host stream, and the TX buffer needs to be flushed.
    fn get_polled_evset(&self) -> EventSet {
        let mut evset = EventSet::empty();
        if !self.tx_buf.is_empty() {
            // There's data waiting in the TX buffer, so we are interested in being notified
            // when writing to the host stream wouldn't block.
            evset.insert(EventSet::OUT);
        }
        // We're generally interested in being notified when data can be read from the host
        // stream, unless we're in a state which doesn't allow moving data from host to guest.
        match self.state {
            ConnState::Killed | ConnState::LocalClosed | ConnState::PeerClosed(true, _) => (),
            _ if self.need_credit_update_from_peer() => (),
            _ => evset.insert(EventSet::IN),
        }
        evset
    }

    /// Notify the connection about an event (or set of events) that it was interested in.
    fn notify(&mut self, evset: EventSet) {
        if evset.contains(EventSet::IN) {
            // Data can be read from the host stream. Setting a Rw pending indication, so that
            // the muxer will know to call `recv_pkt()` later.
            self.pending_rx.insert(PendingRx::Rw);
        }

        if evset.contains(EventSet::OUT) {
            // Data can be written to the host stream. Time to flush out the TX buffer.
            //
            if self.tx_buf.is_empty() {
                METRICS.conn_event_fails.inc();
                info!("vsock: connection received unexpected EPOLLOUT event");
                return;
            }
            let flushed = self
                .tx_buf
                .flush_to(&mut self.stream)
                .unwrap_or_else(|err| {
                    METRICS.tx_flush_fails.inc();
                    warn!(
                        "vsock: error flushing TX buf for (lp={}, pp={}): {:?}",
                        self.local_port, self.peer_port, err
                    );
                    match err {
                        VsockCsmError::TxBufFlush(inner)
                            if inner.kind() == ErrorKind::WouldBlock =>
                        {
                            // This should never happen (EWOULDBLOCK after EPOLLOUT), but
                            // it does, so let's absorb it.
                        }
                        _ => self.kill(),
                    };
                    0
                });
            self.fwd_cnt += wrap_usize_to_u32(flushed);
            METRICS.tx_bytes_count.add(flushed as u64);

            // If this connection was shutting down, but is waiting to drain the TX buffer
            // before forceful termination, the wait might be over.
            if self.state == ConnState::PeerClosed(true, true) && self.tx_buf.is_empty() {
                self.pending_rx.insert(PendingRx::Rst);
            } else if self.peer_needs_credit_update() {
                // If we've freed up some more buffer space, we may need to let the peer know it
                // can safely send more data our way.
                self.pending_rx.insert(PendingRx::CreditUpdate);
            }
        }
    }
}

impl<S> VsockConnection<S>
where
    S: VsockConnectionBackend + Debug,
{
    /// Create a new guest-initiated connection object.
    #[allow(clippy::too_many_arguments)]
    pub fn new_peer_init(
        stream: S,
        local_cid: u64,
        peer_cid: u64,
        local_port: u32,
        peer_port: u32,
        peer_buf_alloc: u32,
        vsock_type: VsockType,
        conn_buffer_size: Option<usize>,
    ) -> Self {
        let buf_size = match vsock_type {
            VsockType::Seqpacket => conn_buffer_size.unwrap_or(DEFAULT_CONN_BUFFER_SIZE),
            VsockType::Stream => 0,
        };
        Self {
            local_cid,
            peer_cid,
            local_port,
            peer_port,
            stream,
            state: ConnState::PeerInit,
            tx_buf: TxBuf::new(),
            fwd_cnt: Wrapping(0),
            peer_buf_alloc,
            peer_fwd_cnt: Wrapping(0),
            rx_cnt: Wrapping(0),
            last_fwd_cnt_to_peer: Wrapping(0),
            pending_rx: PendingRxSet::from(PendingRx::Response),
            expiry: None,
            vsock_type,
            connection_buffer: None,
            conn_buf_size: buf_size,
        }
    }

    /// Create a new host-initiated connection object.
    pub fn new_local_init(
        stream: S,
        local_cid: u64,
        peer_cid: u64,
        local_port: u32,
        peer_port: u32,
        vsock_type: VsockType,
        conn_buffer_size: Option<usize>,
    ) -> Self {
        let buf_size = match vsock_type {
            VsockType::Seqpacket => conn_buffer_size.unwrap_or(DEFAULT_CONN_BUFFER_SIZE),
            VsockType::Stream => 0,
        };
        Self {
            local_cid,
            peer_cid,
            local_port,
            peer_port,
            stream,
            state: ConnState::LocalInit,
            tx_buf: TxBuf::new(),
            fwd_cnt: Wrapping(0),
            peer_buf_alloc: 0,
            peer_fwd_cnt: Wrapping(0),
            rx_cnt: Wrapping(0),
            last_fwd_cnt_to_peer: Wrapping(0),
            pending_rx: PendingRxSet::from(PendingRx::Request),
            expiry: None,
            vsock_type,
            connection_buffer: None,
            conn_buf_size: buf_size,
        }
    }

    /// Check if there is an expiry (kill) timer set for this connection, sometime in the
    /// future.
    pub fn will_expire(&self) -> bool {
        match self.expiry {
            None => false,
            Some(t) => t > Instant::now(),
        }
    }

    /// Check if this connection needs to be scheduled for forceful termination, due to its
    /// kill timer having expired.
    pub fn has_expired(&self) -> bool {
        match self.expiry {
            None => false,
            Some(t) => t <= Instant::now(),
        }
    }

    /// Get the kill timer value, if one is set.
    pub fn expiry(&self) -> Option<Instant> {
        self.expiry
    }

    /// Schedule the connection to be forcefully terminated ASAP (i.e. the next time the
    /// connection is asked to yield a packet, via `recv_pkt()`).
    pub fn kill(&mut self) {
        self.state = ConnState::Killed;
        self.pending_rx.insert(PendingRx::Rst);
    }

    /// Return the connections state.
    pub fn state(&self) -> ConnState {
        self.state
    }

    /// Send some raw, untracked, data straight to the underlying connected stream.
    /// Returns: number of bytes written, or the error describing the write failure.
    ///
    /// Warning: this will bypass the connection state machine and write directly to the
    /// underlying stream. No account of this write is kept, which includes bypassing
    /// vsock flow control.
    pub fn send_bytes_raw(&mut self, buf: &[u8]) -> Result<usize, VsockCsmError> {
        self.stream.write(buf).map_err(VsockCsmError::StreamWrite)
    }

    /// Send some raw data (a byte-slice) to the host stream.
    ///
    /// Raw data can either be sent straight to the host stream, or to our TX buffer, if the
    /// former fails.
    fn send_bytes(&mut self, pkt: &VsockPacketTx) -> Result<(), VsockError> {
        let len = pkt.hdr.len();

        // If there is data in the TX buffer, that means we're already registered for EPOLLOUT
        // events on the underlying stream. Therefore, there's no point in attempting a write
        // at this point. `self.notify()` will get called when EPOLLOUT arrives, and it will
        // attempt to drain the TX buffer then.
        if !self.tx_buf.is_empty() {
            return pkt
                .write_from_offset_to(&mut self.tx_buf, 0, len)
                .map(|_| ());
        }

        // The TX buffer is empty, so we can try to write straight to the host stream.
        let written = match pkt.write_from_offset_to(&mut self.stream, 0, len) {
            Ok(cnt) => cnt,
            Err(VsockError::GuestMemoryMmap(GuestMemoryError::IOError(err)))
                if err.kind() == ErrorKind::WouldBlock =>
            {
                // Absorb any would-block errors, since we can always try again later.
                0
            }
            Err(err) => {
                // We don't know how to handle any other write error, so we'll send it up
                // the call chain.
                METRICS.tx_write_fails.inc();
                return Err(err);
            }
        };
        // Move the "forwarded bytes" counter ahead by how much we were able to send out.
        // Safe to unwrap because the maximum value is pkt.len(), which is a u32.
        self.fwd_cnt += written;
        METRICS.tx_bytes_count.add(written as u64);

        // If we couldn't write the whole slice, we'll need to push the remaining data to our
        // buffer.
        if written < len {
            pkt.write_from_offset_to(&mut self.tx_buf, written, len - written)?;
        }

        Ok(())
    }

    /// Check if the credit information the peer has last received from us is outdated.
    fn peer_needs_credit_update(&self) -> bool {
        let peer_seen_free_buf =
            Wrapping(defs::CONN_TX_BUF_SIZE) - (self.fwd_cnt - self.last_fwd_cnt_to_peer);
        peer_seen_free_buf < Wrapping(defs::CONN_CREDIT_UPDATE_THRESHOLD)
    }

    /// Check if we need to ask the peer for a credit update before sending any more data its
    /// way.
    fn need_credit_update_from_peer(&self) -> bool {
        self.peer_avail_credit() == 0
    }

    /// Get the maximum number of bytes that we can send to our peer, without overflowing its
    /// buffer.
    fn peer_avail_credit(&self) -> u32 {
        (Wrapping(self.peer_buf_alloc) - (self.rx_cnt - self.peer_fwd_cnt)).0
    }

    /// Prepare a packet header for transmission to our peer.
    fn init_pkt_hdr(&self, hdr: &mut VsockPacketHeader) {
        hdr.set_src_cid(self.local_cid)
            .set_dst_cid(self.peer_cid)
            .set_src_port(self.local_port)
            .set_dst_port(self.peer_port)
            .set_buf_alloc(defs::CONN_TX_BUF_SIZE)
            .set_fwd_cnt(self.fwd_cnt.0);
        match self.vsock_type {
            VsockType::Seqpacket => hdr.set_type(uapi::VSOCK_TYPE_SEQPACKET),
            VsockType::Stream => hdr.set_type(uapi::VSOCK_TYPE_STREAM),
        };
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Error as IoError, ErrorKind, Write};
    use std::os::unix::io::RawFd;
    use std::time::{Duration, Instant};

    use vm_memory::{VolatileMemoryError, VolatileSlice};
    use vmm_sys_util::eventfd::EventFd;

    use super::super::super::defs::uapi;
    use super::super::defs as csm_defs;
    use super::*;
    use crate::devices::virtio::vsock::device::{RXQ_INDEX, TXQ_INDEX};
    use crate::devices::virtio::vsock::test_utils;
    use crate::devices::virtio::vsock::test_utils::TestContext;
    use crate::vstate::memory::BitmapSlice;

    const LOCAL_CID: u64 = 2;
    const PEER_CID: u64 = 3;
    const LOCAL_PORT: u32 = 1002;
    const PEER_PORT: u32 = 1003;
    const PEER_BUF_ALLOC: u32 = 64 * 1024;

    #[derive(Debug)]
    enum StreamState {
        Closed,
        Error(ErrorKind),
        Ready,
        WouldBlock,
    }

    #[derive(Debug)]
    struct TestStream {
        fd: EventFd,
        read_buf: Vec<u8>,
        read_state: StreamState,
        write_buf: Vec<u8>,
        write_state: StreamState,
    }
    impl TestStream {
        fn new() -> Self {
            Self {
                fd: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
                read_state: StreamState::Ready,
                write_state: StreamState::Ready,
                read_buf: Vec::new(),
                write_buf: Vec::new(),
            }
        }
        fn new_with_read_buf(buf: &[u8]) -> Self {
            let mut stream = Self::new();
            stream.read_buf = buf.to_vec();
            stream
        }
    }

    impl AsRawFd for TestStream {
        fn as_raw_fd(&self) -> RawFd {
            self.fd.as_raw_fd()
        }
    }

    impl ReadVolatile for TestStream {
        fn read_volatile<B: BitmapSlice>(
            &mut self,
            buf: &mut VolatileSlice<B>,
        ) -> Result<usize, VolatileMemoryError> {
            match self.read_state {
                StreamState::Closed => Ok(0),
                StreamState::Error(kind) => Err(vm_memory::VolatileMemoryError::IOError(
                    IoError::new(kind, "whatevs"),
                )),
                StreamState::Ready => {
                    if self.read_buf.is_empty() {
                        return Err(vm_memory::VolatileMemoryError::IOError(IoError::new(
                            ErrorKind::WouldBlock,
                            "EAGAIN",
                        )));
                    }
                    let len = std::cmp::min(buf.len(), self.read_buf.len());
                    assert_ne!(len, 0);
                    buf.copy_from(&self.read_buf[..len]);
                    self.read_buf = self.read_buf.split_off(len);
                    Ok(len)
                }
                StreamState::WouldBlock => Err(vm_memory::VolatileMemoryError::IOError(
                    IoError::new(ErrorKind::WouldBlock, "EAGAIN"),
                )),
            }
        }
    }

    impl Write for TestStream {
        fn write(&mut self, data: &[u8]) -> Result<usize, IoError> {
            self.write_volatile(&VolatileSlice::from(data.to_vec().as_mut_slice()))
                .map_err(|err| match err {
                    vm_memory::VolatileMemoryError::IOError(io_err) => io_err,
                    _ => unreachable!(),
                })
        }

        fn flush(&mut self) -> Result<(), IoError> {
            Ok(())
        }
    }

    impl WriteVolatile for TestStream {
        fn write_volatile<B: BitmapSlice>(
            &mut self,
            buf: &VolatileSlice<B>,
        ) -> Result<usize, VolatileMemoryError> {
            match self.write_state {
                StreamState::Closed => Err(VolatileMemoryError::IOError(IoError::new(
                    ErrorKind::BrokenPipe,
                    "EPIPE",
                ))),
                StreamState::Error(kind) => {
                    Err(VolatileMemoryError::IOError(IoError::new(kind, "whatevs")))
                }
                StreamState::Ready => self.write_buf.write_volatile(buf),
                StreamState::WouldBlock => Err(VolatileMemoryError::IOError(IoError::new(
                    ErrorKind::WouldBlock,
                    "EAGAIN",
                ))),
            }
        }
    }

    impl VsockConnectionBackend for TestStream {}

    impl<S> VsockConnection<S>
    where
        S: VsockConnectionBackend + Debug,
    {
        /// Get the fwd_cnt value from the connection.
        pub(crate) fn fwd_cnt(&self) -> Wrapping<u32> {
            self.fwd_cnt
        }

        /// Forcefully insert a credit update flag.
        pub(crate) fn insert_credit_update(&mut self) {
            self.pending_rx.insert(PendingRx::CreditUpdate);
        }
    }

    fn init_pkt_hdr(hdr: &mut VsockPacketHeader, op: u16, len: u32) {
        hdr.set_src_cid(PEER_CID)
            .set_dst_cid(LOCAL_CID)
            .set_src_port(PEER_PORT)
            .set_dst_port(LOCAL_PORT)
            .set_type(uapi::VSOCK_TYPE_STREAM)
            .set_buf_alloc(PEER_BUF_ALLOC)
            .set_op(op)
            .set_len(len);
    }

    // This is the connection state machine test context: a helper struct to provide CSM testing
    // primitives. A single `VsockPacket` object will be enough for our testing needs. We'll be
    // using it for simulating both packet sends and packet receives. We need to keep the vsock
    // testing context alive, since `VsockPacket` is just a pointer-wrapper over some data that
    // resides in guest memory. The vsock test context owns the `GuestMemoryMmap` object, so we'll
    // make it a member here, in order to make sure that guest memory outlives our testing
    // packet.  A single `VsockConnection` object will also suffice for our testing needs. We'll
    // be using a specially crafted `Read + Write + AsRawFd` object as a backing stream, so that
    // we can control the various error conditions that might arise.
    #[derive(Debug)]
    struct CsmTestContext {
        _vsock_test_ctx: TestContext,
        // Two views of the same in-memory packet. rx-view for writing, tx-view for reading
        rx_pkt: VsockPacketRx,
        tx_pkt: VsockPacketTx,
        conn: VsockConnection<TestStream>,
    }

    impl CsmTestContext {
        fn new_established() -> Self {
            Self::new(ConnState::Established)
        }

        fn new(conn_state: ConnState) -> Self {
            let vsock_test_ctx = TestContext::new();
            let mut handler_ctx = vsock_test_ctx.create_event_handler_context();
            let stream = TestStream::new();
            let mut rx_pkt = VsockPacketRx::new().unwrap();
            rx_pkt
                .parse(
                    &vsock_test_ctx.mem,
                    handler_ctx.device.queues[RXQ_INDEX].pop().unwrap().unwrap(),
                )
                .unwrap();
            let mut tx_pkt = VsockPacketTx::default();
            tx_pkt
                .parse(
                    &vsock_test_ctx.mem,
                    handler_ctx.device.queues[TXQ_INDEX].pop().unwrap().unwrap(),
                )
                .unwrap();
            let conn = match conn_state {
                ConnState::PeerInit => VsockConnection::<TestStream>::new_peer_init(
                    stream,
                    LOCAL_CID,
                    PEER_CID,
                    LOCAL_PORT,
                    PEER_PORT,
                    PEER_BUF_ALLOC,
                    VsockType::Stream,
                    None,
                ),
                ConnState::LocalInit => VsockConnection::<TestStream>::new_local_init(
                    stream,
                    LOCAL_CID,
                    PEER_CID,
                    LOCAL_PORT,
                    PEER_PORT,
                    VsockType::Stream,
                    None,
                ),
                ConnState::Established => {
                    let mut conn = VsockConnection::<TestStream>::new_peer_init(
                        stream,
                        LOCAL_CID,
                        PEER_CID,
                        LOCAL_PORT,
                        PEER_PORT,
                        PEER_BUF_ALLOC,
                        VsockType::Stream,
                        None,
                    );
                    assert!(conn.has_pending_rx());
                    conn.recv_pkt(&mut rx_pkt).unwrap();
                    assert_eq!(rx_pkt.hdr.op(), uapi::VSOCK_OP_RESPONSE);
                    conn
                }
                other => panic!("invalid ctx state: {:?}", other),
            };
            assert_eq!(conn.state, conn_state);
            Self {
                _vsock_test_ctx: vsock_test_ctx,
                rx_pkt,
                tx_pkt,
                conn,
            }
        }

        fn set_stream(&mut self, stream: TestStream) {
            self.conn.stream = stream;
        }

        fn set_peer_credit(&mut self, credit: u32) {
            assert!(credit < self.conn.peer_buf_alloc);
            self.conn.peer_fwd_cnt = Wrapping(0);
            self.conn.rx_cnt = Wrapping(self.conn.peer_buf_alloc - credit);
            assert_eq!(self.conn.peer_avail_credit(), credit);
        }

        fn send(&mut self) {
            self.conn.send_pkt(&self.tx_pkt).unwrap();
        }

        fn recv(&mut self) {
            self.conn.recv_pkt(&mut self.rx_pkt).unwrap();
        }

        fn notify_epollin(&mut self) {
            self.conn.notify(EventSet::IN);
            assert!(self.conn.has_pending_rx());
        }

        fn notify_epollout(&mut self) {
            self.conn.notify(EventSet::OUT);
        }

        fn init_tx_pkt(&mut self, op: u16, len: u32) -> &mut VsockPacketTx {
            init_pkt_hdr(&mut self.tx_pkt.hdr, op, len);
            &mut self.tx_pkt
        }

        fn init_data_tx_pkt(&mut self, mut data: &[u8]) -> &VsockPacketTx {
            assert!(data.len() <= self.tx_pkt.buf_size() as usize);
            self.init_tx_pkt(uapi::VSOCK_OP_RW, u32::try_from(data.len()).unwrap());

            let len = data.len();
            self.rx_pkt
                .read_at_offset_from(&mut data, 0, len.try_into().unwrap())
                .unwrap();
            &self.tx_pkt
        }
    }

    #[test]
    fn test_peer_request() {
        let mut ctx = CsmTestContext::new(ConnState::PeerInit);
        assert!(ctx.conn.has_pending_rx());
        ctx.recv();
        // For peer-initiated requests, our connection should always yield a vsock reponse packet,
        // in order to establish the connection.
        assert_eq!(ctx.rx_pkt.hdr.op(), uapi::VSOCK_OP_RESPONSE);
        assert_eq!(ctx.rx_pkt.hdr.src_cid(), LOCAL_CID);
        assert_eq!(ctx.rx_pkt.hdr.dst_cid(), PEER_CID);
        assert_eq!(ctx.rx_pkt.hdr.src_port(), LOCAL_PORT);
        assert_eq!(ctx.rx_pkt.hdr.dst_port(), PEER_PORT);
        assert_eq!(ctx.rx_pkt.hdr.type_(), uapi::VSOCK_TYPE_STREAM);
        assert_eq!(ctx.rx_pkt.hdr.len(), 0);
        // After yielding the response packet, the connection should have transitioned to the
        // established state.
        assert_eq!(ctx.conn.state, ConnState::Established);
    }

    #[test]
    fn test_local_request() {
        let mut ctx = CsmTestContext::new(ConnState::LocalInit);
        // Host-initiated connections should first yield a connection request packet.
        assert!(ctx.conn.has_pending_rx());
        // Before yielding the connection request packet, the timeout kill timer shouldn't be
        // armed.
        assert!(!ctx.conn.will_expire());
        ctx.recv();
        assert_eq!(ctx.rx_pkt.hdr.op(), uapi::VSOCK_OP_REQUEST);
        // Since the request might time-out, the kill timer should now be armed.
        assert!(ctx.conn.will_expire());
        assert!(!ctx.conn.has_expired());
        ctx.init_tx_pkt(uapi::VSOCK_OP_RESPONSE, 0);
        ctx.send();
        // Upon receiving a connection response, the connection should have transitioned to the
        // established state, and the kill timer should've been disarmed.
        assert_eq!(ctx.conn.state, ConnState::Established);
        assert!(!ctx.conn.will_expire());
    }

    #[test]
    fn test_local_request_timeout() {
        let mut ctx = CsmTestContext::new(ConnState::LocalInit);
        ctx.recv();
        assert_eq!(ctx.rx_pkt.hdr.op(), uapi::VSOCK_OP_REQUEST);
        assert!(ctx.conn.will_expire());
        assert!(!ctx.conn.has_expired());
        std::thread::sleep(std::time::Duration::from_millis(
            defs::CONN_REQUEST_TIMEOUT_MS,
        ));
        assert!(ctx.conn.has_expired());
    }

    #[test]
    fn test_rx_data() {
        let mut ctx = CsmTestContext::new_established();
        let data = &[1, 2, 3, 4];
        ctx.set_stream(TestStream::new_with_read_buf(data));
        assert_eq!(ctx.conn.as_raw_fd(), ctx.conn.stream.as_raw_fd());
        ctx.notify_epollin();
        ctx.recv();
        assert_eq!(ctx.rx_pkt.hdr.op(), uapi::VSOCK_OP_RW);
        assert_eq!(ctx.rx_pkt.hdr.len() as usize, data.len());

        let buf = test_utils::read_packet_data(&ctx.tx_pkt, 4);
        assert_eq!(&buf, data);

        // There's no more data in the stream, so `recv_pkt` should yield `VsockError::NoData`.
        // match ctx.conn.recv_pkt(&mut ctx.tx_pkt) {
        match ctx.conn.recv_pkt(&mut ctx.rx_pkt) {
            Err(VsockError::NoData) => (),
            other => panic!("{:?}", other),
        }

        // A recv attempt in an invalid state should yield an instant reset packet.
        ctx.conn.state = ConnState::LocalClosed;
        ctx.notify_epollin();
        ctx.recv();
        assert_eq!(ctx.rx_pkt.hdr.op(), uapi::VSOCK_OP_RST);
    }

    #[test]
    fn test_local_close() {
        let mut ctx = CsmTestContext::new_established();
        let mut stream = TestStream::new();
        stream.read_state = StreamState::Closed;
        ctx.set_stream(stream);
        ctx.notify_epollin();
        ctx.recv();
        // When the host-side stream is closed, we can neither send not receive any more data.
        // Therefore, the vsock shutdown packet that we'll deliver to the guest must contain both
        // the no-more-send and the no-more-recv indications.
        assert_eq!(ctx.rx_pkt.hdr.op(), uapi::VSOCK_OP_SHUTDOWN);
        assert_ne!(ctx.rx_pkt.hdr.flags() & uapi::VSOCK_FLAGS_SHUTDOWN_SEND, 0);
        assert_ne!(ctx.rx_pkt.hdr.flags() & uapi::VSOCK_FLAGS_SHUTDOWN_RCV, 0);

        // The kill timer should now be armed.
        assert!(ctx.conn.will_expire());
        assert!(
            ctx.conn.expiry().unwrap()
                < Instant::now() + Duration::from_millis(defs::CONN_SHUTDOWN_TIMEOUT_MS)
        );
    }

    #[test]
    fn test_peer_close() {
        // Test that send/recv shutdown indications are handled correctly.
        // I.e. once set, an indication cannot be reset.
        {
            let mut ctx = CsmTestContext::new_established();

            let tx_pkt = ctx.init_tx_pkt(uapi::VSOCK_OP_SHUTDOWN, 0);
            tx_pkt.hdr.set_flags(uapi::VSOCK_FLAGS_SHUTDOWN_RCV);
            ctx.send();
            assert_eq!(ctx.conn.state, ConnState::PeerClosed(true, false));

            // Attempting to reset the no-more-recv indication should not work
            // (we are only setting the no-more-send indication here).
            ctx.tx_pkt.hdr.set_flags(uapi::VSOCK_FLAGS_SHUTDOWN_SEND);
            ctx.send();
            assert_eq!(ctx.conn.state, ConnState::PeerClosed(true, true));
        }

        // Test case:
        // - reading data from a no-more-send connection should work; and
        // - writing data should have no effect.
        {
            let data = &[1, 2, 3, 4];
            let mut ctx = CsmTestContext::new_established();
            ctx.set_stream(TestStream::new_with_read_buf(data));
            let tx_pkt = ctx.init_tx_pkt(uapi::VSOCK_OP_SHUTDOWN, 0);
            tx_pkt.hdr.set_flags(uapi::VSOCK_FLAGS_SHUTDOWN_SEND);
            ctx.send();
            ctx.notify_epollin();
            ctx.recv();
            assert_eq!(ctx.rx_pkt.hdr.op(), uapi::VSOCK_OP_RW);

            let buf = test_utils::read_packet_data(&ctx.tx_pkt, 4);
            assert_eq!(&buf, data);

            ctx.init_data_tx_pkt(data);
            ctx.send();
            assert_eq!(ctx.conn.stream.write_buf.len(), 0);
            assert!(ctx.conn.tx_buf.is_empty());
        }

        // Test case:
        // - writing data to a no-more-recv connection should work; and
        // - attempting to read data from it should yield an RST packet.
        {
            let mut ctx = CsmTestContext::new_established();
            let tx_pkt = ctx.init_tx_pkt(uapi::VSOCK_OP_SHUTDOWN, 0);
            tx_pkt.hdr.set_flags(uapi::VSOCK_FLAGS_SHUTDOWN_RCV);
            ctx.send();
            let data = &[1, 2, 3, 4];
            ctx.init_data_tx_pkt(data);
            ctx.send();
            assert_eq!(ctx.conn.stream.write_buf, data.to_vec());

            ctx.notify_epollin();
            ctx.recv();
            assert_eq!(ctx.rx_pkt.hdr.op(), uapi::VSOCK_OP_RST);
        }

        // Test case: setting both no-more-send and no-more-recv indications should have the
        // connection confirm termination (i.e. yield an RST).
        {
            let mut ctx = CsmTestContext::new_established();
            let tx_pkt = ctx.init_tx_pkt(uapi::VSOCK_OP_SHUTDOWN, 0);
            tx_pkt
                .hdr
                .set_flags(uapi::VSOCK_FLAGS_SHUTDOWN_RCV | uapi::VSOCK_FLAGS_SHUTDOWN_SEND);
            ctx.send();
            assert!(ctx.conn.has_pending_rx());
            ctx.recv();
            assert_eq!(ctx.rx_pkt.hdr.op(), uapi::VSOCK_OP_RST);
        }
    }

    #[test]
    fn test_local_read_error() {
        let mut ctx = CsmTestContext::new_established();
        let mut stream = TestStream::new();
        stream.read_state = StreamState::Error(ErrorKind::PermissionDenied);
        ctx.set_stream(stream);
        ctx.notify_epollin();
        ctx.recv();
        assert_eq!(ctx.rx_pkt.hdr.op(), uapi::VSOCK_OP_RST);
    }

    #[test]
    fn test_credit_request_to_peer() {
        let mut ctx = CsmTestContext::new_established();
        ctx.set_peer_credit(0);
        ctx.notify_epollin();
        ctx.recv();
        assert_eq!(ctx.rx_pkt.hdr.op(), uapi::VSOCK_OP_CREDIT_REQUEST);
    }

    #[test]
    fn test_credit_request_from_peer() {
        let mut ctx = CsmTestContext::new_established();
        ctx.init_tx_pkt(uapi::VSOCK_OP_CREDIT_REQUEST, 0);
        ctx.send();
        assert!(ctx.conn.has_pending_rx());
        ctx.recv();
        assert_eq!(ctx.rx_pkt.hdr.op(), uapi::VSOCK_OP_CREDIT_UPDATE);
        assert_eq!(ctx.rx_pkt.hdr.buf_alloc(), csm_defs::CONN_TX_BUF_SIZE);
        assert_eq!(ctx.rx_pkt.hdr.fwd_cnt(), ctx.conn.fwd_cnt.0);
    }

    #[test]
    fn test_credit_update_to_peer() {
        let mut ctx = CsmTestContext::new_established();

        // Force a stale state, where the peer hasn't been updated on our credit situation.
        ctx.conn.last_fwd_cnt_to_peer = Wrapping(0);

        // Since a credit update token is sent when the fwd_cnt value exceeds
        // CONN_TX_BUF_SIZE - CONN_CREDIT_UPDATE_THRESHOLD, we initialize
        // fwd_cnt at 6 bytes below the threshold.
        let initial_fwd_cnt =
            csm_defs::CONN_TX_BUF_SIZE - csm_defs::CONN_CREDIT_UPDATE_THRESHOLD - 6;
        ctx.conn.fwd_cnt = Wrapping(initial_fwd_cnt);

        // Use a 4-byte packet for triggering the credit update threshold.
        let data = &[1, 2, 3, 4];

        // Check that there is no pending RX.
        ctx.init_data_tx_pkt(data);
        ctx.send();
        assert!(!ctx.conn.has_pending_rx());

        // Send a packet again.
        ctx.init_data_tx_pkt(data);
        ctx.send();

        // The CSM should now have a credit update available for the peer.
        assert!(ctx.conn.has_pending_rx());
        ctx.recv();
        assert_eq!(ctx.rx_pkt.hdr.op(), uapi::VSOCK_OP_CREDIT_UPDATE);
        assert_eq!(
            ctx.rx_pkt.hdr.fwd_cnt() as usize,
            initial_fwd_cnt as usize + data.len() * 2,
        );
        assert_eq!(ctx.conn.fwd_cnt, ctx.conn.last_fwd_cnt_to_peer);
    }

    #[test]
    fn test_tx_buffering() {
        // Test case:
        // - when writing to the backing stream would block, TX data should end up in the TX buf
        // - when the CSM is notified that it can write to the backing stream, it should flush the
        //   TX buf.
        {
            let mut ctx = CsmTestContext::new_established();

            let mut stream = TestStream::new();
            stream.write_state = StreamState::WouldBlock;
            ctx.set_stream(stream);

            // Send some data through the connection. The backing stream is set to reject writes,
            // so the data should end up in the TX buffer.
            let data = &[1, 2, 3, 4];
            ctx.init_data_tx_pkt(data);
            ctx.send();

            // When there's data in the TX buffer, the connection should ask to be notified when it
            // can write to its backing stream.
            assert!(ctx.conn.get_polled_evset().contains(EventSet::OUT));
            assert_eq!(ctx.conn.tx_buf.len(), data.len());

            // Unlock the write stream and notify the connection it can now write its bufferred
            // data.
            ctx.set_stream(TestStream::new());
            ctx.conn.notify(EventSet::OUT);
            assert!(ctx.conn.tx_buf.is_empty());
            assert_eq!(ctx.conn.stream.write_buf, data);
        }
    }

    #[test]
    fn test_stream_write_error() {
        // Test case: sending a data packet to a broken / closed backing stream should kill it.
        {
            let mut ctx = CsmTestContext::new_established();
            let mut stream = TestStream::new();
            stream.write_state = StreamState::Closed;
            ctx.set_stream(stream);

            let data = &[1, 2, 3, 4];
            ctx.init_data_tx_pkt(data);
            ctx.send();

            assert_eq!(ctx.conn.state, ConnState::Killed);
            assert!(ctx.conn.has_pending_rx());
            ctx.recv();
            assert_eq!(ctx.rx_pkt.hdr.op(), uapi::VSOCK_OP_RST);
        }

        // Test case: notifying a connection that it can flush its TX buffer to a broken stream
        // should kill the connection.
        {
            let mut ctx = CsmTestContext::new_established();

            let mut stream = TestStream::new();
            stream.write_state = StreamState::WouldBlock;
            ctx.set_stream(stream);

            // Send some data through the connection. The backing stream is set to reject writes,
            // so the data should end up in the TX buffer.
            let data = &[1, 2, 3, 4];
            ctx.init_data_tx_pkt(data);
            ctx.send();

            // Set the backing stream to error out on write.
            let mut stream = TestStream::new();
            stream.write_state = StreamState::Closed;
            ctx.set_stream(stream);

            assert!(ctx.conn.get_polled_evset().contains(EventSet::OUT));
            ctx.notify_epollout();
            assert_eq!(ctx.conn.state, ConnState::Killed);
        }
    }

    // A real AF_UNIX SOCK_SEQPACKET socket pair used for seqpacket tests.
    // The local fd is the connection's read end; the remote fd is the test's write end.
    #[derive(Debug)]
    struct SeqpacketTestStream {
        local_fd: RawFd,
        remote_fd: RawFd,
    }

    impl SeqpacketTestStream {
        fn new() -> Self {
            let mut fds = [0i32; 2];
            // SAFETY: valid AF_UNIX socketpair call; fds is a valid 2-element array.
            let ret = unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK,
                    0,
                    fds.as_mut_ptr(),
                )
            };
            assert_eq!(ret, 0, "socketpair failed: {}", IoError::last_os_error());
            Self {
                local_fd: fds[0],
                remote_fd: fds[1],
            }
        }

        // Write one seqpacket message into the remote end.
        fn push_message(&self, data: &[u8]) {
            // SAFETY: `remote_fd` is valid; `data` is a valid slice for the duration of the call.
            let ret = unsafe {
                libc::write(
                    self.remote_fd,
                    data.as_ptr().cast::<libc::c_void>(),
                    data.len(),
                )
            };
            assert_eq!(ret.cast_unsigned(), data.len(), "push_message write failed");
        }
    }

    impl Drop for SeqpacketTestStream {
        fn drop(&mut self) {
            // SAFETY: Both fds are valid and owned by this struct; closing them on drop.
            unsafe {
                libc::close(self.local_fd);
                libc::close(self.remote_fd);
            }
        }
    }

    impl AsRawFd for SeqpacketTestStream {
        fn as_raw_fd(&self) -> RawFd {
            self.local_fd
        }
    }

    impl ReadVolatile for SeqpacketTestStream {
        fn read_volatile<B: BitmapSlice>(
            &mut self,
            buf: &mut VolatileSlice<B>,
        ) -> Result<usize, VolatileMemoryError> {
            let mut tmp = vec![0u8; buf.len()];
            // SAFETY: `local_fd` is valid; `tmp` is a valid writable buffer for the duration of
            // the call.
            let ret = unsafe {
                libc::recv(
                    self.local_fd,
                    tmp.as_mut_ptr().cast::<libc::c_void>(),
                    tmp.len(),
                    0,
                )
            };
            if ret < 0 {
                return Err(VolatileMemoryError::IOError(IoError::last_os_error()));
            }
            let n = ret.cast_unsigned();
            buf.copy_from(&tmp[..n]);
            Ok(n)
        }
    }

    impl Write for SeqpacketTestStream {
        fn write(&mut self, data: &[u8]) -> Result<usize, IoError> {
            // SAFETY: `local_fd` is valid; `data` is a valid readable slice for the duration of
            // the call.
            let ret = unsafe {
                libc::write(
                    self.local_fd,
                    data.as_ptr().cast::<libc::c_void>(),
                    data.len(),
                )
            };
            if ret < 0 {
                Err(IoError::last_os_error())
            } else {
                Ok(ret.cast_unsigned())
            }
        }

        fn flush(&mut self) -> Result<(), IoError> {
            Ok(())
        }
    }

    impl WriteVolatile for SeqpacketTestStream {
        fn write_volatile<B: BitmapSlice>(
            &mut self,
            buf: &VolatileSlice<B>,
        ) -> Result<usize, VolatileMemoryError> {
            let mut tmp = vec![0u8; buf.len()];
            buf.copy_to(&mut tmp);
            // SAFETY: `local_fd` is valid; `tmp` is a valid readable buffer for the duration of
            // the call.
            let ret = unsafe {
                libc::write(
                    self.local_fd,
                    tmp.as_ptr().cast::<libc::c_void>(),
                    tmp.len(),
                )
            };
            if ret < 0 {
                Err(VolatileMemoryError::IOError(IoError::last_os_error()))
            } else {
                Ok(ret.cast_unsigned())
            }
        }
    }

    impl VsockConnectionBackend for SeqpacketTestStream {}

    // EOM bit as defined in packet.rs
    const VIRTIO_VSOCK_SEQ_EOM: u32 = 1 << 0;

    // Creates an established seqpacket connection backed by `stream`.
    // `conn_buffer_size` sets the intermediate buffer used for large messages.
    // Returns (connection, rx_pkt); the caller must keep _ctx alive for the duration.
    fn make_established_seqpacket(
        stream: SeqpacketTestStream,
        conn_buffer_size: Option<usize>,
    ) -> (
        VsockConnection<SeqpacketTestStream>,
        VsockPacketRx,
        TestContext,
    ) {
        let vsock_test_ctx = TestContext::new();
        let mut handler_ctx = vsock_test_ctx.create_event_handler_context();
        let mut rx_pkt = VsockPacketRx::new().unwrap();
        rx_pkt
            .parse(
                &vsock_test_ctx.mem,
                handler_ctx.device.queues[RXQ_INDEX].pop().unwrap().unwrap(),
            )
            .unwrap();

        let mut conn = VsockConnection::<SeqpacketTestStream>::new_peer_init(
            stream,
            LOCAL_CID,
            PEER_CID,
            LOCAL_PORT,
            PEER_PORT,
            PEER_BUF_ALLOC,
            VsockType::Seqpacket,
            conn_buffer_size,
        );
        // Drain the initial RESPONSE to reach Established state.
        assert!(conn.has_pending_rx());
        conn.recv_pkt(&mut rx_pkt).unwrap();
        assert_eq!(rx_pkt.hdr.op(), uapi::VSOCK_OP_RESPONSE);
        assert_eq!(conn.state, ConnState::Established);

        (conn, rx_pkt, vsock_test_ctx)
    }

    // Seqpacket: a small message (fits in one RX descriptor) is delivered in a single recv_pkt
    // call with EOM set and should_retrigger=false.
    #[test]
    fn test_seqpacket_recv_small_message() {
        let stream = SeqpacketTestStream::new();
        stream.push_message(b"hello");
        let (mut conn, mut rx_pkt, _ctx) = make_established_seqpacket(stream, None);

        conn.notify(EventSet::IN);
        assert!(conn.has_pending_rx());

        let res = conn.recv_pkt(&mut rx_pkt).unwrap();

        assert_eq!(rx_pkt.hdr.op(), uapi::VSOCK_OP_RW);
        assert_eq!(rx_pkt.hdr.len(), 5);
        assert_eq!(res.bytes_read, 5);
        assert!(!res.should_retrigger);
        // EOM flag must be set: this is the end of the seqpacket message.
        assert_ne!(rx_pkt.hdr.flags() & VIRTIO_VSOCK_SEQ_EOM, 0);
        // No further pending RX after a complete small message.
        assert!(!conn.has_pending_rx());
    }

    // Seqpacket: a message larger than the RX descriptor buffer (4096 bytes) is split across
    // two recv_pkt calls. The first call sets should_retrigger=true and leaves EOM clear;
    // the second call delivers the remainder with EOM set.
    #[test]
    fn test_seqpacket_recv_large_message() {
        const BUF_SIZE: usize = 4096; // matches the test descriptor size
        const MSG_LEN: usize = BUF_SIZE + 512;

        let stream = SeqpacketTestStream::new();
        stream.push_message(&vec![0xABu8; MSG_LEN]);
        let (mut conn, mut rx_pkt, _ctx) = make_established_seqpacket(stream, None);

        conn.notify(EventSet::IN);
        assert!(conn.has_pending_rx());

        // First call: fills the descriptor (4096 bytes), does not set EOM.
        let res1 = conn.recv_pkt(&mut rx_pkt).unwrap();
        assert_eq!(rx_pkt.hdr.op(), uapi::VSOCK_OP_RW);
        assert_eq!(res1.bytes_read, u32::try_from(BUF_SIZE).unwrap());
        assert!(res1.should_retrigger);
        assert_eq!(rx_pkt.hdr.flags() & VIRTIO_VSOCK_SEQ_EOM, 0);
        // Connection must still have pending RX for the remainder.
        assert!(conn.has_pending_rx());

        // Second call: delivers the remaining 512 bytes with EOM set.
        let res2 = conn.recv_pkt(&mut rx_pkt).unwrap();
        assert_eq!(rx_pkt.hdr.op(), uapi::VSOCK_OP_RW);
        assert_eq!(res2.bytes_read, 512);
        assert!(!res2.should_retrigger);
        assert_ne!(rx_pkt.hdr.flags() & VIRTIO_VSOCK_SEQ_EOM, 0);
        assert!(!conn.has_pending_rx());
    }

    // Seqpacket: a message that exactly fills the RX descriptor is handled in one call,
    // as a "small" packet (not buffered), with EOM set.
    #[test]
    fn test_seqpacket_recv_exact_buf_size_message() {
        const BUF_SIZE: usize = 4096;

        let stream = SeqpacketTestStream::new();
        stream.push_message(&vec![0x42u8; BUF_SIZE]);
        let (mut conn, mut rx_pkt, _ctx) = make_established_seqpacket(stream, None);

        conn.notify(EventSet::IN);

        let res = conn.recv_pkt(&mut rx_pkt).unwrap();

        assert_eq!(rx_pkt.hdr.op(), uapi::VSOCK_OP_RW);
        assert_eq!(res.bytes_read, u32::try_from(BUF_SIZE).unwrap());
        assert!(!res.should_retrigger);
        assert_ne!(rx_pkt.hdr.flags() & VIRTIO_VSOCK_SEQ_EOM, 0);
        assert!(!conn.has_pending_rx());
    }

    // Seqpacket: a message too large to fit in the intermediate connection buffer returns
    // a MessageTooLong error and kills the connection (RST).
    #[test]
    fn test_seqpacket_recv_message_too_long() {
        // Use a tiny intermediate buffer so a message slightly larger than the RX descriptor
        // (4097 bytes > 4096 buf_size) exceeds it.
        const SMALL_BUF: usize = 128;
        const MSG_LEN: usize = 4097; // > buf_size (4096) so large-packet path is taken

        let stream = SeqpacketTestStream::new();
        stream.push_message(&vec![0u8; MSG_LEN]);
        let (mut conn, mut rx_pkt, _ctx) = make_established_seqpacket(stream, Some(SMALL_BUF));

        conn.notify(EventSet::IN);

        // recv_pkt should not propagate the error; instead it emits an RST packet.
        let res = conn.recv_pkt(&mut rx_pkt).unwrap();
        assert_eq!(rx_pkt.hdr.op(), uapi::VSOCK_OP_RST);
        assert_eq!(res.bytes_read, 0);
    }

    #[test]
    fn test_peer_credit_misbehavior() {
        let mut ctx = CsmTestContext::new_established();

        let mut stream = TestStream::new();
        stream.write_state = StreamState::WouldBlock;
        ctx.set_stream(stream);

        // Fill up the TX buffer.
        let data = vec![0u8; ctx.tx_pkt.buf_size() as usize];
        ctx.init_data_tx_pkt(data.as_slice());
        for _i in 0..(csm_defs::CONN_TX_BUF_SIZE as usize / data.len()) {
            ctx.send();
        }

        // Then try to send more data.
        ctx.send();

        // The connection should've committed suicide.
        assert_eq!(ctx.conn.state, ConnState::Killed);
        assert!(ctx.conn.has_pending_rx());
        ctx.recv();
        assert_eq!(ctx.rx_pkt.hdr.op(), uapi::VSOCK_OP_RST);
    }
}
