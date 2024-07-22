// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! This module contains a minimalist TCP [`Connection`] implementation, which only supports
//! passive open scenarios, and some auxiliary logic and data structures.
//!
//! [`Connection`]: struct.Connection.html

use std::fmt::Debug;
use std::num::{NonZeroU16, NonZeroU64, NonZeroUsize, Wrapping};

use bitflags::bitflags;
use utils::rand::xor_pseudo_rng_u32;

use crate::dumbo::pdu::bytes::NetworkBytes;
use crate::dumbo::pdu::tcp::{Flags as TcpFlags, TcpError as TcpSegmentError, TcpSegment};
use crate::dumbo::pdu::Incomplete;
use crate::dumbo::tcp::{
    seq_after, seq_at_or_after, NextSegmentStatus, RstConfig, MAX_WINDOW_SIZE, MSS_DEFAULT,
};
use crate::dumbo::ByteBuffer;

bitflags! {
    // We use a set of flags, instead of a state machine, to represent the connection status. Some
    // parts of the status information are reflected in other fields of the Connection struct, such
    // as Connection::fin_received.
    #[derive(Debug, Clone, PartialEq)]
    struct ConnStatusFlags: u8 {
        const SYN_RECEIVED =        1;
        const SYNACK_SENT =         1 << 1;
        const ESTABLISHED =         1 << 2;
        // We signal the end of the TX half by setting Connection.send_fin to Some(sequence_number),
        // and use this flag to record that at least one FIN segment has been sent.
        const FIN_SENT =            1 << 3;
        // The other endpoint has ACKed our FIN.
        const FIN_ACKED =           1 << 4;
        // The connection is reset, because we either sent, or received a RST segment.
        const RESET =               1 << 5;
    }
}

bitflags! {
    /// Represents any unusual conditions which may occur when receiving a TCP segment.
    #[derive(Debug, Clone, Copy, PartialEq)]
    pub struct RecvStatusFlags: u16 {
        /// The acknowledgement number is invalid.
        const INVALID_ACK =             1;
        /// The connection received a duplicate ACK.
        const DUP_ACK =                 1 << 1;
        /// The connection received a data segment which does not fall within the limits of the
        /// current receive window.
        const SEGMENT_BEYOND_RWND =     1 << 2;
        /// The connection received a data segment, but the sequence number does not match the
        /// next expected sequence number.
        const UNEXPECTED_SEQ =          1 << 3;
        /// The other endpoint advertised a receive window edge which has been moved to the left.
        const REMOTE_RWND_EDGE =        1 << 4;
        /// The other endpoint transmitted additional data after sending a `FIN`.
        const DATA_BEYOND_FIN =         1 << 5;
        /// The connection received a valid `RST` segment.
        const RESET_RECEIVED =          1 << 6;
        /// The connection received an invalid `RST` segment.
        const INVALID_RST =             1 << 7;
        /// The connection received an invalid segment for its current state.
        const INVALID_SEGMENT =         1 << 8;
        /// The connection is resetting, and will switch to being reset after getting the
        /// chance to transmit a `RST` segment.
        const CONN_RESETTING =          1 << 9;
        /// The connection received a `FIN` whose sequence number does not match the next
        /// expected sequence number.
        const INVALID_FIN =             1 << 10;
    }
}

/// Defines a segment payload source.
///
/// When not `None`, it contains a [`ByteBuffer`] which holds the actual data, and the sequence
/// number associated with the first byte from the buffer.
///
/// [`ByteBuffer`]: ../../trait.ByteBuffer.html
// R should have the trait bound R: ByteBuffer, but bounds are ignored on type aliases.
pub type PayloadSource<'a, R> = Option<(&'a R, Wrapping<u32>)>;

/// Describes errors which may occur during a passive open.
#[derive(Debug, PartialEq, Eq, thiserror::Error, displaydoc::Display)]
pub enum PassiveOpenError {
    /// The incoming segment is not a valid `SYN`.
    InvalidSyn,
    /// The `SYN` segment carries an invalid `MSS` option.
    MssOption,
}

/// Describes errors which may occur when an existing connection receives a TCP segment.
#[derive(Debug, PartialEq, Eq, thiserror::Error, displaydoc::Display)]
pub enum RecvError {
    /// The payload length is larger than the receive buffer size.
    BufferTooSmall,
    /// The connection cannot receive the segment because it has been previously reset.
    ConnectionReset,
}

/// Describes errors which may occur when a connection attempts to write a segment.
/// Needs `rustfmt::skip` to make multiline comments work
#[rustfmt::skip]
#[derive(Debug, PartialEq, Eq, thiserror::Error, displaydoc::Display)]
pub enum WriteNextError {
    /// The connection cannot write the segment because it has been previously reset.
    ConnectionReset,
    /// The write sends additional data after a `FIN` has been transmitted.
    DataAfterFin,
    /** The remaining MSS (which can be reduced by IP and/or TCP options) is not large enough to \
    write the segment. */
    MssRemaining,
    // The payload source specifies a buffer larger than [`MAX_WINDOW_SIZE`].
    //
    // [`MAX_WINDOW_SIZE`]: ../constant.MAX_WINDOW_SIZE.html
    /// The payload source is too large.
    PayloadBufTooLarge,
    /// The payload source does not contain the first sequence number that should be sent.
    PayloadMissingSeq,
    /// An error occurred during the actual write to the buffer: {0}
    TcpSegment(#[from] TcpSegmentError),
}

/// Contains the state information and implements the logic for a minimalist TCP connection.
///
/// One particular thing is that whenever the connection sends a `RST` segment, it will also stop
/// working itself. This is just a design decision for our envisioned use cases;
/// improvements/changes may happen in the future (this also goes for other aspects of the
/// current implementation).
///
/// A `Connection` object can only be created via passive open, and will not recognize/use any TCP
/// options except `MSS` during the handshake. The associated state machine is similar to how
/// TCP normally functions, but there are some differences:
///
/// * Since only passive opens are supported, a `Connection` can only be instantiated in response to
///   an incoming `SYN` segment. If the segment is valid, it will start directly in a state called
///   `SYN_RECEIVED`. The valid events at this point are receiving a retransmission of the previous
///   `SYN` (which does nothing), and getting the chance to write a `SYNACK`, which also moves the
///   connection to the `SYNACK_SENT` state. Any incoming segment which is not a copy of the
///   previous `SYN` will reset the connection.
/// * In the `SYNACK_SENT` state, the connection awaits an `ACK` for the `SYNACK`. A retransmission
///   of the original `SYN` moves the state back to `SYN_RECEIVED`. A valid `ACK` advances the state
///   to `ESTABLISHED`. Any unexpected/invalid segment resets the connection.
/// * While `ESTABLISHED`, the connection will only reset if it receives a `RST` or a `SYN`. Invalid
///   segments are simply ignored. `FIN` handling is simplifed: when [`close`] is invoked the
///   connection records the `FIN` sequence number, and starts setting the `FIN` flag (when
///   possible) on outgoing segments. A `FIN` from the other endpoint is only taken into
///   consideration if it has the next expected sequence number. When the connection has both sent
///   and received a `FIN`, it marks itself as being done. There's no equivalent for the `TIME_WAIT`
///   TCP state.
///
/// The current implementation does not do any kind of congestion control, expects segments to
/// arrive in order, triggers a retransmission after the first duplicate `ACK`, and relies on the
/// user to supply an opaque `u64` timestamp value when invoking send or receive functionality. The
/// timestamps must be non-decreasing, and are mainly used for retransmission timeouts.
///
/// See [mmds-design](https://github.com/firecracker-microvm/firecracker/blob/main/docs/mmds/mmds-design.md#dumbo)
/// for why we are able to make these simplifications. Specifically, we want to stress that no
/// traffic handled by dumbo ever leaves a microVM.
///
/// [`close`]: #method.close
#[derive(Debug, Clone)]
pub struct Connection {
    // The sequence number to ACK at the next opportunity. This is 1 + the highest received
    // in-order sequence number.
    ack_to_send: Wrapping<u32>,
    // The highest ACK we received from the other end of the connection.
    highest_ack_received: Wrapping<u32>,
    // The sequence number of the first byte which has NOT yet been sent to the other endpoint.
    first_not_sent: Wrapping<u32>,
    // The right edge of the local receive window. We shouldn't receive any data past this point.
    local_rwnd_edge: Wrapping<u32>,
    // The right edge of the remote receive window. We shouldn't send any data past this point.
    remote_rwnd_edge: Wrapping<u32>,
    // The last time we received an ACK which advanced the receive window. Only makes sense as
    // long as we seq_after(first_not_sent, highest_ack_received), and if we sent something that
    // takes up sequence number space.
    rto_start: u64,
    // How much time can pass after rto_start, without making progress in the ACK space, before a
    // retransmission is triggered.
    rto_period: u64,
    // How many retransmissions triggered before receiving a valid ACK from the other endpoint.
    rto_count: u16,
    // When rto_count reaches this value, the next retransmission will actually reset the
    // connection.
    rto_count_max: u16,
    // Set to the FIN sequence number received from the other endpoint.
    fin_received: Option<Wrapping<u32>>,
    // When set, it represents the sequence number of the FIN byte which closes our end of the
    // connection. No data may be sent past that point.
    send_fin: Option<Wrapping<u32>>,
    // If some, send a RST segment with the specified sequence and ACK numbers, and mark the
    // connection as reset afterwards. The second option determines whether we set the ACK flag
    // on the RST segment.
    send_rst: Option<RstConfig>,
    // The MSS used when sending data segments.
    mss: u16,
    // If true, send an ACK segment at the first opportunity. ACKs can piggyback data segments, so
    // we'll only send an empty ACK segment if we can't transmit any data.
    pending_ack: bool,
    // We've got a duplicate ACK, so we'll retransmit the highest ACKed sequence number at the
    // first opportunity. Unlike regular TCP, we retransmit after the first duplicate ACK.
    dup_ack: bool,
    status_flags: ConnStatusFlags,
}

fn parse_mss_option<T: NetworkBytes + Debug>(
    segment: &TcpSegment<T>,
) -> Result<u16, PassiveOpenError> {
    match segment.parse_mss_option_unchecked(segment.header_len().into()) {
        Ok(Some(value)) => Ok(value.get()),
        Ok(None) => Ok(MSS_DEFAULT),
        Err(_) => Err(PassiveOpenError::MssOption),
    }
}

fn is_valid_syn<T: NetworkBytes + Debug>(segment: &TcpSegment<T>) -> bool {
    segment.flags_after_ns() == TcpFlags::SYN && segment.payload_len() == 0
}

impl Connection {
    /// Attempts to create a new `Connection` in response to an incoming `SYN` segment.
    ///
    /// # Arguments
    ///
    /// * `segment` - The incoming `SYN`.
    /// * `local_rwnd_size` - Initial size of the local receive window.
    /// * `rto_period` - How long the connection waits before a retransmission timeout fires for the
    ///   first segment which has not been acknowledged yet. This uses an opaque time unit.
    /// * `rto_count_max` - How many consecutive timeout-based retransmission may occur before the
    ///   connection resets itself.
    pub fn passive_open<T: NetworkBytes + Debug>(
        segment: &TcpSegment<T>,
        local_rwnd_size: u32,
        rto_period: NonZeroU64,
        rto_count_max: NonZeroU16,
    ) -> Result<Self, PassiveOpenError> {
        // We don't accepting anything other than a SYN segment here.
        if !is_valid_syn(segment) {
            return Err(PassiveOpenError::InvalidSyn);
        }

        // TODO: If we ever implement window scaling, change the part that computes
        // remote_rwnd_edge below.

        // We only care about the MSS option for now.
        let mss = parse_mss_option(segment)?;

        // This is going to get sent on the SYNACK.
        let ack_to_send = Wrapping(segment.sequence_number()) + Wrapping(1);

        // Let's pick the initial sequence number.
        let isn = Wrapping(xor_pseudo_rng_u32());
        let first_not_sent = isn + Wrapping(1);
        let remote_rwnd_edge = first_not_sent + Wrapping(u32::from(segment.window_size()));

        Ok(Connection {
            ack_to_send,
            highest_ack_received: isn,
            // The ISN is sent over the SYNACK, and this is the next sequence number.
            first_not_sent,
            local_rwnd_edge: ack_to_send + Wrapping(local_rwnd_size),
            // We have no information about this yet. It will get updated as the connection reaches
            // the ESTABLISHED state.
            remote_rwnd_edge,
            rto_start: 0,
            rto_period: rto_period.get(),
            rto_count: 0,
            rto_count_max: rto_count_max.get(),
            fin_received: None,
            send_fin: None,
            send_rst: None,
            mss,
            pending_ack: false,
            dup_ack: false,
            status_flags: ConnStatusFlags::SYN_RECEIVED,
        })
    }

    fn flags_intersect(&self, flags: ConnStatusFlags) -> bool {
        self.status_flags.intersects(flags)
    }

    fn set_flags(&mut self, flags: ConnStatusFlags) {
        self.status_flags.insert(flags);
    }

    fn clear_flags(&mut self, flags: ConnStatusFlags) {
        self.status_flags.remove(flags);
    }

    fn syn_received(&self) -> bool {
        self.flags_intersect(ConnStatusFlags::SYN_RECEIVED)
    }

    fn synack_pending(&self) -> bool {
        self.syn_received() && !self.synack_sent()
    }

    fn synack_sent(&self) -> bool {
        self.flags_intersect(ConnStatusFlags::SYNACK_SENT)
    }

    fn is_reset(&self) -> bool {
        self.flags_intersect(ConnStatusFlags::RESET)
    }

    fn fin_sent(&self) -> bool {
        self.flags_intersect(ConnStatusFlags::FIN_SENT)
    }

    fn fin_acked(&self) -> bool {
        self.flags_intersect(ConnStatusFlags::FIN_ACKED)
    }

    fn is_same_syn<T: NetworkBytes + Debug>(&self, segment: &TcpSegment<T>) -> bool {
        // This only really makes sense before getting into ESTABLISHED, but that's fine
        // because we only use it before that point.
        if !is_valid_syn(segment) || self.ack_to_send.0 != segment.sequence_number().wrapping_add(1)
        {
            return false;
        }

        matches!(parse_mss_option(segment), Ok(mss) if mss == self.mss)
    }

    fn reset_for_segment<T: NetworkBytes + Debug>(&mut self, s: &TcpSegment<T>) {
        if !self.rst_pending() {
            self.send_rst = Some(RstConfig::new(s));
        }
    }

    fn rst_pending(&self) -> bool {
        self.send_rst.is_some()
    }

    fn rto_expired(&self, now: u64) -> bool {
        now - self.rto_start >= self.rto_period
    }

    // We send a FIN control segment if every data byte up to the self.send_fin sequence number
    // has been ACKed by the other endpoint, and no FIN has been previously sent.
    fn can_send_first_fin(&self) -> bool {
        !self.fin_sent()
            && matches!(self.send_fin, Some(fin_seq) if fin_seq == self.highest_ack_received)
    }

    // Returns the window size which should be written to an outgoing segment. This is going to be
    // even more useful when we'll support window scaling.
    fn local_rwnd(&self) -> u16 {
        let rwnd = (self.local_rwnd_edge - self.ack_to_send).0;

        u16::try_from(rwnd).unwrap_or(u16::MAX)
    }

    // Will actually become meaningful when/if we implement window scaling.
    fn remote_window_size(&self, window_size: u16) -> u32 {
        u32::from(window_size)
    }

    // Computes the remote rwnd edge given the ACK number and window size from an incoming segment.
    fn compute_remote_rwnd_edge(&self, ack: Wrapping<u32>, window_size: u16) -> Wrapping<u32> {
        ack + Wrapping(self.remote_window_size(window_size))
    }

    // Has this name just in case the pending_ack status will be more than just some boolean at
    // some point in the future.
    fn enqueue_ack(&mut self) {
        self.pending_ack = true;
    }

    /// Closes this half of the connection.
    ///
    /// Subsequent calls after the first one do not have any effect. The sequence number of the
    /// `FIN` is the first sequence number not yet sent at this point.
    #[inline]
    pub fn close(&mut self) {
        if self.send_fin.is_none() {
            self.send_fin = Some(self.first_not_sent);
        }
    }

    /// Returns a valid configuration for a `RST` segment, which can be sent to the other
    /// endpoint to signal the connection should be reset.
    #[inline]
    pub fn make_rst_config(&self) -> RstConfig {
        if self.is_established() {
            RstConfig::Seq(self.first_not_sent.0)
        } else {
            RstConfig::Ack(self.ack_to_send.0)
        }
    }

    /// Specifies that a `RST` segment should be sent to the other endpoint, and then the
    /// connection should be destroyed.
    #[inline]
    pub fn reset(&mut self) {
        if !self.rst_pending() {
            self.send_rst = Some(self.make_rst_config());
        }
    }

    /// Returns `true` if the connection is past the `ESTABLISHED` point.
    #[inline]
    pub fn is_established(&self) -> bool {
        self.flags_intersect(ConnStatusFlags::ESTABLISHED)
    }

    /// Returns `true` if a `FIN` has been received.
    #[inline]
    pub fn fin_received(&self) -> bool {
        self.fin_received.is_some()
    }

    // TODO: The description of this method is also a TODO in disguise.
    /// Returns `true` if the connection is done communicating with the other endpoint.
    ///
    /// Maybe it would be a good idea to return true only after our FIN has also been ACKed?
    /// Otherwise, when using the TCP handler there's pretty much always going to be an ACK for the
    /// FIN that's going to trigger a gratuitous RST (best case), or can even be considered valid if
    /// a new connection is created meanwhile using the same tuple and we get very unlucky (worst
    /// case, extremely unlikely though).
    #[inline]
    pub fn is_done(&self) -> bool {
        self.is_reset() || (self.fin_received() && self.flags_intersect(ConnStatusFlags::FIN_SENT))
    }

    /// Returns the first sequence number which has not been sent yet for the current window.
    #[inline]
    pub fn first_not_sent(&self) -> Wrapping<u32> {
        self.first_not_sent
    }

    /// Returns the highest acknowledgement number received for the current window.
    #[inline]
    pub fn highest_ack_received(&self) -> Wrapping<u32> {
        self.highest_ack_received
    }

    /// Advances the right edge of the local receive window.
    ///
    /// This is effectively allowing the other endpoint to send more data, because no byte can be
    /// sent unless its sequence number falls into the receive window.
    // TODO: return the actual advance value here
    #[inline]
    pub fn advance_local_rwnd_edge(&mut self, value: u32) {
        let v = Wrapping(value);
        let max_w = Wrapping(MAX_WINDOW_SIZE);
        let current_w = self.local_rwnd_edge - self.ack_to_send;

        // Enqueue an ACK if we have to let the other endpoint know the window is opening.
        if current_w.0 == 0 {
            self.enqueue_ack();
        }

        if v + current_w > max_w {
            self.local_rwnd_edge = self.ack_to_send + max_w;
        } else {
            self.local_rwnd_edge += v;
        }
    }

    /// Returns the right edge of the receive window advertised by the other endpoint.
    #[inline]
    pub fn remote_rwnd_edge(&self) -> Wrapping<u32> {
        self.remote_rwnd_edge
    }

    /// Returns `true` if a retransmission caused by the reception of a duplicate `ACK` is pending.
    #[inline]
    pub fn dup_ack_pending(&self) -> bool {
        self.dup_ack
    }

    /// Describes whether a control segment can be sent immediately, a retransmission is pending,
    /// or there's nothing to transmit until more segments are received.
    ///
    /// This function does not tell whether any data segments can/will be sent, because the
    /// Connection itself does not control the send buffer. Thus the information returned here
    /// only pertains to control segments and timeout expiry. Data segment related status will
    /// be reported by higher level components, which also manage the contents of the send buffer.
    #[inline]
    pub fn control_segment_or_timeout_status(&self) -> NextSegmentStatus {
        if self.synack_pending()
            || self.rst_pending()
            || self.can_send_first_fin()
            || self.pending_ack
        {
            NextSegmentStatus::Available
        } else if self.highest_ack_received != self.first_not_sent {
            NextSegmentStatus::Timeout(self.rto_start + self.rto_period)
        } else {
            NextSegmentStatus::Nothing
        }
    }

    // We use this helper method to set up self.send_rst and prepare a return value in one go. It's
    // only used by the receive_segment() method.
    fn reset_for_segment_helper<T: NetworkBytes + Debug>(
        &mut self,
        s: &TcpSegment<T>,
        flags: RecvStatusFlags,
    ) -> Result<(Option<NonZeroUsize>, RecvStatusFlags), RecvError> {
        self.reset_for_segment(s);
        Ok((None, RecvStatusFlags::CONN_RESETTING | flags))
    }

    /// Handles an incoming segment.
    ///
    /// When no errors occur, returns a pair consisting of how many
    /// bytes (if any) were received, and whether any unusual conditions arose while processing the
    /// segment. Since a `Connection` does not have its own internal buffer, `buf` is required to
    /// store any data carried by incoming segments.
    ///
    /// # Arguments
    ///
    /// * `s` - The incoming segment.
    /// * `buf` - The receive buffer where payload data (if any) from `s` is going to be written.
    /// * `now` - An opaque timestamp representing the current moment in time.
    pub fn receive_segment<T: NetworkBytes + Debug>(
        &mut self,
        s: &TcpSegment<T>,
        buf: &mut [u8],
        now: u64,
    ) -> Result<(Option<NonZeroUsize>, RecvStatusFlags), RecvError> {
        if self.rst_pending() || self.is_reset() {
            return Err(RecvError::ConnectionReset);
        }

        // TODO: The following logic fully makes sense only for a passive open (which is what we
        // currently support). Things must change a bit if/when we also implement active opens.

        let segment_flags = s.flags_after_ns();

        if segment_flags.intersects(TcpFlags::RST) {
            let seq = Wrapping(s.sequence_number());
            // We accept the RST only if it carries an in-window sequence number.
            // TODO: If/when we support active opens, we'll also have to accept RST/SYN segments,
            // which must acknowledge our SYN to be valid.
            if seq_at_or_after(seq, self.ack_to_send) && seq_after(self.local_rwnd_edge, seq) {
                self.set_flags(ConnStatusFlags::RESET);
                return Ok((None, RecvStatusFlags::RESET_RECEIVED));
            } else {
                return Ok((None, RecvStatusFlags::INVALID_RST));
            }
        }

        let payload_len = s.len() - u16::from(s.header_len());
        let mut recv_status_flags = RecvStatusFlags::empty();

        if !self.synack_sent() {
            // We received another segment before getting the chance to send a SYNACK. It's either
            // a retransmitted SYN, or something that does not make sense.
            if self.is_same_syn(s) {
                return Ok((None, recv_status_flags));
            } else {
                return self.reset_for_segment_helper(s, RecvStatusFlags::INVALID_SEGMENT);
            }
        } else if !self.is_established() {
            // So at this point we've sent at least one SYNACK, but the connection is not
            // ESTABLISHED yet. We only accept SYN retransmissions and ACKs. I'm not sure that
            // it's completely forbidden to sent an ACK + data in response to a SYNACK, so we don't
            // complain about non-pure ACKs (or even data + ACK + FIN segments).
            if self.is_same_syn(s) {
                // Maybe our previous SYNACK got lost or smt, so clear SYN_ACK_SENT to resend it.
                self.clear_flags(ConnStatusFlags::SYNACK_SENT);
                return Ok((None, recv_status_flags));
            } else if segment_flags.intersects(TcpFlags::SYN) {
                // So we basically freak out over SYN segments which are not valid SYN
                // retransmission.
                return self.reset_for_segment_helper(s, RecvStatusFlags::INVALID_SEGMENT);
            }
        } else {
            // Reaching this branch means the connection is ESTABLISHED. The only thing we want to
            // do right now is reset if we get segments which carry the SYN flag, because they are
            // obviously invalid, and something must be really wrong.
            // TODO: Is it an overreaction to reset here?
            if s.flags_after_ns().intersects(TcpFlags::SYN) {
                return self.reset_for_segment_helper(s, RecvStatusFlags::INVALID_SEGMENT);
            }
        }

        // The ACK number can only be valid when ACK flag is set. The following logic applies to
        // pretty much all connection states which can reach this point.
        if segment_flags.intersects(TcpFlags::ACK) {
            let ack = Wrapping(s.ack_number());

            if seq_at_or_after(ack, self.highest_ack_received)
                && seq_at_or_after(self.first_not_sent, ack)
            {
                // This is a valid ACK. Reset rto_count, since this means the other side is still
                // alive and kicking (or ACking).
                self.rto_count = 0;

                if ack == self.highest_ack_received && ack != self.first_not_sent {
                    if !self.is_established() {
                        // Just kidding, a DUPACK is not valid before the connection is ESTABLISHED.
                        return self.reset_for_segment_helper(s, RecvStatusFlags::INVALID_ACK);
                    }
                    // Duplicate ACKs can only increase in sequence number, so there's no need
                    // to check if this one is older than self.dup_ack.
                    self.dup_ack = true;
                    recv_status_flags |= RecvStatusFlags::DUP_ACK;
                } else {
                    // We're making progress. We should also reset rto_start in this case.
                    self.highest_ack_received = ack;
                    self.rto_start = now;
                    if !self.is_established() && self.synack_sent() {
                        // The connection becomes ESTABLISHED.
                        self.set_flags(ConnStatusFlags::ESTABLISHED);
                    }

                    if self.fin_sent() && ack == self.first_not_sent {
                        self.set_flags(ConnStatusFlags::FIN_ACKED);
                    }
                }

                // Look for remote remote rwnd updates.
                if self.is_established() {
                    let edge = self.compute_remote_rwnd_edge(ack, s.window_size());
                    if seq_after(edge, self.remote_rwnd_edge) {
                        self.remote_rwnd_edge = edge;
                    } else if edge != self.remote_rwnd_edge {
                        // The right edge of the remote receive window has been moved to the left,
                        // or has been set to an invalid value. Both cases represent erroneous TCP
                        // behaviour.
                        recv_status_flags |= RecvStatusFlags::REMOTE_RWND_EDGE;
                    }
                }
            } else {
                recv_status_flags |= RecvStatusFlags::INVALID_ACK;
                if !self.is_established() {
                    // Reset the connection if we receive an invalid ACK before reaching the
                    // ESTABLISHED state.
                    return self.reset_for_segment_helper(s, recv_status_flags);
                }
            }
        }

        // We start looking at the payload and/or FIN next. This makes sense only if the
        // connection is established.
        if !self.is_established() {
            return Ok((None, recv_status_flags));
        }

        let seq = Wrapping(s.sequence_number());
        let wrapping_payload_len = Wrapping(u32::from(payload_len));

        if usize::from(payload_len) > buf.len() {
            return Err(RecvError::BufferTooSmall);
        }

        let mut enqueue_ack = if payload_len > 0 {
            let data_end_seq = seq + wrapping_payload_len;

            if let Some(fin_seq) = self.fin_received {
                if !seq_at_or_after(fin_seq, data_end_seq) {
                    // TODO: This is a strange situation, because the other endpoint is sending data
                    // after it initially closed its half of the connection. We simply ignore the
                    // segment for now.
                    return Ok((None, recv_status_flags | RecvStatusFlags::DATA_BEYOND_FIN));
                }
            }

            if !seq_at_or_after(self.local_rwnd_edge, data_end_seq) {
                // TODO: This is another strange (and potentially dangerous) situation, because
                // either we or the other endpoint broke receive window semantics. We simply ignore
                // the segment for now.
                return Ok((
                    None,
                    recv_status_flags | RecvStatusFlags::SEGMENT_BEYOND_RWND,
                ));
            }

            // We currently assume segments are seldom lost or reordered, and only accept those with
            // the exact next sequence number we're waiting for.
            if seq != self.ack_to_send {
                // TODO: Maybe we should enqueue multiple ACKs here (after making such a thing
                // possible in the first place), just so we're more likely to trigger a
                // retransmission.
                self.enqueue_ack();
                return Ok((None, recv_status_flags | RecvStatusFlags::UNEXPECTED_SEQ));
            }

            self.ack_to_send = data_end_seq;
            true
        } else {
            false
        };

        // We assume the sequence number of the FIN does not change via conflicting FIN carrying
        // segments (as it should be the case during TCP normal operation). It the other endpoint
        // breaks this convention, it will have to deal with potentially hanging (until timing out)
        // connections and/or RST segments.
        if segment_flags.intersects(TcpFlags::FIN) && !self.fin_received() {
            let fin_seq = seq + wrapping_payload_len;

            // In order to avoid some complexity on our side, we only accept an incoming FIN if its
            // sequence number matches that of the first byte yet to be received (this is similar to
            // what we do for data segments right now).
            if fin_seq == self.ack_to_send {
                self.fin_received = Some(fin_seq);
                // Increase this to also ACK the FIN.
                self.ack_to_send += Wrapping(1);
                enqueue_ack = true;
            } else {
                recv_status_flags |= RecvStatusFlags::INVALID_FIN;
            }
        }

        if enqueue_ack {
            self.enqueue_ack();

            // We check this here because if a valid payload has been received, then we must have
            // set enqueue_ack = true earlier.
            if let Some(payload_len) = NonZeroUsize::new(payload_len.into()) {
                buf[..payload_len.into()].copy_from_slice(s.payload());
                return Ok((Some(payload_len), recv_status_flags));
            }
        }

        Ok((None, recv_status_flags))
    }

    // The write helper functions return incomplete segments because &self does not have information
    // regarding the identity of the endpoints, such as source and destination ports, or source and
    // destination L3 addresses (which are required for checksum computation). We need this stupid
    // ?Sized trait bound, because otherwise Sized would be implied, and we can have unsized types
    // which implement ByteBuffer (such as [u8]), since payload expects a reference to some R.
    fn write_segment<'a, R: ByteBuffer + ?Sized + Debug>(
        &mut self,
        buf: &'a mut [u8],
        mss_reserved: u16,
        seq: Wrapping<u32>,
        ack: Wrapping<u32>,
        flags_after_ns: TcpFlags,
        payload: Option<(&R, usize)>,
    ) -> Result<Incomplete<TcpSegment<'a, &'a mut [u8]>>, WriteNextError> {
        // Write the MSS option on SYNACK segments.
        let mss_option = if flags_after_ns == TcpFlags::SYN | TcpFlags::ACK {
            Some(self.mss)
        } else {
            None
        };

        let segment = TcpSegment::write_incomplete_segment(
            buf,
            seq.0,
            ack.0,
            flags_after_ns,
            self.local_rwnd(),
            mss_option,
            self.mss
                .checked_sub(mss_reserved)
                .ok_or(WriteNextError::MssRemaining)?,
            payload,
        )?;

        if flags_after_ns.intersects(TcpFlags::ACK) {
            self.pending_ack = false;
        }

        Ok(segment)
    }

    // Control segments are segments with no payload (at least I like to use this name).
    fn write_control_segment<'a, R: ByteBuffer + ?Sized + Debug>(
        &mut self,
        buf: &'a mut [u8],
        mss_reserved: u16,
    ) -> Result<Incomplete<TcpSegment<'a, &'a mut [u8]>>, WriteNextError> {
        let mut seq = self.highest_ack_received;
        let mut ack = self.ack_to_send;
        let mut flags_after_ns = TcpFlags::empty();

        if let Some(cfg) = self.send_rst {
            let t = cfg.seq_ack_tcp_flags();
            seq = Wrapping(t.0);
            ack = Wrapping(t.1);
            flags_after_ns = t.2;
        } else if !self.is_established() {
            // We can only send SYNACKs on this branch. The ISN should be right before
            // self.first_not_sent.
            flags_after_ns |= TcpFlags::SYN | TcpFlags::ACK;
            seq = self.first_not_sent - Wrapping(1);
        } else {
            // If we got to this point, the connection is ESTABLISHED, and we're not sending a RST.
            // We always want to enable the ACK flag.
            flags_after_ns = TcpFlags::ACK;

            if let Some(fin_seq) = self.send_fin {
                // When all outgoing data segments have been acked, we place the FIN flag and the
                // appropriate sequence number on outgoing control segments, unless we received an
                // ACK for the FIN.
                if !self.fin_acked() && seq_at_or_after(seq, fin_seq) {
                    flags_after_ns |= TcpFlags::FIN;
                    seq = fin_seq;
                }
            }
        }

        self.write_segment::<R>(buf, mss_reserved, seq, ack, flags_after_ns, None)
    }

    /// Writes a new segment (if available) to the specified buffer.
    ///
    /// The `payload_src` argument is required because the `Connection` does not have an internal
    /// send buffer. If the payload source is present, the data referenced therein must not amount
    /// to more than [`MAX_WINDOW_SIZE`].
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer where the segment is written.
    /// * `mss_reserved` - How much (if anything) of the MSS value has been already used at the
    ///   lower layers (by IP options, for example). This will be zero most of the time.
    /// * `payload_src` - References a buffer which contains data to send, and also specifies the
    ///   sequence number associated with the first byte from that that buffer.
    /// * `now` - An opaque timestamp representing the current moment in time.
    ///
    /// [`MAX_WINDOW_SIZE`]: ../constant.MAX_WINDOW_SIZE.html
    pub fn write_next_segment<'a, R: ByteBuffer + ?Sized + Debug>(
        &mut self,
        buf: &'a mut [u8],
        mss_reserved: u16,
        payload_src: PayloadSource<R>,
        now: u64,
    ) -> Result<Option<Incomplete<TcpSegment<'a, &'a mut [u8]>>>, WriteNextError> {
        // TODO: like receive_segment(), this function is specific in some ways to Connections
        // created via passive open. When/if we also implement active opens, some things will
        // have to change.

        if self.is_reset() {
            return Err(WriteNextError::ConnectionReset);
        }

        if self.send_rst.is_some() {
            // A RST is pending. Try to write it, and change the state of the connection to reset
            // if successfull.
            let segment = self.write_control_segment::<R>(buf, mss_reserved)?;
            self.set_flags(ConnStatusFlags::RESET);
            return Ok(Some(segment));
        }

        // The first thing we have to do is reply with a SYNACK if needed.
        if self.synack_pending() {
            let segment = self.write_control_segment::<R>(buf, mss_reserved)?;
            self.set_flags(ConnStatusFlags::SYNACK_SENT);
            self.rto_start = now;
            return Ok(Some(segment));
        }

        // Resend a SYNACK if the RTO expired. Otherwise, no reason to continue until the connection
        // becomes ESTABLISHED.
        if !self.is_established() {
            if self.rto_expired(now) {
                // If we exceeded the maximum retransmission count, reset the connection and call
                // write_next_segment one more time to generate the RST.
                self.rto_count += 1;
                if self.rto_count >= self.rto_count_max {
                    self.reset();
                    return self.write_next_segment(buf, mss_reserved, payload_src, now);
                }
                let segment = self.write_control_segment::<R>(buf, mss_reserved)?;
                self.rto_start = now;
                return Ok(Some(segment));
            }
            return Ok(None);
        }

        // First, try sending a data segment, because we can piggy back ACKs and FINs on top of it.
        if let Some((read_buf, payload_seq)) = payload_src {
            // Limit the size of read_buf so it doesn't mess up later calculations (as usual, I take
            // the easy way out).
            let len = match u32::try_from(read_buf.len()) {
                Ok(len) if len <= MAX_WINDOW_SIZE => len,
                _ => return Err(WriteNextError::PayloadBufTooLarge),
            };

            let payload_end = payload_seq + Wrapping(len);

            let mut rto_triggered = false;

            // Decide what sequence number to send next. Check out if a timeout expired first.
            let seq_to_send =
                if self.highest_ack_received != self.first_not_sent && self.rto_expired(now) {
                    self.rto_count += 1;
                    if self.rto_count >= self.rto_count_max {
                        self.reset();
                        return self.write_next_segment(buf, mss_reserved, payload_src, now);
                    }

                    if let Some(fin_seq) = self.send_fin {
                        if self.highest_ack_received == fin_seq {
                            // We're in the relatively unlikely situation where our FIN got lost.
                            // Simply calling write_control_segment() will retransmit it.
                            let segment = self.write_control_segment::<R>(buf, mss_reserved)?;
                            self.rto_start = now;
                            return Ok(Some(segment));
                        }
                    }

                    // We have to remember this is a retransmission for later.
                    rto_triggered = true;
                    self.highest_ack_received
                } else if self.dup_ack {
                    // We retransmit an older segment if a DUPACK is recorded. We'll clear
                    // self.dup_ack after we make sure the segment has been successfully written.
                    self.highest_ack_received
                } else {
                    // Otherwise, we send some data (if possible) starting with the first byte not
                    // yet sent.
                    self.first_not_sent
                };

            // The payload buffer begins after the first sequence number we are trying to send
            // (or the payload_seq is totally off).
            if !seq_at_or_after(seq_to_send, payload_seq) {
                return Err(WriteNextError::PayloadMissingSeq);
            }

            // We can only send data if it's within both the send buffer and the remote rwnd, and
            // before the sequence number of the local FIN (if the connection is closing).
            let actual_end = if seq_at_or_after(self.remote_rwnd_edge, payload_end) {
                payload_end
            } else {
                self.remote_rwnd_edge
            };

            // Make sure we're not trying to send data past the FIN sequence we previously
            // announced.
            if let Some(fin_seq) = self.send_fin {
                if seq_after(actual_end, fin_seq) {
                    return Err(WriteNextError::DataAfterFin);
                }
            }

            // We only proceed with writing a data segment if the previously computed bounds
            // delimit a valid sequence number interval.
            if seq_after(actual_end, seq_to_send) {
                let max_payload_len = (actual_end - seq_to_send).0 as usize;

                // We always set the ACK flag for data segments.
                let tcp_flags = TcpFlags::ACK;

                let ack_to_send = self.ack_to_send;
                let mut segment = self.write_segment(
                    buf,
                    mss_reserved,
                    seq_to_send,
                    ack_to_send,
                    tcp_flags,
                    Some((read_buf, max_payload_len)),
                )?;

                // If self.dup_ack was Some(_), we've just written the retransmission segment,
                // either directly or via the RTO timer expiring.
                self.dup_ack = false;

                let payload_len = segment.inner().payload_len();
                let mut first_seq_after = seq_to_send + Wrapping(u32::from(payload_len));

                if let Some(fin_seq) = self.send_fin {
                    if first_seq_after == fin_seq {
                        // This segment contains the last bytes of data we're going to send, so
                        // we should also set the FIN flag.
                        segment
                            .inner_mut()
                            .set_flags_after_ns(tcp_flags | TcpFlags::FIN);

                        // The FIN takes up 1 sequence number.
                        first_seq_after += Wrapping(1);
                        // The main purpose of knowing we sent at least one FIN is to signal that
                        // we already added 1 to self.first_not_sent, to account for its sequence
                        // number.
                        self.set_flags(ConnStatusFlags::FIN_SENT);
                    }
                }

                if rto_triggered || self.first_not_sent == self.highest_ack_received {
                    // Reset the RTO "timer" after each retransmission, or after sending the first
                    // unacknowledged segment in the current window.
                    self.rto_start = now;
                }

                if seq_after(first_seq_after, self.first_not_sent) {
                    self.first_not_sent = first_seq_after;
                }

                return Ok(Some(segment));
            }
        }

        // At this point, we only send a control segment if there's a pending ACK, or we didn't send
        // a FIN segment before and we would be sending the first one.

        // The FIN flag will be automatically added to the segment when necessary by the
        // write_control_segment() method.
        let send_first_fin = self.can_send_first_fin();
        if self.pending_ack || send_first_fin {
            let segment = self.write_control_segment::<R>(buf, mss_reserved)?;

            if send_first_fin {
                self.first_not_sent += Wrapping(1);
                self.set_flags(ConnStatusFlags::FIN_SENT);
            }

            return Ok(Some(segment));
        }

        Ok(None)
    }
}

// TODO: I'll be honest: the tests here cover the situations most likely to be encountered, but are
// not even close to being exhaustive. Something like that might be worth pursuing after polishing
// the rougher edges around the current implementation, and deciding its scope relative to an
// actual TCP implementation.
#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // A segment without options or a payload is 20 bytes long.
    const BASIC_SEGMENT_SIZE: usize = 20;

    #[derive(Debug)]
    pub struct ConnectionTester {
        buf: [u8; 2000],
        src_port: u16,
        dst_port: u16,
        remote_window_size: u16,
        pub mss: u16,
        pub mss_reserved: u16,
        local_rwnd_size: u32,
        remote_isn: u32,
        pub rto_period: u64,
        rto_count_max: u16,
        now: u64,
    }

    impl ConnectionTester {
        pub fn new() -> Self {
            ConnectionTester {
                buf: [0u8; 2000],
                src_port: 1000,
                dst_port: 80,
                remote_window_size: 11000,
                mss: 1100,
                mss_reserved: 0,
                local_rwnd_size: 10000,
                remote_isn: 12_345_678,
                rto_period: 100_000,
                rto_count_max: 3,
                now: 0,
            }
        }

        fn passive_open<T: NetworkBytes + Debug>(
            &self,
            s: &TcpSegment<T>,
        ) -> Result<Connection, PassiveOpenError> {
            Connection::passive_open(
                s,
                self.local_rwnd_size,
                NonZeroU64::new(self.rto_period).unwrap(),
                NonZeroU16::new(self.rto_count_max).unwrap(),
            )
        }

        // This helps write segments; it uses a lot of default values, and sets the ACK and SEQ
        // numbers to 0, and self.remote_isn respectively.
        fn write_segment_helper<'a>(
            &self,
            buf: &'a mut [u8],
            add_mss_option: bool,
            payload: Option<(&[u8], usize)>,
        ) -> TcpSegment<'a, &'a mut [u8]> {
            let mss_option = if add_mss_option { Some(self.mss) } else { None };
            TcpSegment::write_segment(
                buf,
                self.src_port,
                self.dst_port,
                self.remote_isn,
                0,
                TcpFlags::empty(),
                self.remote_window_size,
                mss_option,
                self.mss.checked_sub(self.mss_reserved).unwrap(),
                payload,
                None,
            )
            .unwrap()
        }

        pub fn write_syn<'a>(&self, buf: &'a mut [u8]) -> TcpSegment<'a, &'a mut [u8]> {
            self.write_segment_helper(buf, true, None)
        }

        pub fn write_ctrl<'a>(&self, buf: &'a mut [u8]) -> TcpSegment<'a, &'a mut [u8]> {
            self.write_segment_helper(buf, false, None)
        }

        pub fn write_data<'a>(
            &self,
            buf: &'a mut [u8],
            data_buf: &[u8],
        ) -> TcpSegment<'a, &'a mut [u8]> {
            let segment = self.write_segment_helper(buf, false, Some((data_buf, data_buf.len())));
            assert_eq!(usize::from(segment.payload_len()), data_buf.len());
            segment
        }

        fn receive_segment<T: NetworkBytes + Debug>(
            &mut self,
            c: &mut Connection,
            s: &TcpSegment<T>,
        ) -> Result<(Option<NonZeroUsize>, RecvStatusFlags), RecvError> {
            c.receive_segment(s, self.buf.as_mut(), self.now)
        }

        fn write_next_segment(
            &mut self,
            c: &mut Connection,
            payload_src: Option<(&[u8], Wrapping<u32>)>,
        ) -> Result<Option<TcpSegment<&mut [u8]>>, WriteNextError> {
            let src_port = self.src_port;
            let dst_port = self.dst_port;
            c.write_next_segment(self.buf.as_mut(), self.mss_reserved, payload_src, self.now)
                .map(|o| o.map(|incomplete| incomplete.finalize(src_port, dst_port, None)))
        }

        // Checks if the specified connection will reset after receiving the provided segment, and
        // that the receive_segment() method also returns the specified RecvStatusFlags. We
        // also make sure the outgoing RST segment has additional_segment_flags set besides
        // TcpFlags::RST.
        fn should_reset_after<T: NetworkBytes + Debug>(
            &mut self,
            c: &mut Connection,
            s: &TcpSegment<T>,
            recv_flags: RecvStatusFlags,
            additional_segment_flags: TcpFlags,
        ) {
            assert_eq!(self.receive_segment(c, s).unwrap(), (None, recv_flags));

            // We add a payload also, to see that sending a RST has precedence over everything.
            let send_buf = [0u8; 2000];
            let payload_src = Some((send_buf.as_ref(), c.highest_ack_received));

            if !recv_flags.intersects(RecvStatusFlags::RESET_RECEIVED) {
                // If the connection initiated the reset, the next segment to write should be a RST.
                // The first unwrap is for the Result, and the second for the Option.
                check_control_segment(
                    &self.write_next_segment(c, payload_src).unwrap().unwrap(),
                    0,
                    additional_segment_flags | TcpFlags::RST,
                );
            }

            // Calling write_next_segment again should result in a ConnectionReset error.
            assert_eq!(
                self.write_next_segment(c, payload_src).unwrap_err(),
                WriteNextError::ConnectionReset
            );

            // Receive should also no longer work.
            assert_eq!(
                self.receive_segment(c, s).unwrap_err(),
                RecvError::ConnectionReset
            );

            assert!(c.is_done());
        }

        // Checks that the next segment sent by c is a SYNACK.
        fn check_synack_is_next(&mut self, c: &mut Connection) {
            let send_buf = [0u8; 2000];
            let payload_src = Some((send_buf.as_ref(), c.highest_ack_received));
            let remote_isn = self.remote_isn;
            let conn_isn = c.first_not_sent.0.wrapping_sub(1);
            let mss = self.mss;

            let s = self.write_next_segment(c, payload_src).unwrap().unwrap();
            // The MSS option is 4 bytes long.
            check_control_segment(&s, 4, TcpFlags::SYN | TcpFlags::ACK);

            assert_eq!(s.sequence_number(), conn_isn);
            assert_eq!(s.ack_number(), remote_isn.wrapping_add(1));

            // Our implementation mirrors the received value of the MSS option.
            assert_eq!(parse_mss_option(&s).unwrap(), mss);

            check_synack_sent(c);
        }
    }

    // Verifies whether we are dealing with a control segment with the specified flags.
    fn check_control_segment<T: NetworkBytes + Debug>(
        s: &TcpSegment<T>,
        options_len: usize,
        flags_after_ns: TcpFlags,
    ) {
        assert_eq!(usize::from(s.len()), BASIC_SEGMENT_SIZE + options_len);
        assert_eq!(s.flags_after_ns(), flags_after_ns);
    }

    // Checks if the segment ACKs the specified sequence number, and whether the additional_flags
    // are set (besides ACK).
    fn check_acks<T: NetworkBytes + Debug>(
        s: &TcpSegment<T>,
        ack_number: u32,
        additional_flags: TcpFlags,
    ) {
        assert_eq!(s.flags_after_ns(), TcpFlags::ACK | additional_flags);
        assert_eq!(s.ack_number(), ack_number);
    }

    // The following "check_" helper functions ensure a Connection in a certain state does not have
    // any unwarranted status flags set. We wouldn't need to look at this if we used a state enum
    // instead of a status flags set.
    fn check_syn_received(c: &Connection) {
        assert_eq!(c.status_flags, ConnStatusFlags::SYN_RECEIVED);
    }

    fn check_synack_sent(c: &Connection) {
        assert_eq!(
            c.status_flags,
            ConnStatusFlags::SYN_RECEIVED | ConnStatusFlags::SYNACK_SENT
        );
    }

    fn check_established(c: &Connection) {
        assert_eq!(
            c.status_flags,
            ConnStatusFlags::SYN_RECEIVED
                | ConnStatusFlags::SYNACK_SENT
                | ConnStatusFlags::ESTABLISHED
        );
    }

    fn check_fin_received_but_not_sent(c: &Connection) {
        assert_eq!(
            c.status_flags,
            ConnStatusFlags::SYN_RECEIVED
                | ConnStatusFlags::SYNACK_SENT
                | ConnStatusFlags::ESTABLISHED
        );
        assert!(c.fin_received());
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_connection() {
        // These are used to support some segments we play around with.
        let mut buf1 = [0u8; 100];
        let mut buf2 = [0u8; 100];
        let mut buf3 = [0u8; 1500];
        // Buffer containing the payload of the incoming data segment.
        let data_buf = [2u8; 1000];
        // Buffer containing the data which the connection sends on outgoing segments.
        let send_buf = [11u8; 20000];

        let mut t = ConnectionTester::new();

        let mut syn = t.write_syn(buf1.as_mut());
        let mut ctrl = t.write_ctrl(buf2.as_mut());
        let mut data = t.write_data(buf3.as_mut(), data_buf.as_ref());

        // Test creating a new connection based on invalid SYN segments.

        // Invalid flags.
        syn.set_flags_after_ns(TcpFlags::SYN | TcpFlags::ACK);
        assert_eq!(
            t.passive_open(&syn).unwrap_err(),
            PassiveOpenError::InvalidSyn
        );

        // SYN segment with payload.
        data.set_flags_after_ns(TcpFlags::SYN);
        assert_eq!(
            t.passive_open(&data).unwrap_err(),
            PassiveOpenError::InvalidSyn
        );

        // Ok, now let's test with connections created using valid SYN segments.

        // Set valid flags.
        syn.set_flags_after_ns(TcpFlags::SYN);

        let mut c = t.passive_open(&syn).unwrap();

        assert_eq!(c.ack_to_send.0, t.remote_isn.wrapping_add(1));
        assert_eq!(c.first_not_sent, c.highest_ack_received + Wrapping(1));
        assert_eq!(
            c.local_rwnd_edge.0,
            t.remote_isn.wrapping_add(1 + t.local_rwnd_size)
        );
        assert_eq!(
            c.remote_rwnd_edge,
            c.first_not_sent + Wrapping(u32::from(t.remote_window_size))
        );
        check_syn_received(&c);

        // There's a SYNACK to send.
        assert_eq!(
            c.control_segment_or_timeout_status(),
            NextSegmentStatus::Available
        );

        let mut c_clone = c.clone();

        // While the connection is in this state, we send another SYN, with a different ISN.
        syn.set_sequence_number(t.remote_isn.wrapping_add(1));
        t.should_reset_after(
            &mut c,
            &syn,
            RecvStatusFlags::INVALID_SEGMENT | RecvStatusFlags::CONN_RESETTING,
            TcpFlags::ACK,
        );

        // Let's restore the connection.
        c = c_clone;
        let mut payload_src = Some((send_buf.as_ref(), c.highest_ack_received));

        // Sending the exact same SYN again should be fine.
        syn.set_sequence_number(t.remote_isn);
        assert_eq!(
            t.receive_segment(&mut c, &syn).unwrap(),
            (None, RecvStatusFlags::empty())
        );

        // The connection should send a SYNACK at the next opportunity.
        t.check_synack_is_next(&mut c);

        // Calling write_next_segment again should not send anything else.
        assert!(t.write_next_segment(&mut c, payload_src).unwrap().is_none());

        // Also, we now have a RTO pending.
        assert_eq!(
            c.control_segment_or_timeout_status(),
            NextSegmentStatus::Timeout(t.rto_period)
        );

        // However, if we advance the time until just after the RTO, a SYNACK is retransmitted.
        t.now += t.rto_period;
        t.check_synack_is_next(&mut c);

        assert_eq!(
            c.control_segment_or_timeout_status(),
            NextSegmentStatus::Timeout(2 * t.rto_period)
        );

        // Re-receiving a valid SYN moves the connection back to SYN_RECEIVED.
        assert_eq!(
            t.receive_segment(&mut c, &syn).unwrap(),
            (None, RecvStatusFlags::empty())
        );
        check_syn_received(&c);

        // And thus, a SYNACK will be the next segment to be transmitted once again.
        t.check_synack_is_next(&mut c);

        // Now is a time as good as any to see what happens if we receive a RST. First, let's try
        // with an invalid RST (its sequence number is out of window).
        ctrl.set_sequence_number(c.ack_to_send.0.wrapping_sub(1))
            .set_flags_after_ns(TcpFlags::RST);
        assert_eq!(
            t.receive_segment(&mut c, &ctrl).unwrap(),
            (None, RecvStatusFlags::INVALID_RST)
        );

        // Let's back up c, because the next segment will be a valid RST.
        c_clone = c.clone();
        ctrl.set_sequence_number(c.ack_to_send.0);
        t.should_reset_after(
            &mut c,
            &ctrl,
            RecvStatusFlags::RESET_RECEIVED,
            TcpFlags::ACK,
        );

        // Cool, let's restore c and continue.
        c = c_clone.clone();
        let conn_isn = c.first_not_sent.0.wrapping_sub(1);

        // Ok so we're waiting for the SYNACK to be acked. Any incoming segment which is not a
        // retransmitted SYN, but has the SYN flag set will cause a reset.
        data.set_flags_after_ns(TcpFlags::ACK | TcpFlags::SYN)
            .set_ack_number(conn_isn.wrapping_add(1))
            .set_sequence_number(t.remote_isn.wrapping_add(1));

        t.should_reset_after(
            &mut c,
            &data,
            RecvStatusFlags::INVALID_SEGMENT | RecvStatusFlags::CONN_RESETTING,
            // The RST emitted in response won't have the ACK flag set because we can infer a
            // sequence number from the ACK carried by the data segment.
            TcpFlags::empty(),
        );

        c = c_clone.clone();
        // A valid ACK should move the connection into ESTABLISHED. Also, since we allow more than
        // just pure ACKs at this point, any valid data should be received as well.
        data.set_flags_after_ns(TcpFlags::ACK);
        assert_eq!(
            t.receive_segment(&mut c, &data).unwrap(),
            (
                Some(NonZeroUsize::new(data_buf.len()).unwrap()),
                RecvStatusFlags::empty()
            )
        );
        assert!(c.is_established());

        c = c_clone.clone();
        // In fact, since we're so like whatever about the segments we receive here, let's see what
        // happens if data also carries the FIN flag (spoiler: it works).
        data.set_flags_after_ns(TcpFlags::ACK | TcpFlags::FIN);

        assert_eq!(
            t.receive_segment(&mut c, &data).unwrap(),
            (
                Some(NonZeroUsize::new(data_buf.len()).unwrap()),
                RecvStatusFlags::empty()
            )
        );
        assert!(c.is_established());
        assert!(c.fin_received());

        c = c_clone.clone();
        // That being said, let's move into established via a pure ACK.
        ctrl.set_flags_after_ns(TcpFlags::ACK)
            .set_ack_number(conn_isn.wrapping_add(1));

        assert_eq!(
            t.receive_segment(&mut c, &ctrl).unwrap(),
            (None, RecvStatusFlags::empty())
        );
        check_established(&c);

        // Cool, let's back c up.
        c_clone = c.clone();

        // We still get spooked if we get something with a SYN.
        data.set_flags_after_ns(TcpFlags::SYN | TcpFlags::ACK);
        t.should_reset_after(
            &mut c,
            &data,
            RecvStatusFlags::INVALID_SEGMENT | RecvStatusFlags::CONN_RESETTING,
            // The RST emitted in response won't have the ACK flag set because we can infer a
            // sequence number from the ACK carried by the data segment.
            TcpFlags::empty(),
        );

        c = c_clone.clone();

        // Ok so back to ESTABLISHED, let's make sure we only accept the exact sequence
        // number we expect (which is t.remote_isn + 1 at this point). The following segment should
        // not be accepted.
        data.set_flags_after_ns(TcpFlags::ACK)
            .set_sequence_number(t.remote_isn);
        assert_eq!(
            t.receive_segment(&mut c, &data).unwrap(),
            (None, RecvStatusFlags::UNEXPECTED_SEQ)
        );

        // However, if we set the expected sequence everything should be ok.
        data.set_sequence_number(t.remote_isn + 1);
        assert_eq!(
            t.receive_segment(&mut c, &data).unwrap(),
            (
                Some(NonZeroUsize::new(data.payload_len().into()).unwrap()),
                RecvStatusFlags::empty()
            )
        );

        // This is the ack number that should be set/sent.
        let expected_ack = t.remote_isn.wrapping_add(u32::from(data.payload_len()) + 1);

        // Check that internal state gets updated properly.
        assert_eq!(c.ack_to_send.0, expected_ack);

        {
            // We should get a pure ACK here, because we don't provide a payload source.
            let s = t.write_next_segment(&mut c, None).unwrap().unwrap();
            check_acks(&s, expected_ack, TcpFlags::empty());
        }

        // Calling write_next_segment (without a payload source) again should not send
        // anything else.
        assert!(t.write_next_segment(&mut c, None).unwrap().is_none());

        {
            let payload_len = u32::from(data.payload_len());

            // Assuming no one changed the code, the local window size of the connection was 10000,
            // so we should be able to successfully receive 9 more segments with 1000 byte payloads.
            let max = 9;
            for i in 1u32..=max {
                // The 1 we add is because the SYN consumes a sequence number.
                data.set_sequence_number(t.remote_isn.wrapping_add(1 + i * payload_len));
                assert_eq!(
                    t.receive_segment(&mut c, &data).unwrap(),
                    (
                        Some(NonZeroUsize::new(data.payload_len().into()).unwrap()),
                        RecvStatusFlags::empty()
                    )
                );
            }

            let expected_ack = t.remote_isn.wrapping_add(1 + (max + 1) * payload_len);
            // The connection should send a single cumulative ACK, and no other segment afterward
            // (if we don't also provide a payload source, which we don't).
            {
                {
                    let s = t.write_next_segment(&mut c, None).unwrap().unwrap();
                    check_acks(&s, expected_ack, TcpFlags::empty());
                }

                assert!(t.write_next_segment(&mut c, None).unwrap().is_none());
            }

            // Sending any more new data should be outside of the receive window of the connection.
            data.set_sequence_number(expected_ack);
            assert_eq!(
                t.receive_segment(&mut c, &data).unwrap(),
                (None, RecvStatusFlags::SEGMENT_BEYOND_RWND)
            );
        }

        // Restore connection state to just after ESTABLISHED, and make it send some data.
        c = c_clone.clone();

        // This should send anything, as the payload source does not contain the next sequence
        // number to be sent.

        // Should contain conn_isn + 1 to be fine, but we make it start just after.
        payload_src.as_mut().unwrap().1 = Wrapping(conn_isn) + Wrapping(2);

        assert_eq!(
            t.write_next_segment(&mut c, payload_src).unwrap_err(),
            WriteNextError::PayloadMissingSeq
        );

        // Let's fix it.
        payload_src.as_mut().unwrap().1 = Wrapping(conn_isn) + Wrapping(1);

        // The mss is 1100, and the remote window is 11000, so we can send 10 data packets.
        let max = 10;
        let remote_isn = t.remote_isn;
        let mss = t.mss;

        let (payload_buf, mut response_seq) = payload_src.unwrap();
        let mut payload_offset = 0;
        for i in 0..max {
            // Using the expects to get the value of i if there's an error.
            let s = t
                .write_next_segment(&mut c, Some((&payload_buf[payload_offset..], response_seq)))
                .unwrap_or_else(|_| panic!("{}", i))
                .unwrap_or_else(|| panic!("{}", i));

            payload_offset += usize::from(s.payload_len());
            response_seq += Wrapping(u32::from(s.payload_len()));

            // Again, the 1 accounts for the sequence number taken up by the SYN.
            assert_eq!(
                s.sequence_number(),
                conn_isn.wrapping_add(1 + i * u32::from(mss)),
            );
            assert_eq!(s.ack_number(), remote_isn.wrapping_add(1));
            assert_eq!(s.flags_after_ns(), TcpFlags::ACK);
            assert_eq!(s.payload_len(), mss);
        }

        // No more new data can be sent until the window advances, even though data_buf
        // contains 20_000 bytes.
        assert!(t.write_next_segment(&mut c, payload_src).unwrap().is_none());

        // Let's ACK the first segment previously sent.
        ctrl.set_ack_number(conn_isn.wrapping_add(1 + u32::from(mss)))
            .set_flags_after_ns(TcpFlags::ACK);
        assert_eq!(
            t.receive_segment(&mut c, &ctrl).unwrap(),
            (None, RecvStatusFlags::empty())
        );

        // We should be able to send one more segment now.
        {
            let s = t.write_next_segment(&mut c, payload_src).unwrap().unwrap();
            assert_eq!(
                s.sequence_number(),
                conn_isn.wrapping_add(1 + max * u32::from(mss)),
            );
            assert_eq!(s.payload_len(), mss);
        }
        assert!(t.write_next_segment(&mut c, payload_src).unwrap().is_none());

        // We have to wait for the window to open again in order to send new data, but we can
        // have retransmissions. For example, receiving the previous ACK again will cause a
        // DUPACK, which will trigger a retransmission.
        assert_eq!(
            t.receive_segment(&mut c, &ctrl).unwrap(),
            (None, RecvStatusFlags::DUP_ACK)
        );
        assert!(c.dup_ack_pending());

        // Let's check that we indeed get a single retransmitted segment.
        {
            let s = t.write_next_segment(&mut c, payload_src).unwrap().unwrap();
            assert_eq!(s.sequence_number(), ctrl.ack_number());
            assert_eq!(s.payload_len(), mss);
        }
        assert!(t.write_next_segment(&mut c, payload_src).unwrap().is_none());

        // Retransmissions also trigger after time-out.
        t.now += t.rto_period;
        {
            let s = t.write_next_segment(&mut c, payload_src).unwrap().unwrap();
            assert_eq!(s.sequence_number(), ctrl.ack_number());
            assert_eq!(s.payload_len(), mss);
        }
        assert!(t.write_next_segment(&mut c, payload_src).unwrap().is_none());

        // Btw, let's also make sure another retransmission will happen after another time-out,
        // but not earlier.
        t.now += t.rto_period - 1;
        assert!(t.write_next_segment(&mut c, payload_src).unwrap().is_none());

        t.now += 1;
        {
            let s = t.write_next_segment(&mut c, payload_src).unwrap().unwrap();
            assert_eq!(s.sequence_number(), ctrl.ack_number());
            assert_eq!(s.payload_len(), mss);
        }
        assert!(t.write_next_segment(&mut c, payload_src).unwrap().is_none());

        c_clone = c.clone();

        // Triggering another timeout should reset the connection, because t.rto_count_max == 3.
        t.now += t.rto_period;
        {
            let s = t.write_next_segment(&mut c, payload_src).unwrap().unwrap();
            assert!(s.flags_after_ns().intersects(TcpFlags::RST));
            assert!(c.is_reset());
        }

        // Let's undo the reset.
        t.now -= t.rto_period;
        c = c_clone;

        // Also, time-outs should stop happening if we got ACKs for all outgoing segments. This
        // ACK also closes the remote receive window so we can't send any new data.
        ctrl.set_ack_number(c.first_not_sent.0).set_window_size(0);
        assert_eq!(
            t.receive_segment(&mut c, &ctrl).unwrap(),
            (None, RecvStatusFlags::empty())
        );
        assert!(t.write_next_segment(&mut c, payload_src).unwrap().is_none());
        t.now += t.rto_period;
        assert!(t.write_next_segment(&mut c, payload_src).unwrap().is_none());

        // Let's open the window a bit, to see that the next transmitted segment fits that
        // exact size.
        ctrl.set_window_size(123);
        assert_eq!(
            t.receive_segment(&mut c, &ctrl).unwrap(),
            (None, RecvStatusFlags::empty())
        );
        {
            let s = t.write_next_segment(&mut c, payload_src).unwrap().unwrap();
            assert_eq!(s.sequence_number(), ctrl.ack_number());
            assert_eq!(s.payload_len(), 123);
        }
        // And let's do one more retransmission timing check.
        assert!(t.write_next_segment(&mut c, payload_src).unwrap().is_none());
        t.now += t.rto_period - 1;
        assert!(t.write_next_segment(&mut c, payload_src).unwrap().is_none());
        t.now += 1;
        {
            let s = t.write_next_segment(&mut c, payload_src).unwrap().unwrap();
            assert_eq!(s.sequence_number(), ctrl.ack_number());
            assert_eq!(s.payload_len(), 123);
        }

        // This looks like a good time to check what happens for some invalid ACKs. First, let's
        // make sure we properly detect an invalid window_size advertisement (where the remote rwnd
        // edge decreases compared to previously received info).
        ctrl.set_window_size(100);
        assert_eq!(
            t.receive_segment(&mut c, &ctrl).unwrap(),
            (
                None,
                RecvStatusFlags::DUP_ACK | RecvStatusFlags::REMOTE_RWND_EDGE
            )
        );
        // Let's clear the DUP_ACK related state.
        c.dup_ack = false;

        // Now let try some invalid ACKs. This one is an older ACK.
        ctrl.set_ack_number(c.highest_ack_received.0.wrapping_sub(1));
        assert_eq!(
            t.receive_segment(&mut c, &ctrl).unwrap(),
            (None, RecvStatusFlags::INVALID_ACK)
        );

        // Another example of invalid ACK is one that tries to acknowledge a sequence number yet
        // to be sent.
        ctrl.set_ack_number(c.first_not_sent.0.wrapping_add(1));
        assert_eq!(
            t.receive_segment(&mut c, &ctrl).unwrap(),
            (None, RecvStatusFlags::INVALID_ACK)
        );

        // FIN time! As usual let's begin with receiving an invalid FIN, one that does not match
        // the sequence number we expect.
        ctrl.set_flags_after_ns(TcpFlags::FIN)
            .set_sequence_number(c.ack_to_send.0.wrapping_sub(1));
        assert_eq!(
            t.receive_segment(&mut c, &ctrl).unwrap(),
            (None, RecvStatusFlags::INVALID_FIN)
        );

        // Ok now let's use a valid FIN.
        ctrl.set_sequence_number(c.ack_to_send.0);
        assert_eq!(
            t.receive_segment(&mut c, &ctrl).unwrap(),
            (None, RecvStatusFlags::empty())
        );
        check_fin_received_but_not_sent(&c);

        // The next segment right now should be a pure ACK for the FIN.
        {
            let s = t.write_next_segment(&mut c, payload_src).unwrap().unwrap();
            check_control_segment(&s, 0, TcpFlags::ACK);
            assert_eq!(s.ack_number(), ctrl.sequence_number().wrapping_add(1),);
        }

        // Receiving data after the FIN is an error. We increase the rwnd edge for c, because the
        // window was full after the earlier reception tests.
        c.advance_local_rwnd_edge(10_000);
        // We'll also get the INVALID_ACK RecvStausFlag here because the ACK number is old.
        data.set_sequence_number(c.ack_to_send.0);
        assert_eq!(
            t.receive_segment(&mut c, &data).unwrap(),
            (
                None,
                RecvStatusFlags::DATA_BEYOND_FIN | RecvStatusFlags::INVALID_ACK
            )
        );

        assert!(t.write_next_segment(&mut c, payload_src).unwrap().is_none());

        // c = c_clone.clone();

        // We change payload_src to only include those parts of send_buf that were already sent,
        // so it makes sense to close the connection as if we're done transmitting data.
        let bytes_sent_by_c = c.first_not_sent.0.wrapping_sub(conn_isn + 1) as usize;
        payload_src.as_mut().unwrap().0 = &send_buf[..bytes_sent_by_c];

        // We artifically increase the remote rwnd for c, so we can verify we sent everything, and
        // we're not just rwnd bound. We also make it so everything is ACKed, so we can sent a FIN
        // right after calling close() below (this is needed because we didn't ACK the last
        // segment sent by c).
        c.remote_rwnd_edge += Wrapping(50_000);
        c.highest_ack_received = c.first_not_sent;

        // Save the state.
        // c_clone = c.clone();

        // Close the connection.
        c.close();

        // We shouldn't be done yet. Even though we got a FIN, we didn't send our own yet.
        assert!(!c.is_done());

        // If we call write_next at this point, the next outgoing segment should be a pure FIN/ACK.
        {
            let s = t.write_next_segment(&mut c, payload_src).unwrap().unwrap();
            check_control_segment(&s, 0, TcpFlags::FIN | TcpFlags::ACK);
            assert_eq!(
                s.sequence_number(),
                conn_isn.wrapping_add(1 + u32::try_from(bytes_sent_by_c).unwrap())
            );
        }

        // At this point, the connection should be done, because we both sent and received a FIN,
        // and we don't wait for our FIN to be ACKed.
        assert!(c.is_done());
    }
}
