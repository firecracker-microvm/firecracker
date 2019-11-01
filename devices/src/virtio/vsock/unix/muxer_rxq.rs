// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//

/// `MuxerRxQ` implements a helper object that `VsockMuxer` can use for queuing RX (host -> guest)
/// packets (or rather instructions on how to build said packets).
///
/// Under ideal operation, every connection, that has pending RX data, will be present in the muxer
/// RX queue. However, since the RX queue is smaller than the connection pool, it may, under some
/// conditions, become full, meaning that it can no longer account for all the connections that can
/// yield RX data.  When that happens, we say that it is no longer "synchronized" (i.e. with the
/// connection pool).  A desynchronized RX queue still holds valid data, and the muxer will
/// continue to pop packets from it. However, when a desynchronized queue is drained, additional
/// data may still be available, so the muxer will have to perform a more costly walk of the entire
/// connection pool to find it.  This walk is performed here, as part of building an RX queue from
/// the connection pool. When an out-of-sync is drained, the muxer will discard it, and attempt to
/// rebuild a synced one.
use std::collections::{HashMap, VecDeque};

use super::super::VsockChannel;
use super::defs;
use super::muxer::{ConnMapKey, MuxerRx};
use super::MuxerConnection;

/// The muxer RX queue.
pub struct MuxerRxQ {
    /// The RX queue data.
    q: VecDeque<MuxerRx>,
    /// The RX queue sync status.
    synced: bool,
}

impl MuxerRxQ {
    const SIZE: usize = defs::MUXER_RXQ_SIZE;

    /// Trivial RX queue constructor.
    pub fn new() -> Self {
        Self {
            q: VecDeque::with_capacity(Self::SIZE),
            synced: true,
        }
    }

    /// Attempt to build an RX queue, that is synchronized to the connection pool.
    /// Note: the resulting queue may still be desynchronized, if there are too many connections
    ///       that have pending RX data. In that case, the muxer will first drain this queue, and
    ///       then try again to build a synchronized one.
    pub fn from_conn_map(conn_map: &HashMap<ConnMapKey, MuxerConnection>) -> Self {
        let mut q = VecDeque::new();
        let mut synced = true;

        for (key, conn) in conn_map.iter() {
            if !conn.has_pending_rx() {
                continue;
            }
            if q.len() >= Self::SIZE {
                synced = false;
                break;
            }
            q.push_back(MuxerRx::ConnRx(*key));
        }
        Self { q, synced }
    }

    /// Push a new RX item to the queue.
    ///
    /// A push will fail when:
    /// - trying to push a connection key onto an out-of-sync, or full queue; or
    /// - trying to push an RST onto a queue already full of RSTs.
    /// RSTs take precedence over connections, because connections can always be queried for
    /// pending RX data later. Aside from this queue, there is no other storage for RSTs, so
    /// failing to push one means that we have to drop the packet.
    ///
    /// Returns:
    /// - `true` if the new item has been successfully queued; or
    /// - `false` if there was no room left in the queue.
    pub fn push(&mut self, rx: MuxerRx) -> bool {
        // Pushing to a non-full, synchronized queue will always succeed.
        if self.is_synced() && !self.is_full() {
            self.q.push_back(rx);
            return true;
        }

        match rx {
            MuxerRx::RstPkt { .. } => {
                // If we just failed to push an RST packet, we'll look through the queue, trying to
                // find a connection key that we could evict. This way, the queue does lose sync,
                // but we don't drop any packets.
                for qi in self.q.iter_mut().rev() {
                    if let MuxerRx::ConnRx(_) = qi {
                        *qi = rx;
                        self.synced = false;
                        return true;
                    }
                }
            }
            MuxerRx::ConnRx(_) => {
                self.synced = false;
            }
        };

        false
    }

    /// Pop an RX item from the front of the queue.
    pub fn pop(&mut self) -> Option<MuxerRx> {
        self.q.pop_front()
    }

    /// Check if the RX queue is synchronized with the connection pool.
    pub fn is_synced(&self) -> bool {
        self.synced
    }

    /// Get the total number of items in the queue.
    pub fn len(&self) -> usize {
        self.q.len()
    }

    /// Check if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Check if the queue is full.
    pub fn is_full(&self) -> bool {
        self.len() == Self::SIZE
    }
}
