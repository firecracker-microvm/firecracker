// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//

/// `MuxerKillQ` implements a helper object that `VsockMuxer` can use for scheduling forced
/// connection termination. I.e. after one peer issues a clean shutdown request
/// (VSOCK_OP_SHUTDOWN), the concerned connection is queued for termination (VSOCK_OP_RST) in
/// the near future (herein implemented via an expiring timer).
///
/// Whenever the muxer needs to schedule a connection for termination, it pushes it (or rather
/// an identifier - the connection key) to this queue. A subsequent pop() operation will
/// succeed if and only if the first connection in the queue is ready to be terminated (i.e.
/// its kill timer expired).
///
/// Without using this queue, the muxer would have to walk its entire connection pool
/// (hashmap), whenever it needs to check for expired kill timers. With this queue, both
/// scheduling and termination are performed in constant time. However, since we don't want to
/// waste space on a kill queue that's as big as the connection hashmap itself, it is possible
/// that this queue may become full at times.  We call this kill queue "synchronized" if we are
/// certain that all connections that are awaiting termination are present in the queue. This
/// means a simple constant-time pop() operation is enough to check whether any connections
/// need to be terminated.  When the kill queue becomes full, though, pushing fails, so
/// connections that should be terminated are left out. The queue is not synchronized anymore.
/// When that happens, the muxer will first drain the queue, and then replace it with a new
/// queue, created by walking the connection pool, looking for connections that will be
/// expiring in the future.
use std::collections::{HashMap, VecDeque};
use std::time::Instant;

use super::defs;
use super::muxer::ConnMapKey;
use super::MuxerConnection;

/// A kill queue item, holding the connection key and the scheduled time for termination.
#[derive(Clone, Copy)]
struct MuxerKillQItem {
    key: ConnMapKey,
    kill_time: Instant,
}

/// The connection kill queue: a FIFO structure, storing the connections that are scheduled for
/// termination.
pub struct MuxerKillQ {
    /// The kill queue contents.
    q: VecDeque<MuxerKillQItem>,

    /// The kill queue sync status:
    /// - when true, all connections that are awaiting termination are guaranteed to be in this
    ///   queue;
    /// - when false, some connections may have been left out.
    synced: bool,
}

impl MuxerKillQ {
    const SIZE: usize = defs::MUXER_KILLQ_SIZE;

    /// Trivial kill queue constructor.
    pub fn new() -> Self {
        Self {
            q: VecDeque::with_capacity(Self::SIZE),
            synced: true,
        }
    }

    /// Create a kill queue by walking the connection pool, looking for connections that are
    /// set to expire at some point in the future.
    /// Note: if more than `Self::SIZE` connections are found, the queue will be created in an
    ///       out-of-sync state, and will be discarded after it is emptied.
    pub fn from_conn_map(conn_map: &HashMap<ConnMapKey, MuxerConnection>) -> Self {
        let mut q_buf: Vec<MuxerKillQItem> = Vec::with_capacity(Self::SIZE);
        let mut synced = true;
        for (key, conn) in conn_map.iter() {
            if !conn.will_expire() {
                continue;
            }
            if q_buf.len() >= Self::SIZE {
                synced = false;
                break;
            }
            q_buf.push(MuxerKillQItem {
                key: *key,
                kill_time: conn.expiry().unwrap(),
            });
        }
        q_buf.sort_unstable_by_key(|it| it.kill_time);
        Self {
            q: q_buf.into(),
            synced,
        }
    }

    /// Push a connection key to the queue, scheduling it for termination at
    /// `CONN_SHUTDOWN_TIMEOUT_MS` from now (the push time).
    pub fn push(&mut self, key: ConnMapKey, kill_time: Instant) {
        if !self.is_synced() || self.is_full() {
            self.synced = false;
            return;
        }
        self.q.push_back(MuxerKillQItem { key, kill_time });
    }

    /// Attempt to pop an expired connection from the kill queue.
    ///
    /// This will succeed and return a connection key, only if the connection at the front of
    /// the queue has expired. Otherwise, `None` is returned.
    pub fn pop(&mut self) -> Option<ConnMapKey> {
        if let Some(item) = self.q.front() {
            if Instant::now() > item.kill_time {
                return Some(self.q.pop_front().unwrap().key);
            }
        }
        None
    }

    /// Check if the kill queue is synchronized with the connection pool.
    pub fn is_synced(&self) -> bool {
        self.synced
    }

    /// Check if the kill queue is empty, obviously.
    pub fn is_empty(&self) -> bool {
        self.q.len() == 0
    }

    /// Check if the kill queue is full.
    pub fn is_full(&self) -> bool {
        self.q.len() == Self::SIZE
    }
}
