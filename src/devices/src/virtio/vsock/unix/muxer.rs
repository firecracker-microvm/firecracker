// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//

/// `VsockMuxer` is the device-facing component of the Unix domain sockets vsock backend. I.e.
/// by implementing the `VsockBackend` trait, it abstracts away the gory details of translating
/// between AF_VSOCK and AF_UNIX, and presents a clean interface to the rest of the vsock
/// device model.
///
/// The vsock muxer has two main roles:
/// 1. Vsock connection multiplexer:
///    It's the muxer's job to create, manage, and terminate `VsockConnection` objects. The
///    muxer also routes packets to their owning connections. It does so via a connection
///    `HashMap`, keyed by what is basically a (host_port, guest_port) tuple.
///    Vsock packet traffic needs to be inspected, in order to detect connection request
///    packets (leading to the creation of a new connection), and connection reset packets
///    (leading to the termination of an existing connection). All other packets, though, must
///    belong to an existing connection and, as such, the muxer simply forwards them.
/// 2. Event dispatcher
///    There are three event categories that the vsock backend is interested it:
///    1. A new host-initiated connection is ready to be accepted from the listening host Unix
///       socket;
///    2. Data is available for reading from a newly-accepted host-initiated connection (i.e.
///       the host is ready to issue a vsock connection request, informing us of the
///       destination port to which it wants to connect);
///    3. Some event was triggered for a connected Unix socket, that belongs to a
///       `VsockConnection`.
///    The muxer gets notified about all of these events, because, as a `VsockEpollListener`
///    implementor, it gets to register a nested epoll FD into the main VMM epolling loop. All
///    other pollable FDs are then registered under this nested epoll FD.
///    To route all these events to their handlers, the muxer uses another `HashMap` object,
///    mapping `RawFd`s to `EpollListener`s.
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};

use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};

use super::super::csm::ConnState;
use super::super::defs::uapi;
use super::super::packet::VsockPacket;
use super::super::{
    Result as VsockResult, VsockBackend, VsockChannel, VsockEpollListener, VsockError,
};
use super::defs;
use super::muxer_killq::MuxerKillQ;
use super::muxer_rxq::MuxerRxQ;
use super::MuxerConnection;
use super::{Error, Result};

/// A unique identifier of a `MuxerConnection` object. Connections are stored in a hash map,
/// keyed by a `ConnMapKey` object.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ConnMapKey {
    local_port: u32,
    peer_port: u32,
}

/// A muxer RX queue item.
#[derive(Debug)]
pub enum MuxerRx {
    /// The packet must be fetched from the connection identified by `ConnMapKey`.
    ConnRx(ConnMapKey),
    /// The muxer must produce an RST packet.
    RstPkt { local_port: u32, peer_port: u32 },
}

/// An epoll listener, registered under the muxer's nested epoll FD.
enum EpollListener {
    /// The listener is a `MuxerConnection`, identified by `key`, and interested in the events
    /// in `evset`. Since `MuxerConnection` implements `VsockEpollListener`, notifications will
    /// be forwarded to the listener via `VsockEpollListener::notify()`.
    Connection { key: ConnMapKey, evset: EventSet },
    /// A listener interested in new host-initiated connections.
    HostSock,
    /// A listener interested in reading host "connect <port>" commands from a freshly
    /// connected host socket.
    LocalStream(UnixStream),
}

/// The vsock connection multiplexer.
pub struct VsockMuxer {
    /// Guest CID.
    cid: u64,
    /// A hash map used to store the active connections.
    conn_map: HashMap<ConnMapKey, MuxerConnection>,
    /// A hash map used to store epoll event listeners / handlers.
    listener_map: HashMap<RawFd, EpollListener>,
    /// The RX queue. Items in this queue are consumed by `VsockMuxer::recv_pkt()`, and
    /// produced
    /// - by `VsockMuxer::send_pkt()` (e.g. RST in response to a connection request packet);
    ///   and
    /// - in response to EPOLLIN events (e.g. data available to be read from an AF_UNIX
    ///   socket).
    rxq: MuxerRxQ,
    /// A queue used for terminating connections that are taking too long to shut down.
    killq: MuxerKillQ,
    /// The Unix socket, through which host-initiated connections are accepted.
    host_sock: UnixListener,
    /// The file system path of the host-side Unix socket. This is used to figure out the path
    /// to Unix sockets listening on specific ports. I.e. "<this path>_<port number>".
    host_sock_path: String,
    /// The nested epoll event set, used to register epoll listeners.
    epoll: Epoll,
    /// A hash set used to keep track of used host-side (local) ports, in order to assign local
    /// ports to host-initiated connections.
    local_port_set: HashSet<u32>,
    /// The last used host-side port.
    local_port_last: u32,
}

impl VsockChannel for VsockMuxer {
    /// Deliver a vsock packet to the guest vsock driver.
    ///
    /// Retuns:
    /// - `Ok(())`: `pkt` has been successfully filled in; or
    /// - `Err(VsockError::NoData)`: there was no available data with which to fill in the
    ///   packet.
    fn recv_pkt(&mut self, pkt: &mut VsockPacket) -> VsockResult<()> {
        // We'll look for instructions on how to build the RX packet in the RX queue. If the
        // queue is empty, that doesn't necessarily mean we don't have any pending RX, since
        // the queue might be out-of-sync. If that's the case, we'll attempt to sync it first,
        // and then try to pop something out again.
        if self.rxq.is_empty() && !self.rxq.is_synced() {
            self.rxq = MuxerRxQ::from_conn_map(&self.conn_map);
        }

        while let Some(rx) = self.rxq.pop() {
            let res = match rx {
                // We need to build an RST packet, going from `local_port` to `peer_port`.
                MuxerRx::RstPkt {
                    local_port,
                    peer_port,
                } => {
                    pkt.set_op(uapi::VSOCK_OP_RST)
                        .set_src_cid(uapi::VSOCK_HOST_CID)
                        .set_dst_cid(self.cid)
                        .set_src_port(local_port)
                        .set_dst_port(peer_port)
                        .set_len(0)
                        .set_type(uapi::VSOCK_TYPE_STREAM)
                        .set_flags(0)
                        .set_buf_alloc(0)
                        .set_fwd_cnt(0);
                    return Ok(());
                }

                // We'll defer building the packet to this connection, since it has something
                // to say.
                MuxerRx::ConnRx(key) => {
                    let mut conn_res = Err(VsockError::NoData);
                    self.apply_conn_mutation(key, |conn| {
                        conn_res = conn.recv_pkt(pkt);
                    });
                    conn_res
                }
            };

            if res.is_ok() {
                // Inspect traffic, looking for RST packets, since that means we have to
                // terminate and remove this connection from the active connection pool.
                //
                if pkt.op() == uapi::VSOCK_OP_RST {
                    self.remove_connection(ConnMapKey {
                        local_port: pkt.src_port(),
                        peer_port: pkt.dst_port(),
                    });
                }

                debug!("vsock muxer: RX pkt: {:?}", pkt.hdr());
                return Ok(());
            }
        }

        Err(VsockError::NoData)
    }

    /// Deliver a guest-generated packet to its destination in the vsock backend.
    ///
    /// This absorbs unexpected packets, handles RSTs (by dropping connections), and forwards
    /// all the rest to their owning `MuxerConnection`.
    ///
    /// Returns:
    /// always `Ok(())` - the packet has been consumed, and its virtio TX buffers can be
    /// returned to the guest vsock driver.
    fn send_pkt(&mut self, pkt: &VsockPacket) -> VsockResult<()> {
        let conn_key = ConnMapKey {
            local_port: pkt.dst_port(),
            peer_port: pkt.src_port(),
        };

        debug!(
            "vsock: muxer.send[rxq.len={}]: {:?}",
            self.rxq.len(),
            pkt.hdr()
        );

        // If this packet has an unsupported type (!=stream), we must send back an RST.
        //
        if pkt.type_() != uapi::VSOCK_TYPE_STREAM {
            self.enq_rst(pkt.dst_port(), pkt.src_port());
            return Ok(());
        }

        // We don't know how to handle packets addressed to other CIDs. We only handle the host
        // part of the guest - host communication here.
        if pkt.dst_cid() != uapi::VSOCK_HOST_CID {
            info!(
                "vsock: dropping guest packet for unknown CID: {:?}",
                pkt.hdr()
            );
            return Ok(());
        }

        if !self.conn_map.contains_key(&conn_key) {
            // This packet can't be routed to any active connection (based on its src and dst
            // ports).  The only orphan / unroutable packets we know how to handle are
            // connection requests.
            if pkt.op() == uapi::VSOCK_OP_REQUEST {
                // Oh, this is a connection request!
                self.handle_peer_request_pkt(&pkt);
            } else {
                // Send back an RST, to let the drive know we weren't expecting this packet.
                self.enq_rst(pkt.dst_port(), pkt.src_port());
            }
            return Ok(());
        }

        // Right, we know where to send this packet, then (to `conn_key`).
        // However, if this is an RST, we have to forcefully terminate the connection, so
        // there's no point in forwarding it the packet.
        if pkt.op() == uapi::VSOCK_OP_RST {
            self.remove_connection(conn_key);
            return Ok(());
        }

        // Alright, everything looks in order - forward this packet to its owning connection.
        let mut res: VsockResult<()> = Ok(());
        self.apply_conn_mutation(conn_key, |conn| {
            res = conn.send_pkt(pkt);
        });

        res
    }

    /// Check if the muxer has any pending RX data, with which to fill a guest-provided RX
    /// buffer.
    fn has_pending_rx(&self) -> bool {
        !self.rxq.is_empty() || !self.rxq.is_synced()
    }
}

impl AsRawFd for VsockMuxer {
    /// Get the FD to be registered for polling upstream (in the main VMM epoll loop, in this
    /// case).
    ///
    /// This will be the muxer's nested epoll FD.
    fn as_raw_fd(&self) -> RawFd {
        self.epoll.as_raw_fd()
    }
}

impl VsockEpollListener for VsockMuxer {
    /// Get the epoll events to be polled upstream.
    ///
    /// Since the polled FD is a nested epoll FD, we're only interested in EPOLLIN events (i.e.
    /// some event occured on one of the FDs registered under our epoll FD).
    fn get_polled_evset(&self) -> EventSet {
        EventSet::IN
    }

    /// Notify the muxer about a pending event having occured under its nested epoll FD.
    fn notify(&mut self, _: EventSet) {
        debug!("vsock: muxer received kick");

        let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
        match self
            .epoll
            .wait(epoll_events.len(), 0, epoll_events.as_mut_slice())
        {
            Ok(ev_cnt) => {
                for ev in &epoll_events[0..ev_cnt] {
                    self.handle_event(
                        ev.fd(),
                        // It's ok to unwrap here, since the `epoll_events[i].events` is filled
                        // in by `epoll::wait()`, and therefore contains only valid epoll
                        // flags.
                        EventSet::from_bits(ev.events).unwrap(),
                    );
                }
            }
            Err(e) => {
                warn!("vsock: failed to consume muxer epoll event: {}", e);
            }
        }
    }
}

impl VsockBackend for VsockMuxer {}

impl VsockMuxer {
    /// Muxer constructor.
    pub fn new(cid: u64, host_sock_path: String) -> Result<Self> {
        // Open/bind on the host Unix socket, so we can accept host-initiated
        // connections.
        let host_sock = UnixListener::bind(&host_sock_path)
            .and_then(|sock| sock.set_nonblocking(true).map(|_| sock))
            .map_err(Error::UnixBind)?;

        let mut muxer = Self {
            cid,
            host_sock,
            host_sock_path,
            epoll: Epoll::new().map_err(Error::EpollFdCreate)?,
            rxq: MuxerRxQ::new(),
            conn_map: HashMap::with_capacity(defs::MAX_CONNECTIONS),
            listener_map: HashMap::with_capacity(defs::MAX_CONNECTIONS + 1),
            killq: MuxerKillQ::new(),
            local_port_last: (1u32 << 30) - 1,
            local_port_set: HashSet::with_capacity(defs::MAX_CONNECTIONS),
        };

        // Listen on the host initiated socket, for incomming connections.
        muxer.add_listener(muxer.host_sock.as_raw_fd(), EpollListener::HostSock)?;
        Ok(muxer)
    }

    /// Handle/dispatch an epoll event to its listener.
    fn handle_event(&mut self, fd: RawFd, evset: EventSet) {
        debug!(
            "vsock: muxer processing event: fd={}, evset={:?}",
            fd, evset
        );

        match self.listener_map.get_mut(&fd) {
            // This event needs to be forwarded to a `MuxerConnection` that is listening for
            // it.
            Some(EpollListener::Connection { key, evset }) => {
                let key_copy = *key;
                let evset_copy = *evset;
                // The handling of this event will most probably mutate the state of the
                // receiving conection. We'll need to check for new pending RX, event set
                // mutation, and all that, so we're wrapping the event delivery inside those
                // checks.
                self.apply_conn_mutation(key_copy, |conn| {
                    conn.notify(evset_copy);
                });
            }

            // A new host-initiated connection is ready to be accepted.
            Some(EpollListener::HostSock) => {
                if self.conn_map.len() == defs::MAX_CONNECTIONS {
                    // If we're already maxed-out on connections, we'll just accept and
                    // immediately discard this potentially new one.
                    warn!("vsock: connection limit reached; refusing new host connection");
                    self.host_sock.accept().map(|_| 0).unwrap_or(0);
                    return;
                }
                self.host_sock
                    .accept()
                    .map_err(Error::UnixAccept)
                    .and_then(|(stream, _)| {
                        stream
                            .set_nonblocking(true)
                            .map(|_| stream)
                            .map_err(Error::UnixAccept)
                    })
                    .and_then(|stream| {
                        // Before forwarding this connection to a listening AF_VSOCK socket on
                        // the guest side, we need to know the destination port. We'll read
                        // that port from a "connect" command received on this socket, so the
                        // next step is to ask to be notified the moment we can read from it.
                        self.add_listener(stream.as_raw_fd(), EpollListener::LocalStream(stream))
                    })
                    .unwrap_or_else(|err| {
                        warn!("vsock: unable to accept local connection: {:?}", err);
                    });
            }

            // Data is ready to be read from a host-initiated connection. That would be the
            // "connect" command that we're expecting.
            Some(EpollListener::LocalStream(_)) => {
                if let Some(EpollListener::LocalStream(mut stream)) = self.remove_listener(fd) {
                    Self::read_local_stream_port(&mut stream)
                        .and_then(|peer_port| Ok((self.allocate_local_port(), peer_port)))
                        .and_then(|(local_port, peer_port)| {
                            self.add_connection(
                                ConnMapKey {
                                    local_port,
                                    peer_port,
                                },
                                MuxerConnection::new_local_init(
                                    stream,
                                    uapi::VSOCK_HOST_CID,
                                    self.cid,
                                    local_port,
                                    peer_port,
                                ),
                            )
                        })
                        .unwrap_or_else(|err| {
                            info!("vsock: error adding local-init connection: {:?}", err);
                        })
                }
            }

            _ => {
                info!("vsock: unexpected event: fd={:?}, evset={:?}", fd, evset);
            }
        }
    }

    /// Parse a host "connect" command, and extract the destination vsock port.
    fn read_local_stream_port(stream: &mut UnixStream) -> Result<u32> {
        let mut buf = [0u8; 32];

        // This is the minimum number of bytes that we should be able to read, when parsing a
        // valid connection request. I.e. `b"connect 0\n".len()`.
        const MIN_READ_LEN: usize = 10;

        // Bring in the minimum number of bytes that we should be able to read.
        stream
            .read_exact(&mut buf[..MIN_READ_LEN])
            .map_err(Error::UnixRead)?;

        // Now, finish reading the destination port number, by bringing in one byte at a time,
        // until we reach an EOL terminator (or our buffer space runs out).  Yeah, not
        // particularly proud of this approach, but it will have to do for now.
        let mut blen = MIN_READ_LEN;
        while buf[blen - 1] != b'\n' && blen < buf.len() {
            stream
                .read_exact(&mut buf[blen..=blen])
                .map_err(Error::UnixRead)?;
            blen += 1;
        }

        let mut word_iter = std::str::from_utf8(&buf[..blen])
            .map_err(|_| Error::InvalidPortRequest)?
            .split_whitespace();

        word_iter
            .next()
            .ok_or(Error::InvalidPortRequest)
            .and_then(|word| {
                if word.to_lowercase() == "connect" {
                    Ok(())
                } else {
                    Err(Error::InvalidPortRequest)
                }
            })
            .and_then(|_| word_iter.next().ok_or(Error::InvalidPortRequest))
            .and_then(|word| word.parse::<u32>().map_err(|_| Error::InvalidPortRequest))
            .map_err(|_| Error::InvalidPortRequest)
    }

    /// Add a new connection to the active connection pool.
    fn add_connection(&mut self, key: ConnMapKey, conn: MuxerConnection) -> Result<()> {
        // We might need to make room for this new connection, so let's sweep the kill queue
        // first.  It's fine to do this here because:
        // - unless the kill queue is out of sync, this is a pretty inexpensive operation; and
        // - we are under no pressure to respect any accurate timing for connection
        //   termination.
        self.sweep_killq();

        if self.conn_map.len() >= defs::MAX_CONNECTIONS {
            info!(
                "vsock: muxer connection limit reached ({})",
                defs::MAX_CONNECTIONS
            );
            return Err(Error::TooManyConnections);
        }

        self.add_listener(
            conn.as_raw_fd(),
            EpollListener::Connection {
                key,
                evset: conn.get_polled_evset(),
            },
        )
        .and_then(|_| {
            if conn.has_pending_rx() {
                // We can safely ignore any error in adding a connection RX indication. Worst
                // case scenario, the RX queue will get desynchronized, but we'll handle that
                // the next time we need to yield an RX packet.
                self.rxq.push(MuxerRx::ConnRx(key));
            }
            self.conn_map.insert(key, conn);
            Ok(())
        })
    }

    /// Remove a connection from the active connection poll.
    fn remove_connection(&mut self, key: ConnMapKey) {
        if let Some(conn) = self.conn_map.remove(&key) {
            self.remove_listener(conn.as_raw_fd());
        }
        self.free_local_port(key.local_port);
    }

    /// Schedule a connection for immediate termination.
    /// I.e. as soon as we can also let our peer know we're dropping the connection, by sending
    /// it an RST packet.
    fn kill_connection(&mut self, key: ConnMapKey) {
        let mut had_rx = false;
        self.conn_map.entry(key).and_modify(|conn| {
            had_rx = conn.has_pending_rx();
            conn.kill();
        });
        // This connection will now have an RST packet to yield, so we need to add it to the RX
        // queue.  However, there's no point in doing that if it was already in the queue.
        if !had_rx {
            // We can safely ignore any error in adding a connection RX indication. Worst case
            // scenario, the RX queue will get desynchronized, but we'll handle that the next
            // time we need to yield an RX packet.
            self.rxq.push(MuxerRx::ConnRx(key));
        }
    }

    /// Register a new epoll listener under the muxer's nested epoll FD.
    fn add_listener(&mut self, fd: RawFd, listener: EpollListener) -> Result<()> {
        let evset = match listener {
            EpollListener::Connection { evset, .. } => evset,
            EpollListener::LocalStream(_) => EventSet::IN,
            EpollListener::HostSock => EventSet::IN,
        };

        self.epoll
            .ctl(
                ControlOperation::Add,
                fd,
                &EpollEvent::new(evset, fd as u64),
            )
            .and_then(|_| {
                self.listener_map.insert(fd, listener);
                Ok(())
            })
            .map_err(Error::EpollAdd)?;

        Ok(())
    }

    /// Remove (and return) a previously registered epoll listener.
    fn remove_listener(&mut self, fd: RawFd) -> Option<EpollListener> {
        let maybe_listener = self.listener_map.remove(&fd);

        if maybe_listener.is_some() {
            self.epoll
                .ctl(ControlOperation::Delete, fd, &EpollEvent::default())
                .unwrap_or_else(|err| {
                    warn!(
                        "vosck muxer: error removing epoll listener for fd {:?}: {:?}",
                        fd, err
                    );
                });
        }

        maybe_listener
    }

    /// Allocate a host-side port to be assigned to a new host-initiated connection.
    fn allocate_local_port(&mut self) -> u32 {
        // TODO: this doesn't seem very space-efficient.
        // Mybe rewrite this to limit port range and use a bitmap?
        //

        loop {
            self.local_port_last = (self.local_port_last + 1) & !(1 << 31) | (1 << 30);
            if self.local_port_set.insert(self.local_port_last) {
                break;
            }
        }
        self.local_port_last
    }

    /// Mark a previously used host-side port as free.
    fn free_local_port(&mut self, port: u32) {
        self.local_port_set.remove(&port);
    }

    /// Handle a new connection request comming from our peer (the guest vsock driver).
    ///
    /// This will attempt to connect to a host-side Unix socket, expected to be listening at
    /// the file system path corresponing to the destination port. If successful, a new
    /// connection object will be created and added to the connection pool. On failure, a new
    /// RST packet will be scheduled for delivery to the guest.
    fn handle_peer_request_pkt(&mut self, pkt: &VsockPacket) {
        let port_path = format!("{}_{}", self.host_sock_path, pkt.dst_port());

        UnixStream::connect(port_path)
            .and_then(|stream| stream.set_nonblocking(true).map(|_| stream))
            .map_err(Error::UnixConnect)
            .and_then(|stream| {
                self.add_connection(
                    ConnMapKey {
                        local_port: pkt.dst_port(),
                        peer_port: pkt.src_port(),
                    },
                    MuxerConnection::new_peer_init(
                        stream,
                        uapi::VSOCK_HOST_CID,
                        self.cid,
                        pkt.dst_port(),
                        pkt.src_port(),
                        pkt.buf_alloc(),
                    ),
                )
            })
            .unwrap_or_else(|_| self.enq_rst(pkt.dst_port(), pkt.src_port()));
    }

    /// Perform an action that might mutate a connection's state.
    ///
    /// This is used as shorthand for repetitive tasks that need to be performed after a
    /// connection object mutates. E.g.
    /// - update the connection's epoll listener;
    /// - schedule the connection to be queried for RX data;
    /// - kill the connection if an unrecoverable error occurs.
    fn apply_conn_mutation<F>(&mut self, key: ConnMapKey, mut_fn: F)
    where
        F: FnOnce(&mut MuxerConnection),
    {
        if let Some(conn) = self.conn_map.get_mut(&key) {
            let had_rx = conn.has_pending_rx();
            let was_expiring = conn.will_expire();
            let prev_state = conn.state();

            mut_fn(conn);

            // If this is a host-initiated connection that has just become established, we'll have
            // to send an ack message to the host end.
            if prev_state == ConnState::LocalInit && conn.state() == ConnState::Established {
                conn.send_bytes(format!("OK {}\n", key.local_port).as_bytes())
                    .unwrap_or_else(|err| {
                        conn.kill();
                        warn!("vsock: unable to ack host connection: {:?}", err);
                    });
            }

            // If the connection wasn't previously scheduled for RX, add it to our RX queue.
            if !had_rx && conn.has_pending_rx() {
                self.rxq.push(MuxerRx::ConnRx(key));
            }

            // If the connection wasn't previously scheduled for termination, add it to the
            // kill queue.
            if !was_expiring && conn.will_expire() {
                // It's safe to unwrap here, since `conn.will_expire()` already guaranteed that
                // an `conn.expiry` is available.
                self.killq.push(key, conn.expiry().unwrap());
            }

            let fd = conn.as_raw_fd();
            let new_evset = conn.get_polled_evset();
            if new_evset.is_empty() {
                // If the connection no longer needs epoll notifications, remove its listener
                // from our list.
                self.remove_listener(fd);
                return;
            }
            if let Some(EpollListener::Connection { evset, .. }) = self.listener_map.get_mut(&fd) {
                if *evset != new_evset {
                    // If the set of events that the connection is interested in has changed,
                    // we need to update its epoll listener.
                    debug!(
                        "vsock: updating listener for (lp={}, pp={}): old={:?}, new={:?}",
                        key.local_port, key.peer_port, *evset, new_evset
                    );

                    *evset = new_evset;
                    self.epoll
                        .ctl(
                            ControlOperation::Modify,
                            fd,
                            &EpollEvent::new(new_evset, fd as u64),
                        )
                        .unwrap_or_else(|err| {
                            // This really shouldn't happen, like, ever. However, "famous last
                            // words" and all that, so let's just kill it with fire, and walk away.
                            self.kill_connection(key);
                            error!(
                                "vsock: error updating epoll listener for (lp={}, pp={}): {:?}",
                                key.local_port, key.peer_port, err
                            );
                        });
                }
            } else {
                // The connection had previously asked to be removed from the listener map (by
                // returning an empty event set via `get_polled_fd()`), but now wants back in.
                self.add_listener(
                    fd,
                    EpollListener::Connection {
                        key,
                        evset: new_evset,
                    },
                )
                .unwrap_or_else(|err| {
                    self.kill_connection(key);
                    error!(
                        "vsock: error updating epoll listener for (lp={}, pp={}): {:?}",
                        key.local_port, key.peer_port, err
                    );
                });
            }
        }
    }

    /// Check if any connections have timed out, and if so, schedule them for immediate
    /// termination.
    fn sweep_killq(&mut self) {
        while let Some(key) = self.killq.pop() {
            // Connections don't get removed from the kill queue when their kill timer is
            // disarmed, since that would be a costly operation. This means we must check if
            // the connection has indeed expired, prior to killing it.
            let mut kill = false;
            self.conn_map
                .entry(key)
                .and_modify(|conn| kill = conn.has_expired());
            if kill {
                self.kill_connection(key);
            }
        }

        if self.killq.is_empty() && !self.killq.is_synced() {
            self.killq = MuxerKillQ::from_conn_map(&self.conn_map);
            // If we've just re-created the kill queue, we can sweep it again; maybe there's
            // more to kill.
            self.sweep_killq();
        }
    }

    /// Enqueue an RST packet into `self.rxq`.
    ///
    /// Enqueue errors aren't propagated up the call chain, since there is nothing we can do to
    /// handle them. We do, however, log a warning, since not being able to enqueue an RST
    /// packet means we have to drop it, which is not normal operation.
    fn enq_rst(&mut self, local_port: u32, peer_port: u32) {
        let pushed = self.rxq.push(MuxerRx::RstPkt {
            local_port,
            peer_port,
        });
        if !pushed {
            warn!(
                "vsock: muxer.rxq full; dropping RST packet for lp={}, pp={}",
                local_port, peer_port
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::ops::Drop;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};

    use super::super::super::csm::defs as csm_defs;
    use super::super::super::tests::TestContext as VsockTestContext;
    use super::*;

    use crate::virtio::vsock::device::RXQ_INDEX;

    const PEER_CID: u64 = 3;
    const PEER_BUF_ALLOC: u32 = 64 * 1024;

    struct MuxerTestContext {
        _vsock_test_ctx: VsockTestContext,
        pkt: VsockPacket,
        muxer: VsockMuxer,
    }

    impl Drop for MuxerTestContext {
        fn drop(&mut self) {
            std::fs::remove_file(self.muxer.host_sock_path.as_str()).unwrap();
        }
    }

    impl MuxerTestContext {
        fn new(name: &str) -> Self {
            let vsock_test_ctx = VsockTestContext::new();
            let mut handler_ctx = vsock_test_ctx.create_event_handler_context();
            let pkt = VsockPacket::from_rx_virtq_head(
                &handler_ctx.device.queues[RXQ_INDEX]
                    .pop(&vsock_test_ctx.mem)
                    .unwrap(),
            )
            .unwrap();
            let uds_path = format!("test_vsock_{}.sock", name);
            let muxer = VsockMuxer::new(PEER_CID, uds_path).unwrap();

            Self {
                _vsock_test_ctx: vsock_test_ctx,
                pkt,
                muxer,
            }
        }

        fn init_pkt(&mut self, local_port: u32, peer_port: u32, op: u16) -> &mut VsockPacket {
            for b in self.pkt.hdr_mut() {
                *b = 0;
            }
            self.pkt
                .set_type(uapi::VSOCK_TYPE_STREAM)
                .set_src_cid(PEER_CID)
                .set_dst_cid(uapi::VSOCK_HOST_CID)
                .set_src_port(peer_port)
                .set_dst_port(local_port)
                .set_op(op)
                .set_buf_alloc(PEER_BUF_ALLOC)
        }

        fn init_data_pkt(
            &mut self,
            local_port: u32,
            peer_port: u32,
            data: &[u8],
        ) -> &mut VsockPacket {
            assert!(data.len() <= self.pkt.buf().unwrap().len() as usize);
            self.init_pkt(local_port, peer_port, uapi::VSOCK_OP_RW)
                .set_len(data.len() as u32);
            self.pkt.buf_mut().unwrap()[..data.len()].copy_from_slice(data);
            &mut self.pkt
        }

        fn send(&mut self) {
            self.muxer.send_pkt(&self.pkt).unwrap();
        }

        fn recv(&mut self) {
            self.muxer.recv_pkt(&mut self.pkt).unwrap();
        }

        fn notify_muxer(&mut self) {
            self.muxer.notify(EventSet::IN);
        }

        fn count_epoll_listeners(&self) -> (usize, usize) {
            let mut local_lsn_count = 0usize;
            let mut conn_lsn_count = 0usize;
            for key in self.muxer.listener_map.values() {
                match key {
                    EpollListener::LocalStream(_) => local_lsn_count += 1,
                    EpollListener::Connection { .. } => conn_lsn_count += 1,
                    _ => (),
                };
            }
            (local_lsn_count, conn_lsn_count)
        }

        fn create_local_listener(&self, port: u32) -> LocalListener {
            LocalListener::new(format!("{}_{}", self.muxer.host_sock_path, port))
        }

        fn local_connect(&mut self, peer_port: u32) -> (UnixStream, u32) {
            let (init_local_lsn_count, init_conn_lsn_count) = self.count_epoll_listeners();

            let mut stream = UnixStream::connect(self.muxer.host_sock_path.clone()).unwrap();
            stream.set_nonblocking(true).unwrap();
            // The muxer would now get notified of a new connection having arrived at its Unix
            // socket, so it can accept it.
            self.notify_muxer();

            // Just after having accepted a new local connection, the muxer should've added a new
            // `LocalStream` listener to its `listener_map`.
            let (local_lsn_count, _) = self.count_epoll_listeners();
            assert_eq!(local_lsn_count, init_local_lsn_count + 1);

            let buf = format!("CONNECT {}\n", peer_port);
            stream.write_all(buf.as_bytes()).unwrap();
            // The muxer would now get notified that data is available for reading from the locally
            // initiated connection.
            self.notify_muxer();

            // Successfully reading and parsing the connection request should have removed the
            // LocalStream epoll listener and added a Connection epoll listener.
            let (local_lsn_count, conn_lsn_count) = self.count_epoll_listeners();
            assert_eq!(local_lsn_count, init_local_lsn_count);
            assert_eq!(conn_lsn_count, init_conn_lsn_count + 1);

            // A LocalInit connection should've been added to the muxer connection map.  A new
            // local port should also have been allocated for the new LocalInit connection.
            let local_port = self.muxer.local_port_last;
            let key = ConnMapKey {
                local_port,
                peer_port,
            };
            assert!(self.muxer.conn_map.contains_key(&key));
            assert!(self.muxer.local_port_set.contains(&local_port));

            // A connection request for the peer should now be available from the muxer.
            assert!(self.muxer.has_pending_rx());
            self.recv();
            assert_eq!(self.pkt.op(), uapi::VSOCK_OP_REQUEST);
            assert_eq!(self.pkt.dst_port(), peer_port);
            assert_eq!(self.pkt.src_port(), local_port);

            self.init_pkt(local_port, peer_port, uapi::VSOCK_OP_RESPONSE);
            self.send();

            let mut buf = vec![0u8; 32];
            let len = stream.read(&mut buf[..]).unwrap();
            assert_eq!(&buf[..len], format!("OK {}\n", local_port).as_bytes());

            (stream, local_port)
        }
    }

    struct LocalListener {
        path: PathBuf,
        sock: UnixListener,
    }
    impl LocalListener {
        fn new<P: AsRef<Path> + Clone>(path: P) -> Self {
            let path_buf = path.clone().as_ref().to_path_buf();
            let sock = UnixListener::bind(path).unwrap();
            sock.set_nonblocking(true).unwrap();
            Self {
                path: path_buf,
                sock,
            }
        }
        fn accept(&mut self) -> UnixStream {
            let (stream, _) = self.sock.accept().unwrap();
            stream.set_nonblocking(true).unwrap();
            stream
        }
    }
    impl Drop for LocalListener {
        fn drop(&mut self) {
            std::fs::remove_file(&self.path).unwrap();
        }
    }

    #[test]
    fn test_muxer_epoll_listener() {
        let ctx = MuxerTestContext::new("muxer_epoll_listener");
        assert_eq!(ctx.muxer.as_raw_fd(), ctx.muxer.epoll.as_raw_fd());
        assert_eq!(ctx.muxer.get_polled_evset(), EventSet::IN);
    }

    #[test]
    fn test_bad_peer_pkt() {
        const LOCAL_PORT: u32 = 1026;
        const PEER_PORT: u32 = 1025;
        const SOCK_DGRAM: u16 = 2;

        let mut ctx = MuxerTestContext::new("bad_peer_pkt");
        ctx.init_pkt(LOCAL_PORT, PEER_PORT, uapi::VSOCK_OP_REQUEST)
            .set_type(SOCK_DGRAM);
        ctx.send();

        // The guest sent a SOCK_DGRAM packet. Per the vsock spec, we need to reply with an RST
        // packet, since vsock only supports stream sockets.
        assert!(ctx.muxer.has_pending_rx());
        ctx.recv();
        assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RST);
        assert_eq!(ctx.pkt.src_cid(), uapi::VSOCK_HOST_CID);
        assert_eq!(ctx.pkt.dst_cid(), PEER_CID);
        assert_eq!(ctx.pkt.src_port(), LOCAL_PORT);
        assert_eq!(ctx.pkt.dst_port(), PEER_PORT);

        // Any orphan (i.e. without a connection), non-RST packet, should be replied to with an
        // RST.
        let bad_ops = [
            uapi::VSOCK_OP_RESPONSE,
            uapi::VSOCK_OP_CREDIT_REQUEST,
            uapi::VSOCK_OP_CREDIT_UPDATE,
            uapi::VSOCK_OP_SHUTDOWN,
            uapi::VSOCK_OP_RW,
        ];
        for op in bad_ops.iter() {
            ctx.init_pkt(LOCAL_PORT, PEER_PORT, *op);
            ctx.send();
            assert!(ctx.muxer.has_pending_rx());
            ctx.recv();
            assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RST);
            assert_eq!(ctx.pkt.src_port(), LOCAL_PORT);
            assert_eq!(ctx.pkt.dst_port(), PEER_PORT);
        }

        // Any packet addressed to anything other than VSOCK_VHOST_CID should get dropped.
        assert!(!ctx.muxer.has_pending_rx());
        ctx.init_pkt(LOCAL_PORT, PEER_PORT, uapi::VSOCK_OP_REQUEST)
            .set_dst_cid(uapi::VSOCK_HOST_CID + 1);
        ctx.send();
        assert!(!ctx.muxer.has_pending_rx());
    }

    #[test]
    fn test_peer_connection() {
        const LOCAL_PORT: u32 = 1026;
        const PEER_PORT: u32 = 1025;

        let mut ctx = MuxerTestContext::new("peer_connection");

        // Test peer connection refused.
        ctx.init_pkt(LOCAL_PORT, PEER_PORT, uapi::VSOCK_OP_REQUEST);
        ctx.send();
        ctx.recv();
        assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RST);
        assert_eq!(ctx.pkt.len(), 0);
        assert_eq!(ctx.pkt.src_cid(), uapi::VSOCK_HOST_CID);
        assert_eq!(ctx.pkt.dst_cid(), PEER_CID);
        assert_eq!(ctx.pkt.src_port(), LOCAL_PORT);
        assert_eq!(ctx.pkt.dst_port(), PEER_PORT);

        // Test peer connection accepted.
        let mut listener = ctx.create_local_listener(LOCAL_PORT);
        ctx.init_pkt(LOCAL_PORT, PEER_PORT, uapi::VSOCK_OP_REQUEST);
        ctx.send();
        assert_eq!(ctx.muxer.conn_map.len(), 1);
        let mut stream = listener.accept();
        ctx.recv();
        assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RESPONSE);
        assert_eq!(ctx.pkt.len(), 0);
        assert_eq!(ctx.pkt.src_cid(), uapi::VSOCK_HOST_CID);
        assert_eq!(ctx.pkt.dst_cid(), PEER_CID);
        assert_eq!(ctx.pkt.src_port(), LOCAL_PORT);
        assert_eq!(ctx.pkt.dst_port(), PEER_PORT);
        let key = ConnMapKey {
            local_port: LOCAL_PORT,
            peer_port: PEER_PORT,
        };
        assert!(ctx.muxer.conn_map.contains_key(&key));

        // Test guest -> host data flow.
        let data = [1, 2, 3, 4];
        ctx.init_data_pkt(LOCAL_PORT, PEER_PORT, &data);
        ctx.send();
        let mut buf = vec![0; data.len()];
        stream.read_exact(buf.as_mut_slice()).unwrap();
        assert_eq!(buf.as_slice(), data);

        // Test host -> guest data flow.
        let data = [5u8, 6, 7, 8];
        stream.write_all(&data).unwrap();

        // When data is available on the local stream, an EPOLLIN event would normally be delivered
        // to the muxer's nested epoll FD. For testing only, we can fake that event notification
        // here.
        ctx.notify_muxer();
        // After being notified, the muxer should've figured out that RX data was available for one
        // of its connections, so it should now be reporting that it can fill in an RX packet.
        assert!(ctx.muxer.has_pending_rx());
        ctx.recv();
        assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RW);
        assert_eq!(ctx.pkt.buf().unwrap()[..data.len()], data);
        assert_eq!(ctx.pkt.src_port(), LOCAL_PORT);
        assert_eq!(ctx.pkt.dst_port(), PEER_PORT);

        assert!(!ctx.muxer.has_pending_rx());
    }

    #[test]
    fn test_local_connection() {
        let mut ctx = MuxerTestContext::new("local_connection");
        let peer_port = 1025;
        let (mut stream, local_port) = ctx.local_connect(peer_port);

        // Test guest -> host data flow.
        let data = [1, 2, 3, 4];
        ctx.init_data_pkt(local_port, peer_port, &data);
        ctx.send();

        let mut buf = vec![0u8; data.len()];
        stream.read_exact(buf.as_mut_slice()).unwrap();
        assert_eq!(buf.as_slice(), &data);

        // Test host -> guest data flow.
        let data = [5, 6, 7, 8];
        stream.write_all(&data).unwrap();
        ctx.notify_muxer();

        assert!(ctx.muxer.has_pending_rx());
        ctx.recv();
        assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RW);
        assert_eq!(ctx.pkt.src_port(), local_port);
        assert_eq!(ctx.pkt.dst_port(), peer_port);
        assert_eq!(ctx.pkt.buf().unwrap()[..data.len()], data);
    }

    #[test]
    fn test_local_close() {
        let peer_port = 1025;
        let mut ctx = MuxerTestContext::new("local_close");
        let local_port;
        {
            let (_stream, local_port_) = ctx.local_connect(peer_port);
            local_port = local_port_;
        }
        // Local var `_stream` was now dropped, thus closing the local stream. After the muxer gets
        // notified via EPOLLIN, it should attempt to gracefully shutdown the connection, issuing a
        // VSOCK_OP_SHUTDOWN with both no-more-send and no-more-recv indications set.
        ctx.notify_muxer();
        assert!(ctx.muxer.has_pending_rx());
        ctx.recv();
        assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_SHUTDOWN);
        assert_ne!(ctx.pkt.flags() & uapi::VSOCK_FLAGS_SHUTDOWN_SEND, 0);
        assert_ne!(ctx.pkt.flags() & uapi::VSOCK_FLAGS_SHUTDOWN_RCV, 0);
        assert_eq!(ctx.pkt.src_port(), local_port);
        assert_eq!(ctx.pkt.dst_port(), peer_port);

        // The connection should get removed (and its local port freed), after the peer replies
        // with an RST.
        ctx.init_pkt(local_port, peer_port, uapi::VSOCK_OP_RST);
        ctx.send();
        let key = ConnMapKey {
            local_port,
            peer_port,
        };
        assert!(!ctx.muxer.conn_map.contains_key(&key));
        assert!(!ctx.muxer.local_port_set.contains(&local_port));
    }

    #[test]
    fn test_peer_close() {
        let peer_port = 1025;
        let local_port = 1026;
        let mut ctx = MuxerTestContext::new("peer_close");

        let mut sock = ctx.create_local_listener(local_port);
        ctx.init_pkt(local_port, peer_port, uapi::VSOCK_OP_REQUEST);
        ctx.send();
        let mut stream = sock.accept();

        assert!(ctx.muxer.has_pending_rx());
        ctx.recv();
        assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RESPONSE);
        assert_eq!(ctx.pkt.src_port(), local_port);
        assert_eq!(ctx.pkt.dst_port(), peer_port);
        let key = ConnMapKey {
            local_port,
            peer_port,
        };
        assert!(ctx.muxer.conn_map.contains_key(&key));

        // Emulate a full shutdown from the peer (no-more-send + no-more-recv).
        ctx.init_pkt(local_port, peer_port, uapi::VSOCK_OP_SHUTDOWN)
            .set_flag(uapi::VSOCK_FLAGS_SHUTDOWN_SEND)
            .set_flag(uapi::VSOCK_FLAGS_SHUTDOWN_RCV);
        ctx.send();

        // Now, the muxer should remove the connection from its map, and reply with an RST.
        assert!(ctx.muxer.has_pending_rx());
        ctx.recv();
        assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RST);
        assert_eq!(ctx.pkt.src_port(), local_port);
        assert_eq!(ctx.pkt.dst_port(), peer_port);
        let key = ConnMapKey {
            local_port,
            peer_port,
        };
        assert!(!ctx.muxer.conn_map.contains_key(&key));

        // The muxer should also drop / close the local Unix socket for this connection.
        let mut buf = vec![0u8; 16];
        assert_eq!(stream.read(buf.as_mut_slice()).unwrap(), 0);
    }

    #[test]
    fn test_muxer_rxq() {
        let mut ctx = MuxerTestContext::new("muxer_rxq");
        let local_port = 1026;
        let peer_port_first = 1025;
        let mut listener = ctx.create_local_listener(local_port);
        let mut streams: Vec<UnixStream> = Vec::new();

        for peer_port in peer_port_first..peer_port_first + defs::MUXER_RXQ_SIZE {
            ctx.init_pkt(local_port, peer_port as u32, uapi::VSOCK_OP_REQUEST);
            ctx.send();
            streams.push(listener.accept());
        }

        // The muxer RX queue should now be full (with connection reponses), but still
        // synchronized.
        assert!(ctx.muxer.rxq.is_synced());

        // One more queued reply should desync the RX queue.
        ctx.init_pkt(
            local_port,
            (peer_port_first + defs::MUXER_RXQ_SIZE) as u32,
            uapi::VSOCK_OP_REQUEST,
        );
        ctx.send();
        assert!(!ctx.muxer.rxq.is_synced());

        // With an out-of-sync queue, an RST should evict any non-RST packet from the queue, and
        // take its place. We'll check that by making sure that the last packet popped from the
        // queue is an RST.
        ctx.init_pkt(
            local_port + 1,
            peer_port_first as u32,
            uapi::VSOCK_OP_REQUEST,
        );
        ctx.send();

        for peer_port in peer_port_first..peer_port_first + defs::MUXER_RXQ_SIZE - 1 {
            ctx.recv();
            assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RESPONSE);
            // The response order should hold. The evicted response should have been the last
            // enqueued.
            assert_eq!(ctx.pkt.dst_port(), peer_port as u32);
        }
        // There should be one more packet in the queue: the RST.
        assert_eq!(ctx.muxer.rxq.len(), 1);
        ctx.recv();
        assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RST);

        // The queue should now be empty, but out-of-sync, so the muxer should report it has some
        // pending RX.
        assert!(ctx.muxer.rxq.is_empty());
        assert!(!ctx.muxer.rxq.is_synced());
        assert!(ctx.muxer.has_pending_rx());

        // The next recv should sync the queue back up. It should also yield one of the two
        // responses that are still left:
        // - the one that desynchronized the queue; and
        // - the one that got evicted by the RST.
        ctx.recv();
        assert!(ctx.muxer.rxq.is_synced());
        assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RESPONSE);

        assert!(ctx.muxer.has_pending_rx());
        ctx.recv();
        assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RESPONSE);
    }

    #[test]
    fn test_muxer_killq() {
        let mut ctx = MuxerTestContext::new("muxer_killq");
        let local_port = 1026;
        let peer_port_first = 1025;
        let peer_port_last = peer_port_first + defs::MUXER_KILLQ_SIZE;
        let mut listener = ctx.create_local_listener(local_port);

        for peer_port in peer_port_first..=peer_port_last {
            ctx.init_pkt(local_port, peer_port as u32, uapi::VSOCK_OP_REQUEST);
            ctx.send();
            ctx.notify_muxer();
            ctx.recv();
            assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RESPONSE);
            assert_eq!(ctx.pkt.src_port(), local_port);
            assert_eq!(ctx.pkt.dst_port(), peer_port as u32);
            {
                let _stream = listener.accept();
            }
            ctx.notify_muxer();
            ctx.recv();
            assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_SHUTDOWN);
            assert_eq!(ctx.pkt.src_port(), local_port);
            assert_eq!(ctx.pkt.dst_port(), peer_port as u32);
            // The kill queue should be synchronized, up until the `defs::MUXER_KILLQ_SIZE`th
            // connection we schedule for termination.
            assert_eq!(
                ctx.muxer.killq.is_synced(),
                peer_port < peer_port_first + defs::MUXER_KILLQ_SIZE
            );
        }

        assert!(!ctx.muxer.killq.is_synced());
        assert!(!ctx.muxer.has_pending_rx());

        // Wait for the kill timers to expire.
        std::thread::sleep(std::time::Duration::from_millis(
            csm_defs::CONN_SHUTDOWN_TIMEOUT_MS,
        ));

        // Trigger a kill queue sweep, by requesting a new connection.
        ctx.init_pkt(
            local_port,
            peer_port_last as u32 + 1,
            uapi::VSOCK_OP_REQUEST,
        );
        ctx.send();

        // After sweeping the kill queue, it should now be synced (assuming the RX queue is larger
        // than the kill queue, since an RST packet will be queued for each killed connection).
        assert!(ctx.muxer.killq.is_synced());
        assert!(ctx.muxer.has_pending_rx());
        // There should be `defs::MUXER_KILLQ_SIZE` RSTs in the RX queue, from terminating the
        // dying connections in the recent killq sweep.
        for _p in peer_port_first..peer_port_last {
            ctx.recv();
            assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RST);
            assert_eq!(ctx.pkt.src_port(), local_port);
        }

        // There should be one more packet in the RX queue: the connection response our request
        // that triggered the kill queue sweep.
        ctx.recv();
        assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RESPONSE);
        assert_eq!(ctx.pkt.dst_port(), peer_port_last as u32 + 1);

        assert!(!ctx.muxer.has_pending_rx());
    }
}
