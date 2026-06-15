// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! UFFD block backend for on-demand page fault handling via an external server.
//!
//! Supports zero-copy: the server responds with blob fds that are MAP_FIXED directly
//! over the faulting region, avoiding any data copy into guest memory.
//!
//! For servers that do not support this protocol, the socket simply receives
//! no messages and the event handler becomes a no-op with no overhead.

use std::fmt;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::FileExt;
use std::os::unix::net::UnixStream;

use libc::MAP_FAILED;
use userfaultfd::Uffd;
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

use crate::logger::{info, warn};
use crate::persist::GuestRegionUffdMapping;

const UFFD_MAGIC: u32 = 0x5546_4644;
const UFFD_PROTOCOL_VERSION: u16 = 1;
const MSG_HANDSHAKE: u16 = 0x01;
const MSG_PAGE_RESPONSE: u16 = 0x81;
const HANDSHAKE_FLAG_COPY: u8 = 0x01;
const HEADER_SIZE: usize = 20;
const REGION_SIZE: usize = 40;
const RANGE_SIZE: usize = 24;

/// Fault handling policy for UFFD.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum FaultPolicy {
    /// Zero-copy mode: send fd to client, let client do mmap.
    #[default]
    Zerocopy = 0,
    /// Copy mode: use UFFDIO_COPY to copy data directly.
    Copy = 1,
}

/// VMA region information for userfaultfd registration.
#[derive(Debug, Clone)]
pub struct VmaRegion {
    /// Base host virtual address of this region.
    pub base_host_virt_addr: u64,
    /// Size of the region in bytes.
    pub size: usize,
    /// Offset in the backend.
    pub offset: u64,
    /// Page size for this region.
    pub page_size: usize,
    /// Memory protection flags.
    pub prot: i32,
    /// Mmap flags.
    /// Note: `MAP_FIXED` is added by the handler when doing mmap.
    pub flags: i32,
}

/// A single range within a page fault response.
#[derive(Debug)]
pub struct BlobRange {
    /// Offset within the VMA region.
    pub block_offset: u64,
    /// Offset within the blob file.
    pub blob_offset: u64,
    /// Length of the range in bytes.
    pub len: usize,
}

#[derive(Debug, Clone, Copy)]
struct Header {
    magic: u32,
    flags: u16,
    msg_type: u16,
    cookie: u64,
    len: u32,
}

impl Header {
    fn new(msg_type: u16, payload_len: u32) -> Self {
        Self {
            magic: UFFD_MAGIC,
            flags: 0,
            msg_type,
            cookie: 0,
            len: payload_len,
        }
    }

    fn to_bytes(self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(&self.magic.to_le_bytes());
        buf[4..6].copy_from_slice(&self.flags.to_le_bytes());
        buf[6..8].copy_from_slice(&self.msg_type.to_le_bytes());
        buf[8..16].copy_from_slice(&self.cookie.to_le_bytes());
        buf[16..20].copy_from_slice(&self.len.to_le_bytes());
        buf
    }

    fn from_bytes(buf: &[u8; HEADER_SIZE]) -> Self {
        Self {
            magic: u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            flags: u16::from_le_bytes(buf[4..6].try_into().unwrap()),
            msg_type: u16::from_le_bytes(buf[6..8].try_into().unwrap()),
            cookie: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            len: u32::from_le_bytes(buf[16..20].try_into().unwrap()),
        }
    }

    fn validate(&self, expected_msg_type: u16) -> io::Result<()> {
        if self.magic != UFFD_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "invalid UFFD magic 0x{:08x}, expected 0x{:08x}",
                    self.magic, UFFD_MAGIC
                ),
            ));
        }
        if self.msg_type != expected_msg_type {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected UFFD message type 0x{:04x}", self.msg_type),
            ));
        }
        Ok(())
    }
}

fn encode_handshake(policy: FaultPolicy, regions: &[VmaRegion]) -> io::Result<Vec<u8>> {
    let payload_len = 4usize
        .checked_add(regions.len().checked_mul(REGION_SIZE).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "too many UFFD regions")
        })?)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "UFFD payload too large"))?;
    let payload_len_u32 = u32::try_from(payload_len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "UFFD payload too large"))?;

    let mut flags = 0u8;
    if policy == FaultPolicy::Copy {
        flags |= HANDSHAKE_FLAG_COPY;
    }

    let region_count = u8::try_from(regions.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many UFFD regions"))?;

    let mut buf = Vec::with_capacity(HEADER_SIZE + payload_len);
    buf.extend_from_slice(&Header::new(MSG_HANDSHAKE, payload_len_u32).to_bytes());
    buf.extend_from_slice(&UFFD_PROTOCOL_VERSION.to_le_bytes());
    buf.push(flags);
    buf.push(region_count);

    for region in regions {
        buf.extend_from_slice(&region.base_host_virt_addr.to_le_bytes());
        buf.extend_from_slice(&(region.size as u64).to_le_bytes());
        buf.extend_from_slice(&region.offset.to_le_bytes());
        buf.extend_from_slice(&(region.page_size as u64).to_le_bytes());
        buf.extend_from_slice(&region.prot.to_le_bytes());
        buf.extend_from_slice(&region.flags.to_le_bytes());
    }

    Ok(buf)
}

fn decode_page_response(payload: &[u8]) -> io::Result<Vec<BlobRange>> {
    if payload.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "UFFD page response payload too short",
        ));
    }

    let range_count = u32::from_le_bytes(payload[0..4].try_into().unwrap()) as usize;
    let expected_len = 4usize
        .checked_add(range_count.checked_mul(RANGE_SIZE).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "too many UFFD ranges")
        })?)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "UFFD payload too large"))?;
    if payload.len() != expected_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "invalid UFFD page response payload length {}, expected {}",
                payload.len(),
                expected_len
            ),
        ));
    }

    let mut ranges = Vec::with_capacity(range_count);
    let mut offset = 4;
    for _ in 0..range_count {
        let block_offset = u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
        let blob_offset = u64::from_le_bytes(payload[offset + 8..offset + 16].try_into().unwrap());
        let len = u64::from_le_bytes(payload[offset + 16..offset + 24].try_into().unwrap());
        ranges.push(BlobRange {
            block_offset,
            blob_offset,
            len: usize::try_from(len).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "UFFD range length too large")
            })?,
        });
        offset += RANGE_SIZE;
    }

    Ok(ranges)
}

/// Poll timeout for legacy handshake fallback (milliseconds).
const LEGACY_HANDSHAKE_POLL_TIMEOUT_MS: i32 = 100;

const RECV_BUF_SIZE: usize = 4096;
const MAX_FDS: usize = 16;

/// Inline UFFD block backend that connects to an external UFFD server via
/// Unix socket for zero-copy on-demand page resolution and fault recovery.
///
/// Two-phase initialization:
/// 1. `UffdBlock::new(sock_path, policy)` — connects to the server.
/// 2. `block.handshake(uffd, regions, policy)` or
///    `block.handshake_compat(uffd, mappings, prot, flags, fallback)` — performs
///    protocol handshake.
pub struct UffdBlock {
    sock_path: String,
    sock: UnixStream,
    policy: FaultPolicy,
    uffd: Option<Uffd>,
    regions: Vec<VmaRegion>,
}

impl fmt::Debug for UffdBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UffdBlock")
            .field("sock_path", &self.sock_path)
            .field("sock_fd", &self.sock.as_raw_fd())
            .field("policy", &self.policy)
            .field("uffd_fd", &self.uffd.as_ref().map(|u| u.as_raw_fd()))
            .field("regions", &self.regions)
            .finish()
    }
}

impl UffdBlock {
    /// Create a new UffdBlock, connecting to the server at `sock_path`.
    /// Call [`handshake`] or [`handshake_compat`] to complete initialization.
    pub fn new(sock_path: &str, policy: FaultPolicy) -> io::Result<Self> {
        let sock = UnixStream::connect(sock_path)?;
        Ok(Self {
            sock_path: sock_path.to_string(),
            sock,
            policy,
            uffd: None,
            regions: Vec::new(),
        })
    }

    /// Perform a binary protocol handshake with the UFFD server.
    pub fn handshake(&mut self, uffd: Uffd, regions: Vec<VmaRegion>) -> io::Result<()> {
        let request = encode_handshake(self.policy, &regions)?;

        self.sock
            .send_with_fd(request.as_slice(), uffd.as_raw_fd())?;
        self.sock.set_nonblocking(true)?;

        self.uffd = Some(uffd);
        self.regions = regions;
        Ok(())
    }

    /// Perform a legacy handshake: sends a raw `Vec<GuestRegionUffdMapping>`
    /// JSON array, compatible with the stock Firecracker snapshot uffd handler.
    ///
    /// If `fallback` is true and the server closes the connection after
    /// receiving the legacy format (indicating it does not support it),
    /// this method reconnects and retries with the binary protocol.
    pub fn handshake_compat(
        &mut self,
        uffd: Uffd,
        mappings: Vec<GuestRegionUffdMapping>,
        prot: i32,
        flags: i32,
        fallback: bool,
    ) -> io::Result<()> {
        #[allow(deprecated)]
        let regions: Vec<VmaRegion> = mappings
            .iter()
            .map(|m| VmaRegion {
                base_host_virt_addr: m.base_host_virt_addr,
                size: m.size,
                offset: m.offset,
                page_size: m.page_size,
                prot,
                flags,
            })
            .collect();

        let json_data = serde_json::to_string(&mappings)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        self.sock.send_with_fd(
            json_data.as_bytes(),
            // In the happy case we can close the fd since the other process has it open and is
            // using it to serve us pages.
            //
            // The problem is that if other process crashes/exits, firecracker guest memory
            // will simply revert to anon-mem behavior which would lead to silent errors and
            // undefined behavior.
            //
            // To tackle this scenario, the page fault handler can notify Firecracker of any
            // crashes/exits. There is no need for Firecracker to explicitly send its process ID.
            // The external process can obtain Firecracker's PID by calling `getsockopt` with
            // `libc::SO_PEERCRED` option like so:
            //
            // let mut val = libc::ucred { pid: 0, gid: 0, uid: 0 };
            // let mut ucred_size: u32 = mem::size_of::<libc::ucred>() as u32;
            // libc::getsockopt(
            //      socket.as_raw_fd(),
            //      libc::SOL_SOCKET,
            //      libc::SO_PEERCRED,
            //      &mut val as *mut _ as *mut _,
            //      &mut ucred_size as *mut libc::socklen_t,
            // );
            //
            // Per this linux man page: https://man7.org/linux/man-pages/man7/unix.7.html,
            // `SO_PEERCRED` returns the credentials (PID, UID and GID) of the peer process
            // connected to this socket. The returned credentials are those that were in effect
            // at the time of the `connect` call.
            //
            // Moreover, Firecracker holds a copy of the UFFD fd as well, so that even if the
            // page fault handler process does not tear down Firecracker when necessary, the
            // uffd will still be alive but with no one to serve faults, leading to guest freeze.
            uffd.as_raw_fd(),
        )?;

        // We prevent Rust from closing the socket file descriptor to avoid a potential race
        // condition between the mappings message and the connection shutdown. If the latter
        // arrives at the UFFD handler first, the handler never sees the mappings.
        // This is achieved by holding the UnixStream in self.sock for the lifetime of UffdBlock.

        self.sock.set_nonblocking(true)?;

        if fallback {
            // Wait briefly for the server to process and potentially reject.
            // SAFETY: pollfd is a valid struct pointing to the socket fd.
            let mut pfd = libc::pollfd {
                fd: self.sock.as_raw_fd(),
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            };
            // SAFETY: pfd is a valid stack-allocated pollfd struct.
            let poll_ret = unsafe { libc::poll(&mut pfd, 1, LEGACY_HANDSHAKE_POLL_TIMEOUT_MS) };
            if poll_ret < 0 {
                return Err(io::Error::last_os_error());
            }

            // Probe whether the server closed the connection.
            let mut probe = [0u8; 1];
            // SAFETY: valid fd, valid buffer pointer and length.
            let peek_ret = unsafe {
                libc::recv(
                    self.sock.as_raw_fd(),
                    probe.as_mut_ptr().cast(),
                    probe.len(),
                    libc::MSG_PEEK,
                )
            };
            match peek_ret {
                -1 if io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock => {}
                n if n > 0 => {}
                _ => {
                    // Ok(0) = server closed, Err(_) = connection error.
                    // Legacy format not supported — reconnect with formal protocol.
                    self.sock.shutdown(std::net::Shutdown::Both)?;
                    info!("UffdBlock: legacy handshake rejected, retrying with binary protocol");
                    self.sock = UnixStream::connect(&self.sock_path)?;
                    return self.handshake(uffd, regions);
                }
            }
        }

        self.uffd = Some(uffd);
        self.regions = regions;
        Ok(())
    }

    /// Handle a page fault response by mmapping blob fds in a zero-copy manner.
    pub fn handle_response(&self) -> io::Result<bool> {
        let Some((ranges, received_fds)) = self.try_recv_page_response()? else {
            return Ok(false);
        };

        if received_fds.len() != ranges.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "fd count {} != ranges count {}",
                    received_fds.len(),
                    ranges.len()
                ),
            ));
        }

        let uffd = self.uffd.as_ref().expect("handshake not called");

        for (range, file) in ranges.iter().zip(received_fds.iter()) {
            let region = self.regions.iter().find(|r| {
                range.block_offset >= r.offset && range.block_offset < r.offset + r.size as u64
            });
            let region = match region {
                Some(r) => r,
                None => {
                    warn!(
                        "UffdBlock: block_offset 0x{:x} not in any region",
                        range.block_offset
                    );
                    continue;
                }
            };

            let target_addr = region.base_host_virt_addr + (range.block_offset - region.offset);
            // SAFETY: We are calling mmap with a valid fd and checking the result.
            let map_addr = unsafe {
                libc::mmap(
                    target_addr as *mut _,
                    range.len,
                    region.prot,
                    region.flags | libc::MAP_FIXED,
                    file.as_raw_fd(),
                    range.blob_offset.cast_signed(),
                )
            };
            if map_addr == MAP_FAILED {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ENOMEM) {
                    warn!(
                        "UffdBlock: mmap ENOMEM at 0x{:x}, fallback to uffd copy",
                        target_addr
                    );
                    self.copy_fallback(file, target_addr, range.len, range.blob_offset)?;
                } else {
                    warn!("UffdBlock: mmap failed for 0x{:x}: {}", target_addr, err);
                }
                continue;
            }

            if let Err(e) = uffd.wake(target_addr as *mut _, range.len) {
                warn!(
                    "UffdBlock: failed to wake page at 0x{:x}: {}",
                    target_addr, e
                );
            }
        }

        Ok(true)
    }

    fn try_recv_page_response(&self) -> io::Result<Option<(Vec<BlobRange>, Vec<File>)>> {
        let mut data = [0u8; RECV_BUF_SIZE];
        let mut fds = [0i32; MAX_FDS];

        let iov = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: data.len(),
        };
        // SAFETY: iov points to a valid buffer, fds is a valid slice for receiving fds.
        let (bytes_read, fd_count) = unsafe { self.sock.recv_with_fds(&mut [iov], &mut fds) }
            .map_err(|e| io::Error::from_raw_os_error(e.errno()))?;

        // Take ownership of received fds so they are closed on any early return.
        // SAFETY: fds[0..fd_count] contain valid file descriptors received via sendfd.
        let received_fds: Vec<File> = fds[..fd_count]
            .iter()
            .map(|&fd| unsafe { File::from_raw_fd(fd) })
            .collect();

        if bytes_read == 0 {
            // connection closed
            return Ok(None);
        }

        let mut header_buf = [0u8; HEADER_SIZE];
        let header_bytes = bytes_read.min(HEADER_SIZE);
        header_buf[..header_bytes].copy_from_slice(&data[..header_bytes]);
        if header_bytes < HEADER_SIZE {
            self.recv_exact(&mut header_buf[header_bytes..])?;
        }

        let header = Header::from_bytes(&header_buf);
        header.validate(MSG_PAGE_RESPONSE)?;

        let payload_len = usize::try_from(header.len).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "UFFD payload length too large")
        })?;
        let mut payload = vec![0u8; payload_len];
        let initial_payload_bytes = bytes_read.saturating_sub(HEADER_SIZE).min(payload_len);
        if initial_payload_bytes > 0 {
            payload[..initial_payload_bytes].copy_from_slice(
                &data[HEADER_SIZE..HEADER_SIZE + initial_payload_bytes],
            );
        }
        if initial_payload_bytes < payload_len {
            self.recv_exact(&mut payload[initial_payload_bytes..])?;
        }

        let ranges = decode_page_response(&payload)?;
        Ok(Some((ranges, received_fds)))
    }

    fn recv_exact(&self, buf: &mut [u8]) -> io::Result<()> {
        let mut offset = 0;
        while offset < buf.len() {
            // SAFETY: The socket fd is valid and the remaining buffer is writable.
            let ret = unsafe {
                libc::recv(
                    self.sock.as_raw_fd(),
                    buf[offset..].as_mut_ptr().cast(),
                    buf.len() - offset,
                    0,
                )
            };
            if ret < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    std::thread::yield_now();
                    continue;
                }
                return Err(err);
            }
            if ret == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "UFFD peer closed while reading frame",
                ));
            }
            offset += ret.cast_unsigned();
        }
        Ok(())
    }

    /// Fallback when mmap hits vm.max_map_count: read from blob fd, then UFFDIO_COPY.
    ///
    /// NOTE: This uses an intermediate buffer + UFFDIO_COPY for Linux 5.10 compatibility.
    /// UFFDIO_CONTINUE (zero-copy: pread directly into guest memory + continue) requires
    /// Linux 5.13+. When all deployments upgrade to 5.13+, this can be optimized to:
    ///   1. pread() directly into target_addr (guest memory)
    ///   2. uffd.r#continue(target_addr, len, true) to resolve the fault
    ///
    /// Since this is a fallback path (triggered only when mmap hits vm.max_map_count),
    /// the extra copy is acceptable for now.
    fn copy_fallback(
        &self,
        file: &File,
        target_addr: u64,
        len: usize,
        blob_offset: u64,
    ) -> io::Result<()> {
        let mut buf = vec![0u8; len];
        file.read_at(&mut buf, blob_offset)?;

        let uffd = self.uffd.as_ref().expect("handshake not called");
        // TODO: Use UFFDIO_CONTINUE on Linux 5.13+.
        // SAFETY: buf contains valid data read from the blob fd.
        unsafe {
            uffd.copy(buf.as_ptr().cast(), target_addr as *mut _, len, true)
                .map_err(io::Error::other)?;
        }
        Ok(())
    }

    /// Returns the raw file descriptor of the underlying Unix socket.
    pub fn sock_fd(&self) -> RawFd {
        self.sock.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;

    use userfaultfd::UffdBuilder;
    use vmm_sys_util::tempdir::TempDir;

    use super::*;

    fn create_test_uffd() -> Uffd {
        UffdBuilder::new()
            .close_on_exec(true)
            .non_blocking(true)
            .create()
            .expect("Failed to create uffd")
    }

    fn test_vma_regions() -> Vec<VmaRegion> {
        vec![VmaRegion {
            base_host_virt_addr: 0x1000,
            size: 0x1000,
            offset: 0,
            page_size: 4096,
            prot: libc::PROT_READ,
            flags: libc::MAP_SHARED | libc::MAP_FIXED,
        }]
    }

    #[allow(deprecated)]
    fn test_legacy_mappings() -> Vec<GuestRegionUffdMapping> {
        vec![
            GuestRegionUffdMapping {
                base_host_virt_addr: 0,
                size: 0x100000,
                offset: 0,
                page_size: 4096,
                page_size_kib: 4,
            },
            GuestRegionUffdMapping {
                base_host_virt_addr: 0x100000,
                size: 0x200000,
                offset: 0,
                page_size: 2097152,
                page_size_kib: 2048,
            },
        ]
    }

    fn receive_handshake_payload(policy: FaultPolicy) -> (Vec<u8>, bool, RawFd, UffdBlock) {
        let tmp_dir = TempDir::new().unwrap();
        let sock_path = tmp_dir.as_path().join("test.sock");
        let sock_path_str = sock_path.to_str().unwrap().to_string();

        let listener = UnixListener::bind(&sock_path).unwrap();
        let regions = test_vma_regions();
        let uffd = create_test_uffd();
        let uffd_fd = uffd.as_raw_fd();

        let mut block = UffdBlock::new(&sock_path_str, policy).unwrap();

        let client_thread = {
            std::thread::spawn(move || {
                let block_ref = &mut block;
                block_ref.handshake(uffd, regions).unwrap();
                block
            })
        };

        let (stream, _) = listener.accept().unwrap();
        let mut buf = vec![0u8; 4096];
        let (bytes_read, file) = stream.recv_with_fd(&mut buf).unwrap();
        buf.truncate(bytes_read);

        (buf, file.is_some(), uffd_fd, client_thread.join().unwrap())
    }

    #[test]
    fn test_handshake() {
        let (buf, received_uffd_fd, uffd_fd, block) =
            receive_handshake_payload(FaultPolicy::Zerocopy);

        // Verify we received a valid binary HANDSHAKE frame.
        assert_eq!(buf.len(), HEADER_SIZE + 4 + REGION_SIZE);
        let header = Header::from_bytes(buf[..HEADER_SIZE].try_into().unwrap());
        assert_eq!(header.magic, UFFD_MAGIC);
        assert_eq!(header.flags, 0);
        assert_eq!(header.msg_type, MSG_HANDSHAKE);
        assert_eq!(header.cookie, 0);
        assert_eq!(header.len, u32::try_from(4 + REGION_SIZE).unwrap());

        let payload = &buf[HEADER_SIZE..];
        assert_eq!(
            u16::from_le_bytes(payload[0..2].try_into().unwrap()),
            UFFD_PROTOCOL_VERSION
        );
        assert_eq!(payload[2] & HANDSHAKE_FLAG_COPY, 0);
        assert_eq!(payload[3], 1);

        let region = &payload[4..4 + REGION_SIZE];
        assert_eq!(
            u64::from_le_bytes(region[0..8].try_into().unwrap()),
            0x1000
        );
        assert_eq!(
            u64::from_le_bytes(region[8..16].try_into().unwrap()),
            0x1000
        );
        assert_eq!(u64::from_le_bytes(region[16..24].try_into().unwrap()), 0);
        assert_eq!(
            u64::from_le_bytes(region[24..32].try_into().unwrap()),
            4096
        );
        assert_eq!(
            i32::from_le_bytes(region[32..36].try_into().unwrap()),
            libc::PROT_READ
        );
        assert_eq!(
            i32::from_le_bytes(region[36..40].try_into().unwrap()),
            libc::MAP_SHARED | libc::MAP_FIXED
        );

        // Verify we received a uffd fd
        assert!(received_uffd_fd);

        assert_eq!(block.uffd.as_ref().unwrap().as_raw_fd(), uffd_fd);
        assert_eq!(block.policy, FaultPolicy::Zerocopy);
    }

    #[test]
    fn test_copy_handshake_sets_copy_flag() {
        let (buf, received_uffd_fd, _uffd_fd, block) =
            receive_handshake_payload(FaultPolicy::Copy);

        assert!(received_uffd_fd);
        assert_eq!(block.policy, FaultPolicy::Copy);
        let payload = &buf[HEADER_SIZE..];
        assert_eq!(payload[2] & HANDSHAKE_FLAG_COPY, HANDSHAKE_FLAG_COPY);
    }

    #[test]
    fn test_handshake_compat() {
        let tmp_dir = TempDir::new().unwrap();
        let sock_path = tmp_dir.as_path().join("test.sock");
        let sock_path_str = sock_path.to_str().unwrap().to_string();

        let listener = UnixListener::bind(&sock_path).unwrap();
        let mappings = test_legacy_mappings();
        let uffd = create_test_uffd();

        let mut block = UffdBlock::new(&sock_path_str, FaultPolicy::Zerocopy).unwrap();

        let client_thread = {
            std::thread::spawn(move || {
                block
                    .handshake_compat(
                        uffd,
                        mappings,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_SHARED | libc::MAP_FIXED,
                        false,
                    )
                    .unwrap();
                block
            })
        };

        // Server side: accept and verify raw array
        let (stream, _) = listener.accept().unwrap();
        let mut buf = vec![0u8; 4096];
        let (bytes_read, file) = stream.recv_with_fd(&mut buf).unwrap();
        buf.truncate(bytes_read);

        // Legacy format: raw GuestRegionUffdMapping array
        let received: Vec<GuestRegionUffdMapping> =
            serde_json::from_slice(&buf).expect("Invalid JSON from legacy handshake");
        assert_eq!(received.len(), 2);
        assert_eq!(received[0].base_host_virt_addr, 0);
        assert_eq!(received[0].size, 0x100000);
        assert_eq!(received[0].page_size, 4096);
        assert_eq!(received[1].base_host_virt_addr, 0x100000);
        assert_eq!(received[1].size, 0x200000);
        assert_eq!(received[1].page_size, 2097152);
        assert!(file.is_some());

        let block = client_thread.join().unwrap();
        // Verify internal VmaRegion was created with provided prot/flags
        assert_eq!(block.regions[0].prot, libc::PROT_READ | libc::PROT_WRITE);
        assert_eq!(block.regions[0].flags, libc::MAP_SHARED | libc::MAP_FIXED);
    }

    #[test]
    fn test_handle_response_would_block() {
        let tmp_dir = TempDir::new().unwrap();
        let sock_path = tmp_dir.as_path().join("test.sock");
        let sock_path_str = sock_path.to_str().unwrap().to_string();

        let listener = UnixListener::bind(&sock_path).unwrap();
        let uffd = create_test_uffd();

        let mut block = UffdBlock::new(&sock_path_str, FaultPolicy::Zerocopy).unwrap();

        let client_thread = {
            std::thread::spawn(move || {
                block.handshake(uffd, test_vma_regions()).unwrap();
                block
            })
        };

        // Accept and drain handshake
        let (stream, _) = listener.accept().unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = stream.recv_with_fd(&mut buf).unwrap();

        let block = client_thread.join().unwrap();

        // No data sent, non-blocking socket → WouldBlock
        let err = block.handle_response().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn test_handle_response_connection_closed() {
        let tmp_dir = TempDir::new().unwrap();
        let sock_path = tmp_dir.as_path().join("test.sock");
        let sock_path_str = sock_path.to_str().unwrap().to_string();

        let listener = UnixListener::bind(&sock_path).unwrap();
        let uffd = create_test_uffd();

        let mut block = UffdBlock::new(&sock_path_str, FaultPolicy::Zerocopy).unwrap();

        let client_thread = {
            std::thread::spawn(move || {
                block.handshake(uffd, test_vma_regions()).unwrap();
                block
            })
        };

        // Accept, drain handshake, then close
        let (stream, _) = listener.accept().unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = stream.recv_with_fd(&mut buf).unwrap();
        drop(stream);

        let block = client_thread.join().unwrap();

        // Set blocking so recv returns 0 instead of WouldBlock
        block.sock.set_nonblocking(false).unwrap();
        assert!(!block.handle_response().unwrap());
    }
}
