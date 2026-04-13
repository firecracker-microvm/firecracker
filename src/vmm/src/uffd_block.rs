// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! UFFD block backend for on-demand page fault handling via an external server.
//!
//! Two key benefits (both require server support):
//! - **Zero-copy**: the server responds with blob fds that are MAP_FIXED directly
//!   over the faulting region, avoiding any data copy into guest memory.
//! - **Fault recovery**: if the server crashes, the client can reconnect and
//!   re-trigger page faults to resume operation without restarting the VM.
//!
//! For servers that do not support this protocol, the socket simply receives
//! no messages and the event handler becomes a no-op with no overhead.

use crate::logger::{info, warn};
use std::io;
use std::mem::ManuallyDrop;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::{Mutex, OnceLock};

use libc::MAP_FAILED;
use serde::{Deserialize, Serialize};
use userfaultfd::Uffd;
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

use crate::persist::GuestRegionUffdMapping;

/// Message type enum for UFFD protocol.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// Handshake message.
    #[default]
    Handshake = 0,
    /// Page fault notification.
    PageFault = 1,
}

/// Fault handling policy for UFFD.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u8)]
pub enum FaultPolicy {
    /// Zero-copy mode: send fd to client, let client do mmap.
    #[default]
    Zerocopy = 0,
    /// Copy mode: use UFFDIO_COPY to copy data directly.
    Copy = 1,
}

/// VMA region information for userfaultfd registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmaRegion {
    /// Base host virtual address of this region.
    pub base_host_virt_addr: u64,
    /// Size of the region in bytes.
    pub size: usize,
    /// Offset in the backend.
    pub offset: u64,
    /// Page size for this region.
    pub page_size: usize,
    /// Page size in KiB (legacy, defaults to 0).
    #[serde(default)]
    pub page_size_kib: usize,
    /// Memory protection flags (defaults to `PROT_READ`).
    #[serde(default = "default_prot")]
    pub prot: i32,
    /// Mmap flags (defaults to `MAP_PRIVATE | MAP_FIXED`).
    #[serde(default = "default_flags")]
    pub flags: i32,
}

fn default_prot() -> i32 {
    libc::PROT_READ
}

fn default_flags() -> i32 {
    libc::MAP_PRIVATE | libc::MAP_FIXED
}

impl Default for VmaRegion {
    fn default() -> Self {
        Self {
            base_host_virt_addr: 0,
            size: 0,
            offset: 0,
            page_size: 4096,
            page_size_kib: 0,
            prot: default_prot(),
            flags: default_flags(),
        }
    }
}

/// Handshake request to the UFFD server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeRequest {
    /// Message type (defaults to Handshake).
    #[serde(default)]
    pub r#type: MessageType,
    /// VMA regions to register.
    pub regions: Vec<VmaRegion>,
    /// Fault handling policy (defaults to Zerocopy).
    #[serde(default)]
    pub policy: FaultPolicy,
}

/// Page fault response from the UFFD server.
#[derive(Debug, Deserialize)]
struct PageFaultResponse {
    ranges: Vec<BlobRange>,
}

/// A single range within a page fault response.
#[derive(Debug, Deserialize)]
struct BlobRange {
    len: usize,
    blob_offset: u64,
    block_offset: u64,
}

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
    sock: Mutex<UnixStream>,
    policy: FaultPolicy,
    uffd: OnceLock<ManuallyDrop<Uffd>>,
    regions: OnceLock<Vec<VmaRegion>>,
}

impl std::fmt::Debug for UffdBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UffdBlock")
            .field("sock_path", &self.sock_path)
            .field("sock_fd", &self.sock.lock().unwrap().as_raw_fd())
            .field("policy", &self.policy)
            .field("uffd_fd", &self.uffd.get().map(|u| u.as_raw_fd()))
            .field("regions", &self.regions.get())
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
            sock: Mutex::new(sock),
            policy,
            uffd: OnceLock::new(),
            regions: OnceLock::new(),
        })
    }

    /// Perform a formal protocol handshake with the UFFD server.
    pub fn handshake(&self, uffd: Uffd, regions: Vec<VmaRegion>) -> io::Result<()> {
        let request = HandshakeRequest {
            r#type: MessageType::Handshake,
            regions: regions.clone(),
            policy: self.policy,
        };
        let json_data = serde_json::to_string(&request)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let sock = self.sock.lock().unwrap();
        sock.send_with_fd(json_data.as_bytes(), uffd.as_raw_fd())?;
        sock.set_nonblocking(true)?;
        drop(sock);

        let _ = self.uffd.set(ManuallyDrop::new(uffd));
        let _ = self.regions.set(regions);
        Ok(())
    }

    /// Perform a legacy handshake: sends a raw `Vec<GuestRegionUffdMapping>`
    /// JSON array, compatible with the stock Firecracker snapshot uffd handler.
    ///
    /// If `fallback` is true and the server closes the connection after
    /// receiving the legacy format (indicating it does not support it),
    /// this method reconnects and retries with the formal `HandshakeRequest`
    /// protocol.
    pub fn handshake_compat(
        &self,
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
                page_size_kib: m.page_size_kib,
                prot,
                flags,
            })
            .collect();

        let json_data = serde_json::to_string(&mappings)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let sock = self.sock.lock().unwrap();
        sock.send_with_fd(json_data.as_bytes(), uffd.as_raw_fd())?;
        sock.set_nonblocking(true)?;

        if fallback {
            // Wait briefly for the server to process and potentially reject.
            // SAFETY: pollfd is a valid struct pointing to the socket fd.
            let mut pfd = libc::pollfd {
                fd: sock.as_raw_fd(),
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            };
            // 100ms timeout — enough for the server to close if it rejects.
            // SAFETY: pfd is a valid stack-allocated pollfd struct.
            unsafe { libc::poll(&mut pfd, 1, 100) };

            // Probe whether the server closed the connection.
            let mut probe = [0u8; 1];
            // SAFETY: valid fd, valid buffer pointer and length.
            let peek_ret = unsafe {
                libc::recv(
                    std::os::unix::io::AsRawFd::as_raw_fd(&*sock),
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
                    drop(sock);
                    info!("UffdBlock: legacy handshake rejected, retrying with formal protocol");
                    let new_sock = UnixStream::connect(&self.sock_path)?;
                    *self.sock.lock().unwrap() = new_sock;
                    return self.handshake(uffd, regions);
                }
            }
        }
        drop(sock);

        let _ = self.uffd.set(ManuallyDrop::new(uffd));
        let _ = self.regions.set(regions);
        Ok(())
    }

    /// Handle a page fault response by mmapping blob fds in a zero-copy manner.
    pub fn handle_response(&self) -> io::Result<bool> {
        let mut data = [0u8; RECV_BUF_SIZE];
        let mut fds = [0i32; MAX_FDS];

        let sock = self.sock.lock().unwrap();
        let iov = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: data.len(),
        };
        // SAFETY: iov points to a valid buffer, fds is a valid slice for receiving fds.
        let (bytes_read, fd_count) = unsafe { sock.recv_with_fds(&mut [iov], &mut fds) }
            .map_err(|e| io::Error::from_raw_os_error(e.errno()))?;

        if bytes_read == 0 {
            // connection closed
            return Ok(false);
        }

        let json_str = std::str::from_utf8(&data[..bytes_read])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let response: PageFaultResponse = serde_json::from_str(json_str)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        if fd_count != response.ranges.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "fd count {} != ranges count {}",
                    fd_count,
                    response.ranges.len()
                ),
            ));
        }

        let regions = self.regions.get().expect("handshake not called");
        let uffd = self.uffd.get().expect("handshake not called");

        for (range, fd) in response.ranges.iter().zip(fds.iter()) {
            let region = regions.iter().find(|r| {
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
            // SAFETY: fd is a valid file descriptor received via sendfd.
            let file = unsafe { std::fs::File::from_raw_fd(*fd) };
            // SAFETY: We are calling mmap with a valid fd and checking the result.
            let map_addr = unsafe {
                libc::mmap(
                    target_addr as *mut _,
                    range.len,
                    region.prot,
                    region.flags,
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
                    self.copy_fallback(&file, target_addr, range.len, range.blob_offset)?;
                } else {
                    warn!("UffdBlock: mmap failed for 0x{:x}: {}", target_addr, err);
                }
                continue;
            }

            std::mem::forget(file);
            let _ = uffd.wake(target_addr as *mut _, range.len);
        }

        Ok(true)
    }

    /// Fallback when mmap hits vm.max_map_count: pread from blob fd, then UFFDIO_COPY.
    fn copy_fallback(
        &self,
        file: &std::fs::File,
        target_addr: u64,
        len: usize,
        blob_offset: u64,
    ) -> io::Result<()> {
        let mut buf = vec![0u8; len];
        // SAFETY: file is a valid fd, buf is a valid mutable buffer, and blob_offset
        // is within the file bounds. pread reads up to len bytes without modifying
        // the file offset.
        let n = unsafe {
            libc::pread(
                file.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                len,
                blob_offset.cast_signed(),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        let uffd = self.uffd.get().expect("handshake not called");
        // SAFETY: buf is a valid buffer with data read from the blob fd.
        unsafe {
            uffd.copy(buf.as_ptr().cast(), target_addr as *mut _, len, true)
                .map_err(io::Error::other)?;
        }
        Ok(())
    }

    /// Reconnect to the UFFD server: redo handshake, and wake all regions.
    /// Requires server-side support for accepting reconnections.
    ///
    /// Returns `(old_fd, new_fd)` so the caller can re-register with epoll.
    pub fn reconnect(&self) -> io::Result<(RawFd, RawFd)> {
        let regions = self.regions.get().expect("handshake not called");
        let uffd = self.uffd.get().expect("handshake not called");
        let request = HandshakeRequest {
            r#type: MessageType::Handshake,
            regions: regions.clone(),
            policy: self.policy,
        };
        let json_data = serde_json::to_string(&request)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let new_sock = UnixStream::connect(&self.sock_path)?;
        new_sock.send_with_fd(json_data.as_bytes(), uffd.as_raw_fd())?;
        new_sock.set_nonblocking(true)?;
        let new_fd = new_sock.as_raw_fd();

        let mut guard = self.sock.lock().unwrap();
        let old_fd = guard.as_raw_fd();
        *guard = new_sock;
        drop(guard);

        for region in regions {
            // SAFETY: base_host_virt_addr and size describe a valid registered uffd region.
            let _ = uffd.wake(region.base_host_virt_addr as *mut _, region.size);
        }

        Ok((old_fd, new_fd))
    }

    /// Returns the raw file descriptor of the underlying Unix socket.
    pub fn sock_fd(&self) -> RawFd {
        self.sock.lock().unwrap().as_raw_fd()
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
            ..Default::default()
        }]
    }

    #[allow(deprecated)]
    fn test_legacy_mappings() -> Vec<GuestRegionUffdMapping> {
        vec![GuestRegionUffdMapping {
            base_host_virt_addr: 0x1000,
            size: 0x1000,
            offset: 0,
            page_size: 4096,
            page_size_kib: 0,
        }]
    }

    #[test]
    fn test_handshake() {
        let tmp_dir = TempDir::new().unwrap();
        let sock_path = tmp_dir.as_path().join("test.sock");
        let sock_path_str = sock_path.to_str().unwrap().to_string();

        let listener = UnixListener::bind(&sock_path).unwrap();
        let regions = test_vma_regions();
        let uffd = create_test_uffd();
        let uffd_fd = uffd.as_raw_fd();

        let block = UffdBlock::new(&sock_path_str, FaultPolicy::Zerocopy).unwrap();

        let client_thread = {
            std::thread::spawn(move || {
                block.handshake(uffd, regions).unwrap();
                block
            })
        };

        // Server side: accept and verify handshake data
        let (stream, _) = listener.accept().unwrap();
        let mut buf = vec![0u8; 4096];
        let (bytes_read, file) = stream.recv_with_fd(&mut buf).unwrap();
        buf.truncate(bytes_read);

        // Verify we received valid HandshakeRequest JSON
        let received: HandshakeRequest =
            serde_json::from_slice(&buf).expect("Invalid JSON from handshake");
        assert_eq!(received.r#type, MessageType::Handshake);
        assert_eq!(received.regions.len(), 1);
        assert_eq!(received.regions[0].base_host_virt_addr, 0x1000);
        assert_eq!(received.regions[0].size, 0x1000);
        assert_eq!(received.policy, FaultPolicy::Zerocopy);

        // Verify we received a uffd fd
        assert!(file.is_some());

        let block = client_thread.join().unwrap();
        assert_eq!(block.sock_path, sock_path_str);
        assert_eq!(block.uffd.get().unwrap().as_raw_fd(), uffd_fd);
        assert_eq!(block.policy, FaultPolicy::Zerocopy);
    }

    #[test]
    fn test_handshake_compat() {
        let tmp_dir = TempDir::new().unwrap();
        let sock_path = tmp_dir.as_path().join("test.sock");
        let sock_path_str = sock_path.to_str().unwrap().to_string();

        let listener = UnixListener::bind(&sock_path).unwrap();
        let mappings = test_legacy_mappings();
        let uffd = create_test_uffd();

        let block = UffdBlock::new(&sock_path_str, FaultPolicy::Zerocopy).unwrap();

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
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].base_host_virt_addr, 0x1000);
        assert!(file.is_some());

        let block = client_thread.join().unwrap();
        // Verify internal VmaRegion was created with provided prot/flags
        let regions = block.regions.get().unwrap();
        assert_eq!(regions[0].prot, libc::PROT_READ | libc::PROT_WRITE);
        assert_eq!(regions[0].flags, libc::MAP_SHARED | libc::MAP_FIXED);
    }

    #[test]
    fn test_handle_response_would_block() {
        let tmp_dir = TempDir::new().unwrap();
        let sock_path = tmp_dir.as_path().join("test.sock");
        let sock_path_str = sock_path.to_str().unwrap().to_string();

        let listener = UnixListener::bind(&sock_path).unwrap();
        let uffd = create_test_uffd();

        let block = UffdBlock::new(&sock_path_str, FaultPolicy::Zerocopy).unwrap();

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

        let block = UffdBlock::new(&sock_path_str, FaultPolicy::Zerocopy).unwrap();

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
        block.sock.lock().unwrap().set_nonblocking(false).unwrap();
        assert!(!block.handle_response().unwrap());
    }

    #[test]
    fn test_reconnect() {
        let tmp_dir = TempDir::new().unwrap();
        let sock_path = tmp_dir.as_path().join("test.sock");
        let sock_path_str = sock_path.to_str().unwrap().to_string();

        let listener = UnixListener::bind(&sock_path).unwrap();
        let uffd = create_test_uffd();

        let block = UffdBlock::new(&sock_path_str, FaultPolicy::Zerocopy).unwrap();

        let client_thread = {
            std::thread::spawn(move || {
                block.handshake(uffd, test_vma_regions()).unwrap();
                block
            })
        };

        // Accept initial connection
        let (stream, _) = listener.accept().unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = stream.recv_with_fd(&mut buf).unwrap();

        let block = client_thread.join().unwrap();
        let old_fd = block.sock_fd();

        // Reconnect in a separate thread (reconnect blocks on connect)
        let reconnect_thread = std::thread::spawn(move || {
            let result = block.reconnect().unwrap();
            (block, result)
        });

        // Accept reconnection
        let (stream2, _) = listener.accept().unwrap();
        let mut buf2 = vec![0u8; 4096];
        let (bytes_read, fd) = stream2.recv_with_fd(&mut buf2).unwrap();
        buf2.truncate(bytes_read);

        // Verify reconnect sends HandshakeRequest format
        let received: HandshakeRequest =
            serde_json::from_slice(&buf2).expect("Invalid JSON from reconnect handshake");
        assert_eq!(received.regions.len(), 1);
        assert_eq!(received.policy, FaultPolicy::Zerocopy);
        assert!(fd.is_some());

        let (block, (returned_old_fd, new_fd)) = reconnect_thread.join().unwrap();
        assert_eq!(returned_old_fd, old_fd);
        assert_ne!(new_fd, old_fd);
        assert_eq!(block.sock_fd(), new_fd);
    }
}
