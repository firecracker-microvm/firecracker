// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The handshake with a memory backend: Firecracker hands guest memory to an external process
//! over a Unix domain socket.

use std::mem::forget;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;

use serde::{Deserialize, Serialize};
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

use crate::vmm_config::machine_config::HugePageConfig;
use crate::vstate::memory::GuestRegionMmap;

/// This describes the mapping between Firecracker base virtual address and
/// offset in the buffer or file backend for a guest memory region. It is used
/// to tell an external process/thread where to populate the guest memory data
/// for this range.
///
/// E.g. Guest memory contents for a region of `size` bytes can be found in the
/// backend at `offset` bytes from the beginning, and should be copied/populated
/// into `base_host_address`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuestRegionMapping {
    /// Base host virtual address where the guest memory contents for this
    /// region should be copied/populated.
    pub base_host_virt_addr: u64,
    /// Region size.
    pub size: usize,
    /// Offset in the backend file/buffer where the region contents are.
    pub offset: u64,
    /// The configured page size for this memory region.
    pub page_size: usize,
    /// The configured page size **in bytes** for this memory region. The name is
    /// wrong but cannot be changed due to being API, so this field is deprecated,
    /// to be removed in 2.0.
    #[deprecated]
    pub page_size_kib: usize,
}

/// Error type for [`Handshake::send`]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum HandshakeError {
    /// Failed to connect to UDS Unix stream: {0}
    Connect(#[from] std::io::Error),
    /// Failed to send file descriptors: {0}
    Send(#[from] vmm_sys_util::errno::Error),
}

/// The message Firecracker sends to a memory backend once guest memory is set up: the layout of
/// guest memory, with the file descriptors the backend needs attached as `SCM_RIGHTS` data.
#[derive(Debug)]
pub struct Handshake {
    /// One entry per guest memory region, in the order the regions were allocated. A region's
    /// `offset` is its offset in a guest memory file.
    pub regions: Vec<GuestRegionMapping>,
}

impl Handshake {
    /// Describes `regions`, all backed by pages of the size `huge_pages` selects.
    pub fn new<'a>(
        regions: impl Iterator<Item = &'a GuestRegionMmap>,
        huge_pages: HugePageConfig,
    ) -> Self {
        let mut mappings = Vec::new();
        let mut offset = 0;
        for mem_region in regions {
            #[allow(deprecated)]
            mappings.push(GuestRegionMapping {
                base_host_virt_addr: mem_region.as_ptr() as u64,
                size: mem_region.size(),
                offset,
                page_size: huge_pages.page_size(),
                page_size_kib: huge_pages.page_size(),
            });
            offset += mem_region.size() as u64;
        }
        Self { regions: mappings }
    }

    /// Connects to `uds_path` and sends the message with `fds` attached (the uffd and/or the guest
    /// memory memfd, depending on the backend), then keeps the connection open for the life of the
    /// process.
    pub fn send(&self, uds_path: &Path, fds: &[RawFd]) -> Result<(), HandshakeError> {
        // This is safe to unwrap() because we control the contents of the vector
        // (i.e GuestRegionMapping entries).
        let backend_mappings = serde_json::to_string(&self.regions).unwrap();

        let socket = UnixStream::connect(uds_path)?;
        socket.send_with_fds(
            &[backend_mappings.as_bytes()],
            // In the happy case we can close the fds since the other process has them open and is
            // using them to serve us pages / read our memory.
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
            fds,
        )?;

        // We prevent Rust from closing the socket file descriptor to avoid a potential race
        // condition between the mappings message and the connection shutdown. If the latter
        // arrives at the backend first, the backend never sees the mappings.
        forget(socket);

        Ok(())
    }
}

/// Receives one handshake on `listener`: the message and the fds that came with it.
#[cfg(test)]
pub(crate) fn receive_handshake(
    listener: &std::os::unix::net::UnixListener,
) -> (Vec<GuestRegionMapping>, Vec<std::fs::File>) {
    use std::os::unix::io::FromRawFd;

    let (stream, _) = listener.accept().expect("Cannot listen on UDS socket");

    let mut message_buf = vec![0u8; 1024];
    let mut fds = [-1; 3];
    let mut iovecs = [libc::iovec {
        iov_base: message_buf.as_mut_ptr().cast(),
        iov_len: message_buf.len(),
    }];
    // SAFETY: `iovecs` points into `message_buf`, which outlives the call.
    let (bytes_read, fd_count) = unsafe {
        stream
            .recv_with_fds(&mut iovecs, &mut fds)
            .expect("Cannot recv_with_fds")
    };
    message_buf.resize(bytes_read, 0);
    let files = fds[..fd_count]
        .iter()
        // SAFETY: the kernel just gave us these fds; nobody else owns them.
        .map(|&fd| unsafe { std::fs::File::from_raw_fd(fd) })
        .collect();
    (serde_json::from_slice(&message_buf).unwrap(), files)
}

#[cfg(test)]
mod tests {
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixListener;

    use vm_memory::GuestAddress;
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::vstate::memory;

    #[test]
    fn test_handshake_new() {
        let regions = [
            (GuestAddress(0), 0x20000),
            (GuestAddress(0x100000), 0x10000),
        ];
        let guest_memory = memory::anonymous(&regions, false, HugePageConfig::None).unwrap();

        let handshake = Handshake::new(guest_memory.iter(), HugePageConfig::None);
        let regions = &handshake.regions;

        assert_eq!(regions.len(), 2);
        assert_eq!(
            regions[0].base_host_virt_addr,
            guest_memory[0].as_ptr() as u64
        );
        assert_eq!(regions[0].size, 0x20000);
        assert_eq!(regions[0].offset, 0);
        assert_eq!(regions[0].page_size, HugePageConfig::None.page_size());
        // Regions are contiguous in the memory file, whatever the gap between them in guest
        // physical memory.
        assert_eq!(
            regions[1].base_host_virt_addr,
            guest_memory[1].as_ptr() as u64
        );
        assert_eq!(regions[1].size, 0x10000);
        assert_eq!(regions[1].offset, 0x20000);
    }

    #[test]
    fn test_handshake_send() {
        #[allow(deprecated)]
        let handshake = Handshake {
            regions: vec![
                GuestRegionMapping {
                    base_host_virt_addr: 0,
                    size: 0x100000,
                    offset: 0,
                    page_size: HugePageConfig::None.page_size(),
                    page_size_kib: HugePageConfig::None.page_size(),
                },
                GuestRegionMapping {
                    base_host_virt_addr: 0x100000,
                    size: 0x200000,
                    offset: 0,
                    page_size: HugePageConfig::Hugetlbfs2M.page_size(),
                    page_size_kib: HugePageConfig::Hugetlbfs2M.page_size(),
                },
            ],
        };

        let uds_path = TempFile::new().unwrap();
        let uds_path = uds_path.as_path();
        std::fs::remove_file(uds_path).unwrap();

        let listener = UnixListener::bind(uds_path).expect("Cannot bind to socket path");

        let fds = [std::io::stdin().as_raw_fd(), std::io::stdout().as_raw_fd()];
        handshake.send(uds_path, &fds).unwrap();

        let (deserialized, files) = receive_handshake(&listener);
        assert_eq!(handshake.regions, deserialized);
        assert_eq!(files.len(), 2);
    }
}
