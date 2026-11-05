// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The handshake with a memory backend: Firecracker hands guest memory to an external process
//! over a Unix domain socket.

use std::mem::forget;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;

use serde::{Deserialize, Serialize};
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

/// This describes the mapping between Firecracker base virtual address and
/// offset in the buffer or file backend for a guest memory region. It is used
/// to tell an external process/thread where to populate the guest memory data
/// for this range.
///
/// E.g. Guest memory contents for a region of `size` bytes can be found in the
/// backend at `offset` bytes from the beginning, and should be copied/populated
/// into `base_host_address`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuestRegionUffdMapping {
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

/// Error type for [`send_uffd_handshake`]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum HandshakeError {
    /// Failed to connect to UDS Unix stream: {0}
    Connect(#[from] std::io::Error),
    /// Failed to sends file descriptor: {0}
    Send(#[from] vmm_sys_util::errno::Error),
}

pub(crate) fn send_uffd_handshake(
    mem_uds_path: &Path,
    backend_mappings: &[GuestRegionUffdMapping],
    uffd: &impl AsRawFd,
) -> Result<(), HandshakeError> {
    // This is safe to unwrap() because we control the contents of the vector
    // (i.e GuestRegionUffdMapping entries).
    let backend_mappings = serde_json::to_string(backend_mappings).unwrap();

    let socket = UnixStream::connect(mem_uds_path)?;
    socket.send_with_fd(
        backend_mappings.as_bytes(),
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

    // We prevent Rust from closing the socket file descriptor to avoid a potential race condition
    // between the mappings message and the connection shutdown. If the latter arrives at the UFFD
    // handler first, the handler never sees the mappings.
    forget(socket);

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::vmm_config::machine_config::HugePageConfig;

    #[test]
    fn test_send_uffd_handshake() {
        #[allow(deprecated)]
        let uffd_regions = vec![
            GuestRegionUffdMapping {
                base_host_virt_addr: 0,
                size: 0x100000,
                offset: 0,
                page_size: HugePageConfig::None.page_size(),
                page_size_kib: HugePageConfig::None.page_size(),
            },
            GuestRegionUffdMapping {
                base_host_virt_addr: 0x100000,
                size: 0x200000,
                offset: 0,
                page_size: HugePageConfig::Hugetlbfs2M.page_size(),
                page_size_kib: HugePageConfig::Hugetlbfs2M.page_size(),
            },
        ];

        let uds_path = TempFile::new().unwrap();
        let uds_path = uds_path.as_path();
        std::fs::remove_file(uds_path).unwrap();

        let listener = UnixListener::bind(uds_path).expect("Cannot bind to socket path");

        send_uffd_handshake(uds_path, &uffd_regions, &std::io::stdin()).unwrap();

        let (stream, _) = listener.accept().expect("Cannot listen on UDS socket");

        let mut message_buf = vec![0u8; 1024];
        let (bytes_read, _) = stream
            .recv_with_fd(&mut message_buf[..])
            .expect("Cannot recv_with_fd");
        message_buf.resize(bytes_read, 0);

        let deserialized: Vec<GuestRegionUffdMapping> =
            serde_json::from_slice(&message_buf).unwrap();

        assert_eq!(uffd_regions, deserialized);
    }
}
