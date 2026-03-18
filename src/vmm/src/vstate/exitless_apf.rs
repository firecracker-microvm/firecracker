// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Exitless Async Page Fault context for the VMM side.
//!
//! Creates the memfd-backed shared page, eventfds, and issues the
//! `KVM_SET_APF_EVENTFD` ioctl. The ring buffer types and all read/write
//! logic live exclusively in the UFFD handler (`uffd_utils.rs`).

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::io::OwnedFd;

use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::ioctl::ioctl_with_ref;
use vmm_sys_util::ioctl_iow_nr;

const KVMIO: u32 = 0xAE;

/// `KVM_SET_APF_EVENTFD` ioctl — registers eventfds for exitless APF.
mod apf_eventfd_ioctl {
    use super::*;
    ioctl_iow_nr!(KVM_SET_APF_EVENTFD, KVMIO, 0xd9, KvmApfEventfd);
}
use apf_eventfd_ioctl::KVM_SET_APF_EVENTFD;

/// Matches kernel `struct kvm_apf_eventfd`.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct KvmApfEventfd {
    /// Notify eventfd: kernel signals this when an APF occurs.
    pub fd: i32,
    /// Completion eventfd: userspace signals this after resolving a page.
    pub complete_fd: i32,
    /// Userspace address of the shared page containing notify/completion rings.
    pub page_addr: u64,
    /// Flags (reserved, must be 0). Set `fd = -1` to deregister.
    pub flags: u32,
    /// Padding for alignment.
    pub padding: u32,
}

/// Exitless APF context for a single vCPU.
///
/// Creates a memfd-backed shared page that the kernel, VMM, and UFFD handler
/// all mmap. The VMM treats the page as opaque — only the kernel and handler
/// read/write the ring buffers it contains.
pub struct ExitlessApfContext {
    eventfd: EventFd,
    complete_eventfd: EventFd,
    memfd: OwnedFd,
    /// Opaque mmap of the shared page (ring layout managed by handler)
    shared_page: *mut libc::c_void,
    vcpu_fd: RawFd,
}

impl std::fmt::Debug for ExitlessApfContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExitlessApfContext")
            .field("vcpu_fd", &self.vcpu_fd)
            .finish()
    }
}

// SAFETY: `ExitlessApfContext` holds a raw pointer (`shared_page`) to a memfd-backed mmap.
// Sending across threads is safe because:
// - The mmap remains valid for the struct's lifetime: the backing `OwnedFd` (memfd) is owned
//   by this struct, so the mapping cannot be freed while the struct exists.
// - The VMM never reads or writes the shared page contents after setup — only the kernel
//   and UFFD handler access the ring buffers via their own independent mmaps of the same memfd.
// - The eventfds and memfd are plain file descriptors, which are Send.
unsafe impl Send for ExitlessApfContext {}

// SAFETY: Shared references are safe because:
// - The VMM only calls `eventfd()` and `fds_for_handler()` which return owned fds/references
//   and never touch the shared page pointer.
// - The `MAP_SHARED` mmap is designed for concurrent access: the kernel writes the notify ring
//   and the handler writes the completion ring, synchronized by volatile head/tail indices.
// - No `&self` method on this struct reads or writes through `shared_page`.
unsafe impl Sync for ExitlessApfContext {}

impl ExitlessApfContext {
    /// Create a new exitless APF context for the given vCPU fd.
    pub fn new(vcpu_fd: RawFd) -> io::Result<Self> {
        let eventfd = EventFd::new(libc::EFD_NONBLOCK)?;
        let complete_eventfd = EventFd::new(libc::EFD_NONBLOCK)?;

        // SAFETY: sysconf(_SC_PAGESIZE) is always safe and returns a positive value on Linux.
        let page_size =
            usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap_or(4096);

        // SAFETY: memfd_create with a valid C string and MFD_CLOEXEC is safe.
        let raw_memfd = unsafe { libc::memfd_create(c"apf_shared".as_ptr(), libc::MFD_CLOEXEC) };
        if raw_memfd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw_memfd is a valid fd (checked >= 0 above) and we take sole ownership.
        let memfd = unsafe { OwnedFd::from_raw_fd(raw_memfd) };

        // SAFETY: ftruncate on a valid memfd with a small positive size is safe.
        #[allow(clippy::cast_possible_wrap)]
        if unsafe { libc::ftruncate(memfd.as_raw_fd(), page_size as libc::off_t) } < 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: mmap with MAP_SHARED on a valid memfd, page-aligned size, is safe.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                memfd.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: ptr is a valid mmap'd region of page_size bytes (checked != MAP_FAILED above).
        unsafe { std::ptr::write_bytes(ptr.cast::<u8>(), 0, page_size) };

        let apf_eventfd = KvmApfEventfd {
            fd: eventfd.as_raw_fd(),
            complete_fd: complete_eventfd.as_raw_fd(),
            page_addr: ptr as u64,
            flags: 0,
            padding: 0,
        };

        // SAFETY: ioctl on a valid vCPU fd with a properly initialized KvmApfEventfd struct.
        let ret = unsafe { ioctl_with_ref(&vcpu_fd, KVM_SET_APF_EVENTFD(), &apf_eventfd) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            // SAFETY: ptr/page_size are from a successful mmap above.
            unsafe { libc::munmap(ptr, page_size) };
            return Err(err);
        }

        Ok(Self {
            eventfd,
            complete_eventfd,
            memfd,
            shared_page: ptr,
            vcpu_fd,
        })
    }

    /// Returns a reference to the notification eventfd.
    pub fn eventfd(&self) -> &EventFd {
        &self.eventfd
    }

    /// Returns fds to send to the UFFD handler:
    /// (notify_eventfd, complete_eventfd, shared_page_memfd)
    pub fn fds_for_handler(&self) -> (RawFd, RawFd, RawFd) {
        (
            self.eventfd.as_raw_fd(),
            self.complete_eventfd.as_raw_fd(),
            self.memfd.as_raw_fd(),
        )
    }
}

impl Drop for ExitlessApfContext {
    fn drop(&mut self) {
        let dereg = KvmApfEventfd {
            fd: -1,
            complete_fd: -1,
            page_addr: 0,
            flags: 0,
            padding: 0,
        };
        // SAFETY: ioctl on a valid vCPU fd to deregister the eventfd (fd = -1).
        unsafe {
            ioctl_with_ref(&self.vcpu_fd, KVM_SET_APF_EVENTFD(), &dereg);
        }
        // SAFETY: sysconf(_SC_PAGESIZE) is always safe and returns a positive value on Linux.
        let page_size =
            usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap_or(4096);
        // SAFETY: shared_page and page_size are from the successful mmap in new().
        unsafe {
            libc::munmap(self.shared_page, page_size);
        }
    }
}
