// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Exitless Async Page Fault context for the VMM side.
//!
//! Creates eventfds, issues the `KVM_SET_APF_EVENTFD` ioctl, and mmaps the
//! kernel-allocated APF shared page. The ring buffer types and all read/write
//! logic live exclusively in the UFFD handler (`uffd_utils.rs`).

use std::io;
use std::os::fd::{AsRawFd, RawFd};

use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::ioctl::ioctl_with_ref;
use vmm_sys_util::ioctl_iow_nr;

const KVMIO: u32 = 0xAE;
const KVM_APF_PAGE_OFFSET: libc::off_t = 3;
const KVM_APF_SHARED_VERSION: u32 = 1;
const KVM_APF_RING_SIZE: u32 = 64;
const KVM_APF_RING_ENTRY_SIZE: u32 = 16;

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
    /// Flags (reserved, must be 0). Set `fd = -1` to deregister.
    pub flags: u32,
    /// Padding for alignment.
    pub padding: u32,
    /// Reserved for future use.
    pub reserved: [u64; 2],
}

/// Exitless APF context for a single vCPU.
///
/// Maps the kernel-allocated shared page for a vCPU. The VMM treats the page as
/// opaque — only the kernel and handler read/write the ring buffers it contains.
pub struct ExitlessApfContext {
    eventfd: EventFd,
    complete_eventfd: EventFd,
    /// Opaque mmap of the shared page (ring layout managed by handler).
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

// SAFETY: `ExitlessApfContext` holds a raw pointer (`shared_page`) to a vCPU-fd mmap.
// Sending across threads is safe because:
// - The mmap remains valid for the struct's lifetime and is explicitly unmapped in Drop.
// - The VMM never reads or writes the shared page contents after setup — only the kernel
//   and UFFD handler access the ring buffers via independent mmaps of the vCPU fd.
// - The eventfds and vCPU fd are plain file descriptors, which are Send.
unsafe impl Send for ExitlessApfContext {}

// SAFETY: Shared references are safe because:
// - The VMM only calls `eventfd()` and `fds_for_handler()` which return owned fds/references
//   and never touch the shared page pointer.
// - The `MAP_SHARED` mmap is designed for concurrent access: the kernel writes the notify ring
//   and the handler writes the completion ring, synchronized by volatile head/tail indices.
// - No `&self` method on this struct reads or writes through `shared_page`.
unsafe impl Sync for ExitlessApfContext {}

fn validate_shared_page(ptr: *mut libc::c_void) -> io::Result<()> {
    // SAFETY: caller passes a valid shared-page mapping.
    let header = ptr.cast::<u32>();
    // SAFETY: the header starts with version, ring_size, entry_size.
    let version = unsafe { std::ptr::read_volatile(header) };
    // SAFETY: the header starts with version, ring_size, entry_size.
    let ring_size = unsafe { std::ptr::read_volatile(header.add(1)) };
    // SAFETY: the header starts with version, ring_size, entry_size.
    let entry_size = unsafe { std::ptr::read_volatile(header.add(2)) };

    if version != KVM_APF_SHARED_VERSION
        || ring_size != KVM_APF_RING_SIZE
        || entry_size != KVM_APF_RING_ENTRY_SIZE
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unsupported APF shared page: version={version} ring_size={ring_size} entry_size={entry_size}"
            ),
        ));
    }

    Ok(())
}

impl ExitlessApfContext {
    /// Create a new exitless APF context for the given vCPU fd.
    pub fn new(vcpu_fd: RawFd) -> io::Result<Self> {
        let eventfd = EventFd::new(libc::EFD_NONBLOCK)?;
        let complete_eventfd = EventFd::new(libc::EFD_NONBLOCK)?;

        // SAFETY: sysconf(_SC_PAGESIZE) is always safe and returns a positive value on Linux.
        let page_size =
            usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap_or(4096);

        let apf_eventfd = KvmApfEventfd {
            fd: eventfd.as_raw_fd(),
            complete_fd: complete_eventfd.as_raw_fd(),
            flags: 0,
            padding: 0,
            reserved: [0; 2],
        };

        // SAFETY: ioctl on a valid vCPU fd with a properly initialized KvmApfEventfd struct.
        let ret = unsafe { ioctl_with_ref(&vcpu_fd, KVM_SET_APF_EVENTFD(), &apf_eventfd) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        let page_offset = libc::off_t::try_from(page_size)
            .map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
        let offset = KVM_APF_PAGE_OFFSET * page_offset;
        // SAFETY: mmap with MAP_SHARED on a valid vCPU fd and APF page offset is safe.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                vcpu_fd,
                offset,
            )
        };
        if ptr == libc::MAP_FAILED {
            let err = io::Error::last_os_error();
            let dereg = KvmApfEventfd {
                fd: -1,
                complete_fd: -1,
                flags: 0,
                padding: 0,
                reserved: [0; 2],
            };
            // SAFETY: best-effort deregistration on the vCPU fd.
            unsafe { ioctl_with_ref(&vcpu_fd, KVM_SET_APF_EVENTFD(), &dereg) };
            return Err(err);
        }

        if let Err(err) = validate_shared_page(ptr) {
            // SAFETY: ptr/page_size are from a successful mmap above.
            unsafe { libc::munmap(ptr, page_size) };
            let dereg = KvmApfEventfd {
                fd: -1,
                complete_fd: -1,
                flags: 0,
                padding: 0,
                reserved: [0; 2],
            };
            // SAFETY: best-effort deregistration on the vCPU fd.
            unsafe { ioctl_with_ref(&vcpu_fd, KVM_SET_APF_EVENTFD(), &dereg) };
            return Err(err);
        }

        Ok(Self {
            eventfd,
            complete_eventfd,
            shared_page: ptr,
            vcpu_fd,
        })
    }

    /// Returns a reference to the notification eventfd.
    pub fn eventfd(&self) -> &EventFd {
        &self.eventfd
    }

    /// Returns fds to send to the UFFD handler:
    /// (notify_eventfd, complete_eventfd, vcpu_fd_for_shared_page_mmap)
    pub fn fds_for_handler(&self) -> (RawFd, RawFd, RawFd) {
        (
            self.eventfd.as_raw_fd(),
            self.complete_eventfd.as_raw_fd(),
            self.vcpu_fd,
        )
    }
}

impl Drop for ExitlessApfContext {
    fn drop(&mut self) {
        let dereg = KvmApfEventfd {
            fd: -1,
            complete_fd: -1,
            flags: 0,
            padding: 0,
            reserved: [0; 2],
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
