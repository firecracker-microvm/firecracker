// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::undocumented_unsafe_blocks,
    clippy::ptr_as_ptr,
    clippy::cast_possible_wrap,
    // Not everything is used by both binaries
    dead_code
)]

mod userfault_bitmap;

use std::collections::HashMap;
use std::ffi::c_void;
use std::fs::File;
use std::io::{Read, Write};
use std::num::NonZero;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::ptr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use userfaultfd::{Error, Event, Uffd};
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

use crate::uffd_utils::userfault_bitmap::UserfaultBitmap;

// Exitless APF support — must match kernel UAPI definitions
pub const KVM_APF_RING_SIZE: usize = 32;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct KvmApfRingEntry {
    pub gpa: u64,
    pub flags: u64,
}

#[repr(C)]
pub struct KvmApfRing {
    pub head: AtomicU32,
    pub tail: AtomicU32,
    pub reserved: u32,
    pub padding: u32,
    pub entries: [KvmApfRingEntry; KVM_APF_RING_SIZE],
}

#[repr(C)]
pub struct KvmApfSharedPage {
    pub notify: KvmApfRing,
    pub complete: KvmApfRing,
}

impl KvmApfRing {
    pub fn pop(&self) -> Option<KvmApfRingEntry> {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Relaxed);
        if head == tail {
            return None;
        }
        let entry = self.entries[tail as usize];
        self.tail
            .store((tail + 1) % KVM_APF_RING_SIZE as u32, Ordering::Release);
        Some(entry)
    }
}

pub struct ExitlessApfVcpu {
    pub eventfd: RawFd,
    pub complete_eventfd: RawFd,
    pub shared_page: *mut KvmApfSharedPage,
    buff: [u8; 8],
}

impl ExitlessApfVcpu {
    pub fn from_fds(
        eventfd: RawFd,
        complete_eventfd: RawFd,
        shared_page_memfd: RawFd,
    ) -> std::io::Result<Self> {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                page_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                shared_page_memfd,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        unsafe { libc::close(shared_page_memfd) };
        Ok(Self {
            eventfd,
            complete_eventfd,
            shared_page: ptr as *mut KvmApfSharedPage,
            buff: [0; 8],
        })
    }

    pub fn notify_ring(&self) -> &KvmApfRing {
        unsafe { &(*self.shared_page).notify }
    }
    fn complete_ring(&self) -> &KvmApfRing {
        unsafe { &(*self.shared_page).complete }
    }

    pub fn drain_eventfd(&mut self) {
        unsafe { libc::read(self.eventfd, self.buff.as_mut_ptr() as *mut c_void, 8) };
    }

    pub fn signal_ready(&self, gpa: u64) {
        let ring = self.complete_ring();
        let entry = KvmApfRingEntry { gpa, flags: 0 };
        for attempt in 0u32.. {
            let head = ring.head.load(Ordering::Relaxed);
            let tail = ring.tail.load(Ordering::Acquire);
            let next = (head + 1) % KVM_APF_RING_SIZE as u32;
            if next != tail {
                unsafe {
                    let slot = &raw const ring.entries[head as usize] as *mut KvmApfRingEntry;
                    ptr::write(slot, entry);
                }
                ring.head.store(next, Ordering::Release);
                let val: u64 = 1;
                unsafe {
                    libc::write(
                        self.complete_eventfd,
                        &val as *const u64 as *const c_void,
                        8,
                    )
                };
                return;
            }
            if attempt == 0 {
                let val: u64 = 1;
                unsafe {
                    libc::write(
                        self.complete_eventfd,
                        &val as *const u64 as *const c_void,
                        8,
                    )
                };
            }
            if attempt >= 10_000 {
                eprintln!("WARN: APF completion ring full after {attempt} spins for gpa {gpa:#x}");
            }
            std::hint::spin_loop();
        }
    }
}

impl Drop for ExitlessApfVcpu {
    fn drop(&mut self) {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        unsafe {
            libc::munmap(self.shared_page as *mut c_void, page_size);
            libc::close(self.eventfd);
            libc::close(self.complete_eventfd);
        }
    }
}

struct SendableSharedPage(*mut KvmApfSharedPage);
unsafe impl Send for SendableSharedPage {}

fn signal_apf_ready(shared_page: SendableSharedPage, complete_eventfd: RawFd, gpa: u64) {
    let ring = unsafe { &(*shared_page.0).complete };
    let entry = KvmApfRingEntry { gpa, flags: 0 };
    for attempt in 0u32.. {
        let head = ring.head.load(Ordering::Relaxed);
        let tail = ring.tail.load(Ordering::Acquire);
        let next = (head + 1) % KVM_APF_RING_SIZE as u32;
        if next != tail {
            unsafe {
                let slot = &raw const ring.entries[head as usize] as *mut KvmApfRingEntry;
                ptr::write(slot, entry);
            }
            ring.head.store(next, Ordering::Release);
            let val: u64 = 1;
            unsafe { libc::write(complete_eventfd, &val as *const u64 as *const c_void, 8) };
            return;
        }
        if attempt == 0 {
            let val: u64 = 1;
            unsafe { libc::write(complete_eventfd, &val as *const u64 as *const c_void, 8) };
        }
        if attempt >= 10_000 {
            eprintln!("WARN: APF completion ring full after {attempt} spins for gpa {gpa:#x}");
        }
        std::hint::spin_loop();
    }
}

// This is the same with the one used in src/vmm.
/// This describes the mapping between Firecracker base virtual address and offset in the
/// buffer or file backend for a guest memory region. It is used to tell an external
/// process/thread where to populate the guest memory data for this range.
///
/// E.g. Guest memory contents for a region of `size` bytes can be found in the backend
/// at `offset` bytes from the beginning, and should be copied/populated into `base_host_address`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuestRegionUffdMapping {
    /// Base host virtual address where the guest memory contents for this region
    /// should be copied/populated.
    pub base_host_virt_addr: u64,
    /// Region size.
    pub size: usize,
    /// Offset in the backend file/buffer where the region contents are.
    pub offset: u64,
    /// Guest physical address start for this region.
    pub gpa_start: u64,
    /// The configured page size for this memory region.
    pub page_size: usize,
    /// Whether this region uses guest_memfd.
    pub is_guest_memfd: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, bitcode::Encode, bitcode::Decode)]
pub struct FaultRequest {
    /// vCPU that encountered the fault
    pub vcpu: u32,
    /// Offset in guest_memfd where the fault occured
    pub offset: u64,
    /// Flags
    pub flags: u64,
    /// Async PF GPA (set for APF fallback faults, None for sync faults)
    pub gpa: Option<u64>,
}

impl FaultRequest {
    pub fn into_reply(self, len: u64) -> FaultReply {
        FaultReply {
            vcpu: Some(self.vcpu),
            offset: self.offset,
            len,
            flags: self.flags,
            gpa: self.gpa,
            zero: false,
        }
    }
}

/// FaultReply
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, bitcode::Encode, bitcode::Decode)]
pub struct FaultReply {
    /// vCPU that encountered the fault, from `FaultRequest` (if present, otherwise 0)
    pub vcpu: Option<u32>,
    /// Offset in guest_memfd where population started
    pub offset: u64,
    /// Length of populated area
    pub len: u64,
    /// Flags, must be copied from `FaultRequest`, otherwise 0
    pub flags: u64,
    /// Async PF GPA, must be copied from `FaultRequest`, otherwise None
    pub gpa: Option<u64>,
    /// Whether the populated pages are zero pages
    pub zero: bool,
}

/// UffdMsgFromFirecracker
#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum UffdMsgFromFirecracker {
    /// Mappings
    Mappings(Vec<GuestRegionUffdMapping>),
    /// FaultReq
    FaultReq(FaultRequest),
}

/// UffdMsgToFirecracker
#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum UffdMsgToFirecracker {
    /// FaultRep
    FaultRep(FaultReply),
}

impl GuestRegionUffdMapping {
    fn contains(&self, fault_page_addr: u64) -> bool {
        fault_page_addr >= self.base_host_virt_addr
            && fault_page_addr < self.base_host_virt_addr + self.size as u64
    }
}

#[derive(Debug)]
pub struct UffdHandler {
    pub mem_regions: Vec<GuestRegionUffdMapping>,
    pub page_size: usize,
    backing_buffer: *const u8,
    pub uffd: Uffd,
    pub guest_memfd: Option<File>,
    pub guest_memfd_addr: Option<*mut u8>,
    pub userfault_bitmap: Option<UserfaultBitmap>,
}

impl UffdHandler {
    fn try_get_mappings_and_file(
        stream: &UnixStream,
    ) -> Result<(String, Option<File>), std::io::Error> {
        let mut message_buf = vec![0u8; 1024];
        let (bytes_read, file) = stream.recv_with_fd(&mut message_buf[..])?;
        message_buf.resize(bytes_read, 0);

        // We do not expect to receive non-UTF-8 data from Firecracker, so this is probably
        // an error we can't recover from. Just immediately abort
        let body = String::from_utf8(message_buf.clone()).unwrap_or_else(|_| {
            panic!(
                "Received body is not a utf-8 valid string. Raw bytes received: {message_buf:#?}"
            )
        });
        Ok((body, file))
    }

    fn get_mappings_and_file(stream: &UnixStream) -> (String, File) {
        // Sometimes, reading from the stream succeeds but we don't receive any
        // UFFD descriptor. We don't really have a good understanding why this is
        // happening, but let's try to be a bit more robust and retry a few times
        // before we declare defeat.
        for _ in 1..=5 {
            match Self::try_get_mappings_and_file(stream) {
                Ok((body, Some(file))) => {
                    return (body, file);
                }
                Ok((body, None)) => {
                    println!("Didn't receive UFFD over socket. We received: '{body}'. Retrying...");
                }
                Err(err) => {
                    println!("Could not get UFFD and mapping from Firecracker: {err}. Retrying...");
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        panic!("Could not get UFFD and mappings after 5 retries");
    }

    fn mmap_helper(len: libc::size_t, fd: libc::c_int) -> *mut libc::c_void {
        // SAFETY: `mmap` is a safe function to call with valid parameters.
        let ret = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };

        assert_ne!(ret, libc::MAP_FAILED);

        ret
    }

    pub fn from_mappings(
        mappings: Vec<GuestRegionUffdMapping>,
        uffd: File,
        guest_memfd: Option<File>,
        userfault_bitmap_memfd: Option<File>,
        backing_buffer: *const u8,
        size: usize,
    ) -> Self {
        let memsize: usize = mappings.iter().map(|r| r.size).sum();
        // Page size is the same for all memory regions, so just grab the first one
        let first_mapping = mappings.first().unwrap_or_else(|| {
            panic!(
                "Cannot get the first mapping. Mappings size is {}.",
                mappings.len()
            )
        });
        let page_size = first_mapping.page_size;

        // Make sure memory size matches backing data size.
        assert_eq!(memsize, size);
        assert!(page_size.is_power_of_two());

        let uffd = unsafe { Uffd::from_raw_fd(uffd.into_raw_fd()) };

        match (&guest_memfd, &userfault_bitmap_memfd) {
            (Some(guestmem_file), Some(bitmap_file)) => {
                let guest_memfd_addr =
                    Some(Self::mmap_helper(size, guestmem_file.as_raw_fd()) as *mut u8);

                let bitmap_ptr = Self::mmap_helper(size, bitmap_file.as_raw_fd()) as *mut AtomicU64;

                // SAFETY: The bitmap pointer is valid and the size is correct.
                let userfault_bitmap = Some(unsafe {
                    UserfaultBitmap::new(bitmap_ptr, memsize, NonZero::new(page_size).unwrap())
                });

                Self {
                    mem_regions: mappings,
                    page_size,
                    backing_buffer,
                    uffd,
                    guest_memfd,
                    guest_memfd_addr,
                    userfault_bitmap,
                }
            }
            (None, None) => Self {
                mem_regions: mappings,
                page_size,
                backing_buffer,
                uffd,
                guest_memfd: None,
                guest_memfd_addr: None,
                userfault_bitmap: None,
            },
            (_, _) => {
                panic!(
                    "Only both guest_memfd and userfault_bitmap_memfd can be set at the same time."
                );
            }
        }
    }

    /// Convert a guest physical address to an offset in the backing memory file.
    #[inline]
    pub fn gpa_to_offset(&self, gpa: u64) -> Option<usize> {
        for region in &self.mem_regions {
            if region.gpa_start <= gpa && gpa < region.gpa_start + region.size as u64 {
                return Some((gpa - region.gpa_start + region.offset) as usize);
            }
        }
        None
    }

    pub fn read_event(&mut self) -> Result<Option<Event>, Error> {
        self.uffd.read_event()
    }

    pub fn unregister_range(&mut self, start: *mut c_void, end: *mut c_void) {
        assert!(
            (start as usize).is_multiple_of(self.page_size)
                && (end as usize).is_multiple_of(self.page_size)
                && end > start
        );
        // SAFETY: start and end are valid and provided by UFFD
        let len = unsafe { end.offset_from_unsigned(start) };
        self.uffd
            .unregister(start, len)
            .expect("range should be valid");
    }

    pub fn addr_to_offset(&self, addr: *mut u8) -> u64 {
        let addr = addr as u64;
        for region in &self.mem_regions {
            if region.contains(addr) {
                return addr - region.base_host_virt_addr + region.offset;
            }
        }

        panic!(
            "Could not find addr: {:#x} within guest region mappings.",
            addr
        );
    }

    pub fn serve_pf(&mut self, addr: *mut u8, len: usize) -> bool {
        // Find the start of the page that the current faulting address belongs to.
        let dst = (addr as usize & !(self.page_size - 1)) as *mut libc::c_void;
        let fault_page_addr = dst as u64;

        for region in self.mem_regions.iter() {
            if region.contains(fault_page_addr) {
                let offset =
                    (region.offset + fault_page_addr - region.base_host_virt_addr) as usize;
                let src = unsafe { self.backing_buffer.add(offset) };
                return self.populate_via_uffdio_copy(src, fault_page_addr, len);
            }
        }

        panic!(
            "Could not find addr: {:?} within guest region mappings.",
            addr
        );
    }

    pub fn size(&self) -> usize {
        self.mem_regions.iter().map(|r| r.size).sum()
    }

    pub fn populate_via_write(&mut self, offset: usize, len: usize) -> usize {
        // man 2 write:
        //
        //    On Linux, write() (and similar system calls) will transfer at most
        //    0x7ffff000 (2,147,479,552) bytes, returning the number of bytes
        //    actually transferred.  (This is true on both 32-bit and 64-bit
        //    systems.)
        const MAX_WRITE_LEN: usize = 2_147_479_552;

        assert!(
            offset.checked_add(len).unwrap() <= self.size(),
            "{} + {} >= {}",
            offset,
            len,
            self.size()
        );

        let mut total_written = 0;
        let mut pos = 0;

        while pos < len {
            let src = unsafe { self.backing_buffer.add(offset + pos) };
            let len_to_write = (len - pos).min(MAX_WRITE_LEN);
            let bytes_written = unsafe {
                libc::pwrite64(
                    self.guest_memfd.as_ref().unwrap().as_raw_fd(),
                    src.cast(),
                    len_to_write,
                    (offset + pos) as libc::off64_t,
                )
            };

            let bytes_written = match bytes_written {
                -1 if vmm_sys_util::errno::Error::last().errno() == libc::EEXIST => {
                    // write() syscall returns -1 with EEXIST when the direct map PTE for the page
                    // has already been removed, indicating the page has been populated. Reset the
                    // corresponding bit in the userfault bitmap to suppress further KVM userfaults
                    // for that page and skip the page.
                    self.userfault_bitmap
                        .as_mut()
                        .unwrap()
                        .reset_addr_range(offset + pos, self.page_size);
                    pos += self.page_size;
                    0
                }
                written @ 0.. => {
                    if (written as usize) < len_to_write {
                        // write() syscall wrote less bytes than we requested when the direct map
                        // PTE for the page has already been removed,
                        // indicating a page has been populated. Reset the
                        // corresponding bit in the userfault bitmap to
                        // suppress further KVM userfaults for that page and
                        // skip the page.
                        self.userfault_bitmap.as_mut().unwrap().reset_addr_range(
                            offset + pos + bytes_written as usize,
                            self.page_size,
                        );
                        pos += self.page_size;
                    }
                    written as usize
                }
                _ => panic!("{:?}", std::io::Error::last_os_error()),
            };

            self.userfault_bitmap
                .as_mut()
                .unwrap()
                .reset_addr_range(offset + pos, bytes_written);

            total_written += bytes_written;
            pos += bytes_written;
        }

        total_written
    }

    fn populate_via_uffdio_copy(&mut self, src: *const u8, dst: u64, len: usize) -> bool {
        // Calculate offset before the match to avoid borrow checker issues
        let offset = self.addr_to_offset(dst as *mut u8) as usize;

        unsafe {
            match self.uffd.copy(src.cast(), dst as *mut _, len, true) {
                // Make sure the UFFD copied some bytes.
                Ok(value) => {
                    assert!(value > 0);
                    // For secret-free VMs, clear the bit in userfault_bitmap after successful UFFDIO_COPY
                    if let Some(bitmap) = &mut self.userfault_bitmap {
                        bitmap.reset_addr_range(offset, len);
                    }
                }
                // Catch EAGAIN errors, which occur when a `remove` event lands in the UFFD
                // queue while we're processing `pagefault` events.
                // The weird cast is because the `bytes_copied` field is based on the
                // `uffdio_copy->copy` field, which is a signed 64 bit integer, and if something
                // goes wrong, it gets set to a -errno code. However, uffd-rs always casts this
                // value to an unsigned `usize`, which scrambled the errno.
                Err(Error::PartiallyCopied(bytes_copied))
                    if bytes_copied == 0 || bytes_copied == (-libc::EAGAIN) as usize =>
                {
                    return false;
                }
                Err(Error::CopyFailed(errno))
                    if std::io::Error::from(errno).raw_os_error().unwrap() == libc::EEXIST => {}
                Err(e) => {
                    panic!("Uffd copy failed: {e:?}");
                }
            }
        };

        true
    }

    fn zero_out(&mut self, addr: u64) -> bool {
        match unsafe { self.uffd.zeropage(addr as *mut _, self.page_size, true) } {
            Ok(_) => true,
            Err(Error::ZeropageFailed(error)) if error as i32 == libc::EAGAIN => false,
            r => panic!("Unexpected zeropage result: {:?}", r),
        }
    }
}

/// Length-prefixed bitcode message iterator matching the VMM's UffdMessageBroker protocol.
/// Messages are framed as: 4-byte LE size header + bitcode payload.
struct UffdMsgIterBitcode {
    stream: UnixStream,
    buffer: Vec<u8>,
    current_pos: usize,
}

impl Iterator for UffdMsgIterBitcode {
    type Item = FaultRequest;

    fn next(&mut self) -> Option<Self::Item> {
        match self.stream.read(&mut self.buffer[self.current_pos..]) {
            Ok(bytes_read) => self.current_pos += bytes_read,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => panic!("Failed to read from stream: {e}"),
        }

        if self.current_pos < 4 {
            return None;
        }

        let size = u32::from_le_bytes(self.buffer[..4].try_into().unwrap()) as usize;
        if self.current_pos < 4 + size {
            return None;
        }

        let decoded: FaultRequest = bitcode::decode(&self.buffer[4..4 + size])
            .unwrap_or_else(|e| panic!("Failed to decode bitcode message: {e}"));
        self.buffer.copy_within(4 + size..self.current_pos, 0);
        self.current_pos -= 4 + size;
        Some(decoded)
    }
}

impl UffdMsgIterBitcode {
    fn new(stream: UnixStream) -> Self {
        Self {
            stream,
            buffer: vec![0u8; 4096],
            current_pos: 0,
        }
    }
}

pub struct Runtime {
    stream: UnixStream,
    backing_file: File,
    backing_memory: *mut u8,
    backing_memory_size: usize,
    handler: UffdHandler,
    apf_stream: UnixStream,
    exitless_vcpus: HashMap<RawFd, ExitlessApfVcpu>,
}

impl Runtime {
    pub fn new(stream: UnixStream, backing_file: File, apf_stream: UnixStream) -> Self {
        let file_meta = backing_file
            .metadata()
            .expect("can not get backing file metadata");
        let backing_memory_size = file_meta.len() as usize;
        // # Safety:
        // File size and fd are valid
        let ret = unsafe {
            libc::mmap(
                ptr::null_mut(),
                backing_memory_size,
                libc::PROT_READ,
                libc::MAP_PRIVATE | libc::MAP_POPULATE,
                backing_file.as_raw_fd(),
                0,
            )
        };
        if ret == libc::MAP_FAILED {
            panic!("mmap on backing file failed");
        }

        let handler = Runtime::construct_handler(&stream, ret.cast(), backing_memory_size);

        Self {
            stream,
            backing_file,
            backing_memory: ret.cast(),
            backing_memory_size,
            handler,
            apf_stream,
            exitless_vcpus: HashMap::new(),
        }
    }

    fn peer_process_credentials(&self) -> libc::ucred {
        let mut creds: libc::ucred = libc::ucred {
            pid: 0,
            gid: 0,
            uid: 0,
        };
        let mut creds_size = size_of::<libc::ucred>() as u32;
        let ret = unsafe {
            libc::getsockopt(
                self.stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&raw mut creds).cast::<c_void>(),
                &raw mut creds_size,
            )
        };
        if ret != 0 {
            panic!("Failed to get peer process credentials");
        }
        creds
    }

    pub fn install_panic_hook(&self) {
        let peer_creds = self.peer_process_credentials();

        let default_panic_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |panic_info| {
            let r = unsafe { libc::kill(peer_creds.pid, libc::SIGKILL) };

            if r != 0 {
                eprintln!("Failed to kill Firecracker process from panic hook");
            }

            default_panic_hook(panic_info);
        }));
    }

    pub fn send_fault_reply(&mut self, fault_reply: FaultReply) {
        let encoded = bitcode::encode(&fault_reply);
        let size = (encoded.len() as u32).to_le_bytes();
        self.stream.write_all(&size).unwrap();
        self.stream.write_all(&encoded).unwrap();
    }

    pub fn send_apf_fault_reply(&mut self, fault_reply: FaultReply) {
        let encoded = bitcode::encode(&fault_reply);
        let size = (encoded.len() as u32).to_le_bytes();
        self.apf_stream.write_all(&size).unwrap();
        self.apf_stream.write_all(&encoded).unwrap();
    }

    pub fn construct_handler(
        stream: &UnixStream,
        backing_memory: *mut u8,
        backing_memory_size: usize,
    ) -> UffdHandler {
        let mut message_buf = vec![0u8; 1024];
        let mut iovecs = [libc::iovec {
            iov_base: message_buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: message_buf.len(),
        }];
        let mut fds = [0; 3];
        let (bytes_read, fds_read) = unsafe {
            stream
                .recv_with_fds(&mut iovecs, &mut fds)
                .expect("recv_with_fds failed")
        };
        message_buf.resize(bytes_read, 0);

        let (guest_memfd, userfault_bitmap_memfd) = if fds_read == 3 {
            (
                Some(unsafe { File::from_raw_fd(fds[1]) }),
                Some(unsafe { File::from_raw_fd(fds[2]) }),
            )
        } else {
            (None, None)
        };

        UffdHandler::from_mappings(
            serde_json::from_slice(message_buf.as_slice()).unwrap(),
            unsafe { File::from_raw_fd(fds[0]) },
            guest_memfd,
            userfault_bitmap_memfd,
            backing_memory,
            backing_memory_size,
        )
    }

    pub fn try_receive_exitless_apf(&mut self) -> std::io::Result<bool> {
        let mut msg_buf = [0u8; 256];
        let mut fds = [0i32; 64];
        // Firecracker sends exitless APF fds over the UFFD socket (self.stream),
        // not the APF socket. Block until we receive the message.
        self.stream.set_nonblocking(false).expect("set nonblocking");
        let (bytes_read, fds_read) = {
            let mut iovecs = [libc::iovec {
                iov_base: msg_buf.as_mut_ptr().cast(),
                iov_len: msg_buf.len(),
            }];
            match unsafe { self.stream.recv_with_fds(&mut iovecs, &mut fds) } {
                Ok(r) => r,
                Err(e) => {
                    self.stream.set_nonblocking(true).expect("Set nonblocking");
                    return Err(std::io::Error::from_raw_os_error(e.errno()));
                }
            }
        };
        self.stream.set_nonblocking(true).expect("set nonblocking");
        if bytes_read > 0 && fds_read == 0 {
            let msg = std::str::from_utf8(&msg_buf[..bytes_read]).unwrap_or("");
            if msg.starts_with("no_exitless_apf") {
                println!("Exitless APF: not supported by kernel, disabled");
                return Ok(false);
            }
        }
        if fds_read == 0 || fds_read % 3 != 0 {
            return Ok(false);
        }
        let num_vcpus = fds_read / 3;
        for i in 0..num_vcpus {
            let base = i * 3;
            let ctx = ExitlessApfVcpu::from_fds(fds[base], fds[base + 1], fds[base + 2])?;
            let eventfd = ctx.eventfd;
            self.exitless_vcpus.insert(eventfd, ctx);
        }
        println!("Exitless APF: {num_vcpus} vCPUs configured");
        Ok(!self.exitless_vcpus.is_empty())
    }

    /// Polls the `UnixStream` and UFFD fds in a loop.
    /// When stream is polled, new uffd is retrieved.
    /// When uffd is polled, page fault is handled by
    /// calling `pf_event_dispatch` with corresponding
    /// uffd object passed in.
    pub fn run(
        &mut self,
        pf_event_dispatch: impl Fn(&mut UffdHandler),
        pf_vcpu_event_dispatch: impl Fn(&mut UffdHandler, usize),
    ) {
        let stream_fd = self.stream.as_raw_fd();
        let apf_stream_fd = self.apf_stream.as_raw_fd();

        let mut pollfds = vec![];

        // Poll the stream for incoming uffds
        pollfds.push(libc::pollfd {
            fd: stream_fd,
            events: libc::POLLIN,
            revents: 0,
        });

        pollfds.push(libc::pollfd {
            fd: self.handler.uffd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });

        // Poll the APF stream for fallback fault requests
        pollfds.push(libc::pollfd {
            fd: apf_stream_fd,
            events: libc::POLLIN,
            revents: 0,
        });

        // Add exitless APF eventfds to pollfds
        for &eventfd in self.exitless_vcpus.keys() {
            pollfds.push(libc::pollfd {
                fd: eventfd,
                events: libc::POLLIN,
                revents: 0,
            });
        }

        let mut uffd_msg_iter =
            UffdMsgIterBitcode::new(self.stream.try_clone().expect("Failed to clone stream"));
        let mut apf_msg_iter = UffdMsgIterBitcode::new(
            self.apf_stream
                .try_clone()
                .expect("Failed to clone APF stream"),
        );

        loop {
            let pollfd_ptr = pollfds.as_mut_ptr();
            let pollfd_size = pollfds.len() as u64;

            // # Safety:
            // Pollfds vector is valid
            let mut nready = unsafe { libc::poll(pollfd_ptr, pollfd_size, -1) };

            if nready == -1 {
                panic!("Could not poll for events!")
            }

            for fd in &pollfds {
                if nready == 0 {
                    break;
                }
                if fd.revents & libc::POLLIN != 0 {
                    nready -= 1;
                    if fd.fd == stream_fd {
                        for fault_request in uffd_msg_iter.by_ref() {
                            let page_size = self.handler.page_size;
                            let offset = fault_request
                                .gpa
                                .and_then(|gpa| self.handler.gpa_to_offset(gpa))
                                .unwrap_or(fault_request.offset as usize);
                            assert!(
                                offset < self.handler.size(),
                                "received bogus offset from firecracker"
                            );
                            pf_vcpu_event_dispatch(&mut self.handler, offset);
                            self.send_fault_reply(fault_request.into_reply(page_size as u64));
                        }
                    } else if fd.fd == apf_stream_fd {
                        // APF fallback path: read from APF socket, reply on APF socket
                        for fault_request in apf_msg_iter.by_ref() {
                            let page_size = self.handler.page_size;
                            let offset = fault_request
                                .gpa
                                .and_then(|gpa| self.handler.gpa_to_offset(gpa))
                                .unwrap_or(fault_request.offset as usize);
                            assert!(
                                offset < self.handler.size(),
                                "received bogus offset from APF handler"
                            );
                            pf_vcpu_event_dispatch(&mut self.handler, offset);
                            self.send_apf_fault_reply(fault_request.into_reply(page_size as u64));
                        }
                    } else if let Some(ctx) = self.exitless_vcpus.get_mut(&fd.fd) {
                        // Exitless APF: drain notify ring and resolve pages
                        ctx.drain_eventfd();
                        while let Some(entry) = ctx.notify_ring().pop() {
                            if let Some(offset) = self.handler.gpa_to_offset(entry.gpa) {
                                pf_vcpu_event_dispatch(&mut self.handler, offset);
                            }
                            ctx.signal_ready(entry.gpa);
                        }
                    } else {
                        // Handle one of uffd page faults
                        pf_event_dispatch(&mut self.handler);
                    }
                }
            }
            // If connection is closed, we can skip the socket from being polled.
            pollfds.retain(|pollfd| pollfd.revents & (libc::POLLRDHUP | libc::POLLHUP) == 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::mem::MaybeUninit;
    use std::os::unix::net::UnixListener;

    use vmm_sys_util::tempdir::TempDir;
    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    unsafe impl Send for Runtime {}

    #[test]
    fn test_runtime() {
        let tmp_dir = TempDir::new().unwrap();
        let dummy_socket_path = tmp_dir.as_path().join("dummy_socket");
        let dummy_socket_path_clone = dummy_socket_path.clone();
        let apf_socket_path = tmp_dir.as_path().join("apf_socket");
        let apf_socket_path_clone = apf_socket_path.clone();

        let mut uninit_runtime = Box::new(MaybeUninit::<Runtime>::uninit());
        // We will use this pointer to bypass a bunch of Rust Safety
        // for the sake of convenience.
        let runtime_ptr = uninit_runtime.as_ptr().cast::<Runtime>();

        let runtime_thread = std::thread::spawn(move || {
            let tmp_file = TempFile::new().unwrap();
            tmp_file.as_file().set_len(0x1000).unwrap();
            let dummy_mem_path = tmp_file.as_path();

            let file = File::open(dummy_mem_path).expect("Cannot open memfile");
            let listener =
                UnixListener::bind(dummy_socket_path).expect("Cannot bind to socket path");
            let apf_listener =
                UnixListener::bind(apf_socket_path).expect("Cannot bind to apf socket path");
            let (stream, _) = listener.accept().expect("Cannot listen on UDS socket");
            let (apf_stream, _) = apf_listener
                .accept()
                .expect("Cannot listen on APF UDS socket");
            apf_stream
                .set_nonblocking(true)
                .expect("Cannot set APF stream non-blocking");
            // Update runtime with actual runtime
            let runtime = uninit_runtime.write(Runtime::new(stream, file, apf_stream));
            runtime.run(|_: &mut UffdHandler| {}, |_: &mut UffdHandler, _: usize| {});
        });

        // wait for runtime thread to initialize itself
        std::thread::sleep(std::time::Duration::from_millis(100));

        let mut stream =
            UnixStream::connect(dummy_socket_path_clone).expect("Cannot connect to the socket");
        let _apf_stream =
            UnixStream::connect(apf_socket_path_clone).expect("Cannot connect to the apf socket");

        #[allow(deprecated)]
        let dummy_memory_region = vec![GuestRegionUffdMapping {
            base_host_virt_addr: 0,
            size: 0x1000,
            offset: 0,
            gpa_start: 0,
            page_size: 4096,
            is_guest_memfd: false,
        }];
        let dummy_memory_region_json = serde_json::to_string(&dummy_memory_region).unwrap();

        // Send the mapping message to the runtime.
        // We expect for the runtime to create a corresponding UffdHandler
        let dummy_file = TempFile::new().unwrap();
        let dummy_fd = dummy_file.as_file().as_raw_fd();
        stream
            .send_with_fd(dummy_memory_region_json.as_bytes(), dummy_fd)
            .unwrap();
        // wait for the runtime thread to process message
        std::thread::sleep(std::time::Duration::from_millis(100));
        unsafe {
            assert_eq!(
                (*runtime_ptr).handler.mem_regions.len(),
                dummy_memory_region.len()
            );
        }

        // There is no way to properly stop runtime, so we send a
        // bitcode-encoded FaultRequest with a bogus offset (beyond handler
        // size) to trigger the assert in the run() loop.
        let bogus_request = FaultRequest {
            vcpu: 0,
            offset: 0xDEAD_0000, // way beyond 0x1000 handler size
            flags: 0,
            gpa: None,
        };
        let encoded = bitcode::encode(&bogus_request);
        let size = (encoded.len() as u32).to_le_bytes();
        use std::io::Write;
        stream.write_all(&size).unwrap();
        stream.write_all(&encoded).unwrap();

        runtime_thread.join().unwrap_err();
    }
}
