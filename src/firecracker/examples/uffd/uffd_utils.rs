// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Not everything is used by both binaries
#![allow(dead_code)]

mod userfault_bitmap;

use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::fs::File;
use std::io::Write;
use std::num::NonZero;
use std::ops::DerefMut;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::net::UnixStream;
use std::ptr;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use userfaultfd::{Error, Event, Uffd};
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

use crate::uffd_utils::userfault_bitmap::UserfaultBitmap;

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
    /// The configured page size for this memory region.
    pub page_size: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FaultRequest {
    /// vCPU that encountered the fault (not meaningful to Fission)
    pub vcpu: u32,
    /// Offset in guest_memfd where the fault occured
    pub offset: u64,
    /// Flags (not meaningful to Fission)
    pub flags: u64,
    /// Async PF token (not meaningful to Fission)
    pub token: Option<u32>,
}

impl FaultRequest {
    pub fn into_reply(self, len: u64) -> FaultReply {
        FaultReply {
            vcpu: Some(self.vcpu),
            offset: self.offset,
            len,
            flags: self.flags,
            token: self.token,
            zero: false,
        }
    }
}

/// FaultReply
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FaultReply {
    /// vCPU that encountered the fault, from `FaultRequest` (if present, otherwise 0)
    pub vcpu: Option<u32>,
    /// Offset in guest_memfd where population started
    pub offset: u64,
    /// Length of populated area
    pub len: u64,
    /// Flags, must be copied from `FaultRequest`, otherwise 0
    pub flags: u64,
    /// Async PF token, must be copied from `FaultRequest`, otherwise None
    pub token: Option<u32>,
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
    uffd: Uffd,
    removed_pages: HashSet<u64>,
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
                    removed_pages: HashSet::new(),
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
                removed_pages: HashSet::new(),
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

    pub fn read_event(&mut self) -> Result<Option<Event>, Error> {
        self.uffd.read_event()
    }

    pub fn mark_range_removed(&mut self, start: u64, end: u64) {
        let pfn_start = start / self.page_size as u64;
        let pfn_end = end / self.page_size as u64;

        for pfn in pfn_start..pfn_end {
            self.removed_pages.insert(pfn);
        }
    }

    pub fn serve_pf(&mut self, addr: *mut u8, len: usize) -> bool {
        // Find the start of the page that the current faulting address belongs to.
        let dst = (addr as usize & !(self.page_size - 1)) as *mut libc::c_void;
        let fault_page_addr = dst as u64;
        let fault_pfn = fault_page_addr / self.page_size as u64;

        if self.removed_pages.contains(&fault_pfn) {
            self.zero_out(fault_page_addr);
            return true;
        } else {
            for region in self.mem_regions.iter() {
                if region.contains(fault_page_addr) {
                    return self.populate_from_file(region, fault_page_addr, len);
                }
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

    fn populate_from_file(&self, region: &GuestRegionUffdMapping, dst: u64, len: usize) -> bool {
        let offset = dst - region.base_host_virt_addr;
        let src = self.backing_buffer as u64 + region.offset + offset;

        unsafe {
            match self.uffd.copy(src as *const _, dst as *mut _, len, true) {
                // Make sure the UFFD copied some bytes.
                Ok(value) => assert!(value > 0),
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

    fn zero_out(&mut self, addr: u64) {
        let ret = unsafe {
            self.uffd
                .zeropage(addr as *mut _, self.page_size, true)
                .expect("Uffd zeropage failed")
        };
        // Make sure the UFFD zeroed out some bytes.
        assert!(ret > 0);
    }
}

#[derive(Debug)]
pub struct Runtime {
    stream: UnixStream,
    backing_file: File,
    backing_memory: *mut u8,
    backing_memory_size: usize,
    uffds: HashMap<i32, UffdHandler>,
    main_handler_fd: Option<i32>,
}

impl Runtime {
    pub fn new(stream: UnixStream, backing_file: File) -> Self {
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
                libc::MAP_PRIVATE,
                backing_file.as_raw_fd(),
                0,
            )
        };
        if ret == libc::MAP_FAILED {
            panic!("mmap on backing file failed");
        }

        Self {
            stream,
            backing_file,
            backing_memory: ret.cast(),
            backing_memory_size,
            uffds: HashMap::default(),
            main_handler_fd: None,
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
        let reply = UffdMsgToFirecracker::FaultRep(fault_reply);
        let reply_json = serde_json::to_string(&reply).unwrap();
        self.stream.write_all(reply_json.as_bytes()).unwrap();
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
        let mut pollfds = vec![];

        // Poll the stream for incoming uffds
        pollfds.push(libc::pollfd {
            fd: self.stream.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });

        // We can skip polling on stream fd if
        // the connection is closed.
        let mut skip_stream: usize = 0;
        loop {
            let pollfd_ptr = pollfds[skip_stream..].as_mut_ptr();
            let pollfd_size = pollfds[skip_stream..].len() as u64;

            // # Safety:
            // Pollfds vector is valid
            let mut nready = unsafe { libc::poll(pollfd_ptr, pollfd_size, -1) };

            if nready == -1 {
                panic!("Could not poll for events!")
            }

            for i in skip_stream..pollfds.len() {
                if nready == 0 {
                    break;
                }
                if pollfds[i].revents & libc::POLLIN != 0 {
                    nready -= 1;
                    if pollfds[i].fd == self.stream.as_raw_fd() {
                        const BUFFER_SIZE: usize = 4096;

                        let mut buffer = [0u8; BUFFER_SIZE];
                        let mut fds = [0; 3];
                        let mut current_pos = 0;
                        let mut secret_free = false;
                        let mut exit_loop = false;

                        loop {
                            // Read more data into the buffer if there's space
                            let mut iov = [libc::iovec {
                                iov_base: (buffer[current_pos..]).as_mut_ptr() as *mut libc::c_void,
                                iov_len: buffer.len() - current_pos,
                            }];

                            if current_pos < BUFFER_SIZE {
                                let ret = unsafe { self.stream.recv_with_fds(&mut iov, &mut fds) };
                                match ret {
                                    Ok((0, _)) => break,
                                    Ok((n, 1)) => current_pos += n,
                                    Ok((n, 3)) => {
                                        current_pos += n;
                                        secret_free = true;
                                    }
                                    Ok((n, 0)) | Ok((_, n)) => panic!("Wrong number of fds: {}", n),
                                    Err(e) if e.errno() == libc::EAGAIN => {
                                        if exit_loop {
                                            break;
                                        }
                                        continue;
                                    }
                                    Err(e) => panic!("Read error: {}", e),
                                }

                                exit_loop = false;
                            }

                            let mut parser =
                                serde_json::Deserializer::from_slice(&buffer[..current_pos])
                                    .into_iter::<UffdMsgFromFirecracker>();
                            let mut total_consumed = 0;
                            let mut needs_more = false;

                            while let Some(result) = parser.next() {
                                match result {
                                    Ok(UffdMsgFromFirecracker::Mappings(mappings)) => {
                                        let (guest_memfd, userfault_bitmap_memfd) = if secret_free {
                                            (
                                                Some(unsafe { File::from_raw_fd(fds[1]) }),
                                                Some(unsafe { File::from_raw_fd(fds[2]) }),
                                            )
                                        } else {
                                            (None, None)
                                        };

                                        // Handle new uffd from stream
                                        let handler = UffdHandler::from_mappings(
                                            mappings,
                                            unsafe { File::from_raw_fd(fds[0]) },
                                            guest_memfd,
                                            userfault_bitmap_memfd,
                                            self.backing_memory,
                                            self.backing_memory_size,
                                        );

                                        let fd = handler.uffd.as_raw_fd();

                                        pollfds.push(libc::pollfd {
                                            fd,
                                            events: libc::POLLIN,
                                            revents: 0,
                                        });
                                        self.uffds.insert(fd, handler);

                                        // If connection is closed, we can skip the socket from
                                        // being polled.
                                        if pollfds[i].revents & (libc::POLLRDHUP | libc::POLLHUP)
                                            != 0
                                        {
                                            skip_stream = 1;
                                        }

                                        total_consumed = parser.byte_offset();
                                    }
                                    Ok(UffdMsgFromFirecracker::FaultReq(fault_request)) => {
                                        let fd = self.main_handler_fd.unwrap();

                                        let mut locked_uffd = self.uffds.get_mut(&fd).unwrap();
                                        let page_size = locked_uffd.page_size;

                                        assert!(
                                            (fault_request.offset as usize) < locked_uffd.size(),
                                            "received bogus offset from firecracker"
                                        );

                                        // Handle one of FaultRequest page faults
                                        pf_vcpu_event_dispatch(
                                            locked_uffd.deref_mut(),
                                            fault_request.offset as usize,
                                        );

                                        self.send_fault_reply(
                                            fault_request.into_reply(page_size as u64),
                                        );

                                        // If connection is closed, we can skip the socket from
                                        // being polled.
                                        if pollfds[i].revents & (libc::POLLRDHUP | libc::POLLHUP)
                                            != 0
                                        {
                                            skip_stream = 1;
                                        }

                                        total_consumed = parser.byte_offset();
                                    }
                                    Err(e) if e.is_eof() => {
                                        needs_more = true;
                                        break;
                                    }
                                    Err(e) => {
                                        println!(
                                            "Buffer content: {:?}",
                                            std::str::from_utf8(&buffer[..current_pos])
                                        );
                                        panic!("Invalid JSON: {}", e);
                                    }
                                }
                            }

                            if total_consumed > 0 {
                                buffer.copy_within(total_consumed..current_pos, 0);
                                current_pos -= total_consumed;
                            }

                            if needs_more {
                                continue;
                            }

                            // We consumed all data in the buffer, but the socket may have remaining
                            // unread data so we attempt to read from it
                            // and exit the loop only if we confirm that nothing is in
                            // there.
                            if current_pos == 0 {
                                exit_loop = true;
                            }
                        }
                    } else {
                        // Handle one of uffd page faults
                        pf_event_dispatch(self.uffds.get_mut(&pollfds[i].fd).unwrap());
                    }
                }
            }
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
            let (stream, _) = listener.accept().expect("Cannot listen on UDS socket");
            // Update runtime with actual runtime
            let runtime = uninit_runtime.write(Runtime::new(stream, file));
            runtime.run(|_: &mut UffdHandler| {});
        });

        // wait for runtime thread to initialize itself
        std::thread::sleep(std::time::Duration::from_millis(100));

        let stream =
            UnixStream::connect(dummy_socket_path_clone).expect("Cannot connect to the socket");

        let dummy_memory_region = vec![GuestRegionUffdMapping {
            base_host_virt_addr: 0,
            size: 0x1000,
            offset: 0,
            page_size: 4096,
        }];
        let dummy_memory_region_json = serde_json::to_string(&dummy_memory_region).unwrap();

        let dummy_file_1 = TempFile::new().unwrap();
        let dummy_fd_1 = dummy_file_1.as_file().as_raw_fd();
        stream
            .send_with_fd(dummy_memory_region_json.as_bytes(), dummy_fd_1)
            .unwrap();
        // wait for the runtime thread to process message
        std::thread::sleep(std::time::Duration::from_millis(100));
        unsafe {
            assert_eq!((*runtime_ptr).uffds.len(), 1);
        }

        let dummy_file_2 = TempFile::new().unwrap();
        let dummy_fd_2 = dummy_file_2.as_file().as_raw_fd();
        stream
            .send_with_fd(dummy_memory_region_json.as_bytes(), dummy_fd_2)
            .unwrap();
        // wait for the runtime thread to process message
        std::thread::sleep(std::time::Duration::from_millis(100));
        unsafe {
            assert_eq!((*runtime_ptr).uffds.len(), 2);
        }

        // there is no way to properly stop runtime, so
        // we send a message with an incorrect memory region
        // to cause runtime thread to panic
        let error_memory_region = vec![GuestRegionUffdMapping {
            base_host_virt_addr: 0,
            size: 0,
            offset: 0,
            page_size: 4096,
        }];
        let error_memory_region_json = serde_json::to_string(&error_memory_region).unwrap();
        stream
            .send_with_fd(error_memory_region_json.as_bytes(), dummy_fd_2)
            .unwrap();

        runtime_thread.join().unwrap_err();
    }
}
