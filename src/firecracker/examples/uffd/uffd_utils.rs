// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::undocumented_unsafe_blocks,
    // Not everything is used by both binaries
    dead_code
)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::ptr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use userfaultfd::{Error, Event, Uffd};
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

// This is the same with the one used in src/vmm.
/// This describes the mapping between Firecracker base virtual address and offset in the
/// buffer or file backend for a guest memory region. It is used to tell an external
/// process/thread where to populate the guest memory data for this range.
///
/// E.g. Guest memory contents for a region of `size` bytes can be found in the backend
/// at `offset` bytes from the beginning, and should be copied/populated into `base_host_address`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuestRegionMapping {
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

impl GuestRegionMapping {
    fn contains(&self, fault_page_addr: u64) -> bool {
        fault_page_addr >= self.base_host_virt_addr
            && fault_page_addr < self.base_host_virt_addr + self.size as u64
    }
}

/// How the handler is attached to the microVM, from its command line: the `backend_type` it was
/// given, and the snapshot memory file to populate page faults from on a restore. Each mode
/// expects one row of the [`Handshake`] table.
#[derive(Debug)]
pub enum Mode {
    /// `backend_type: Uffd` on restore: the handshake carries `[uffd]`.
    UffdRestore { mem_file: File },
    /// `backend_type: SharedMemfd` on restore: `[uffd, memfd]`.
    SharedMemfdRestore { mem_file: File },
    /// `machine-config.mem_backend` at boot: `[memfd]`.
    SharedMemfdBoot,
}

impl Mode {
    /// Opens the memory file right away, so that a wrong path fails the handler before it
    /// listens on the socket, and Firecracker's connect fails with it.
    fn new(backend_type: &str, mem_file: Option<PathBuf>) -> Self {
        let open = |path: PathBuf| {
            File::open(&path)
                .unwrap_or_else(|err| panic!("Cannot open memory file {path:?}: {err}; {USAGE}"))
        };
        match (backend_type, mem_file) {
            ("Uffd", Some(path)) => Self::UffdRestore {
                mem_file: open(path),
            },
            ("Uffd", None) => {
                panic!("A `Uffd` handler needs a memory file to populate page faults from; {USAGE}")
            }
            ("SharedMemfd", Some(path)) => Self::SharedMemfdRestore {
                mem_file: open(path),
            },
            ("SharedMemfd", None) => Self::SharedMemfdBoot,
            (other, _) => panic!("Unknown backend type `{other}`; {USAGE}"),
        }
    }
}

/// What Firecracker sends on the UDS, once, after guest memory is set up and before any vCPU
/// runs: the guest memory layout as a JSON array of [`GuestRegionMapping`]s, and one or two
/// file descriptors as `SCM_RIGHTS` data, depending on how the microVM was started:
///
/// | How the microVM was started          | fds             |
/// | :----------------------------------- | :-------------- |
/// | restore, `backend_type: Uffd`        | `[uffd]`        |
/// | restore, `backend_type: SharedMemfd` | `[uffd, memfd]` |
/// | boot, `machine-config.mem_backend`   | `[memfd]`       |
///
/// The uffd, when present, is always first; the memfd is always last. The handler knows which
/// row to expect from its [`Mode`].
#[derive(Debug)]
pub struct Handshake {
    pub mappings: Vec<GuestRegionMapping>,
    pub fds: Fds,
}

/// The file descriptors of a [`Handshake`], one variant per row of its table.
#[derive(Debug)]
pub enum Fds {
    Uffd(Uffd),
    UffdAndMemfd(Uffd, File),
    Memfd(File),
}

impl Handshake {
    fn try_receive(stream: &UnixStream) -> Result<(String, Vec<File>), std::io::Error> {
        let mut message_buf = vec![0u8; 1024];
        // Room for the most fds a handshake carries; `from_message` checks the count against
        // what the mode expects.
        let mut fds = [-1 as RawFd; 2];
        let mut iovecs = [libc::iovec {
            iov_base: message_buf.as_mut_ptr().cast::<c_void>(),
            iov_len: message_buf.len(),
        }];
        // SAFETY: `iovecs` points into `message_buf`, which outlives the call.
        let (bytes_read, fd_count) = unsafe { stream.recv_with_fds(&mut iovecs, &mut fds)? };
        message_buf.resize(bytes_read, 0);
        // SAFETY: the first `fd_count` entries are fds we now own and nobody else closes.
        let files = fds[..fd_count]
            .iter()
            .map(|&fd| unsafe { File::from_raw_fd(fd) })
            .collect();

        // We do not expect to receive non-UTF-8 data from Firecracker, so this is probably
        // an error we can't recover from. Just immediately abort
        let body = String::from_utf8(message_buf.clone()).unwrap_or_else(|_| {
            panic!(
                "Received body is not a utf-8 valid string. Raw bytes received: {message_buf:#?}"
            )
        });
        Ok((body, files))
    }

    /// Receives the handshake from `stream`, retrying a few times if no fd came along, and
    /// checks that it carries exactly the fds `mode` expects (see above).
    pub fn receive(stream: &UnixStream, mode: &Mode) -> Self {
        // Sometimes, reading from the stream succeeds but we don't receive any
        // descriptor. We don't really have a good understanding why this is
        // happening, but let's try to be a bit more robust and retry a few times
        // before we declare defeat.
        for _ in 1..=5 {
            match Self::try_receive(stream) {
                Ok((body, files)) if !files.is_empty() => {
                    return Self::from_message(&body, files, mode);
                }
                Ok((body, _)) => {
                    println!(
                        "Didn't receive any fd over socket. We received: '{body}'. Retrying..."
                    );
                }
                Err(err) => {
                    println!("Could not get fds and mapping from Firecracker: {err}. Retrying...");
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        panic!("Could not get fds and mappings after 5 retries");
    }

    fn from_message(body: &str, files: Vec<File>, mode: &Mode) -> Self {
        let mappings = serde_json::from_str::<Vec<GuestRegionMapping>>(body).unwrap_or_else(|_| {
            panic!("Cannot deserialize memory mappings. Received body: {body}")
        });
        assert!(
            !mappings.is_empty(),
            "Cannot get the first mapping. Mappings size is 0. Received body: {body}"
        );

        let uffd = |file: File| unsafe { Uffd::from_raw_fd(file.into_raw_fd()) };
        let memfd = |file: File| {
            // The memfd is all of guest memory, laid out like a memory snapshot file.
            let memsize: u64 = mappings.iter().map(|r| r.size as u64).sum();
            let memfd_size = file.metadata().expect("cannot stat memfd").len();
            assert_eq!(
                memsize, memfd_size,
                "memfd size does not match the sum of the region sizes"
            );
            println!("Received guest memory memfd of {memfd_size} bytes");
            file
        };
        let mut files = files.into_iter();
        let fds = match (mode, files.next(), files.next()) {
            (Mode::UffdRestore { .. }, Some(uffd_file), None) => Fds::Uffd(uffd(uffd_file)),
            (Mode::SharedMemfdRestore { .. }, Some(uffd_file), Some(memfd_file)) => {
                Fds::UffdAndMemfd(uffd(uffd_file), memfd(memfd_file))
            }
            (Mode::SharedMemfdBoot, Some(memfd_file), None) => Fds::Memfd(memfd(memfd_file)),
            (mode, first, second) => panic!(
                "Unexpected number of fds in handshake for {mode:?}: {}",
                first.is_some() as usize + second.is_some() as usize
            ),
        };

        Self { mappings, fds }
    }
}

#[derive(Debug)]
pub struct UffdHandler {
    pub mem_regions: Vec<GuestRegionMapping>,
    pub page_size: usize,
    backing_buffer: *const u8,
    uffd: Uffd,
}

impl UffdHandler {
    /// Serves page faults on `uffd` for the regions in `mappings`, from a mapping of the
    /// snapshot memory file at `backing_buffer`, which is `size` bytes long.
    pub fn new(
        mappings: Vec<GuestRegionMapping>,
        uffd: Uffd,
        backing_buffer: *const u8,
        size: usize,
    ) -> Self {
        let memsize: usize = mappings.iter().map(|r| r.size).sum();
        // Page size is the same for all memory regions, so just grab the first one
        let page_size = mappings.first().expect("no memory region").page_size;

        // Make sure memory size matches backing data size.
        assert_eq!(memsize, size);
        assert!(page_size.is_power_of_two());

        Self {
            mem_regions: mappings,
            page_size,
            backing_buffer,
            uffd,
        }
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

    pub fn serve_pf(&mut self, addr: *mut u8, len: usize) -> bool {
        // Find the start of the page that the current faulting address belongs to.
        let dst = (addr as usize & !(self.page_size - 1)) as *mut libc::c_void;
        let fault_page_addr = dst as u64;

        for region in self.mem_regions.iter() {
            if region.contains(fault_page_addr) {
                return self.populate_from_file(region, fault_page_addr, len);
            }
        }

        panic!(
            "Could not find addr: {:?} within guest region mappings.",
            addr
        );
    }

    fn populate_from_file(&self, region: &GuestRegionMapping, dst: u64, len: usize) -> bool {
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
}

/// Command line of the example handlers:
/// `<Uffd|SharedMemfd> <backend socket path> [<snapshot memory file>]`.
///
/// The first argument is the `backend_type` the handler is attached to Firecracker with, the
/// socket is where it listens for Firecracker's handshake. The memory file is what page faults
/// are populated from, and is needed whenever a uffd is handed over (a restore). It is left out
/// when the handler is started for a boot with `machine-config.mem_backend`, where there are no
/// page faults to serve and the handshake carries the guest memory memfd alone.
#[derive(Debug)]
pub struct Args {
    pub mode: Mode,
    pub socket_path: PathBuf,
}

const USAGE: &str =
    "usage: <handler> <Uffd|SharedMemfd> <backend socket path> [<snapshot memory file>]";

impl Args {
    pub fn parse() -> Self {
        let mut args = std::env::args().skip(1);
        let backend_type = args
            .next()
            .unwrap_or_else(|| panic!("No backend type given; {USAGE}"));
        let socket_path = PathBuf::from(
            args.next()
                .unwrap_or_else(|| panic!("No socket path given; {USAGE}")),
        );
        let mem_file = args.next().map(PathBuf::from);
        assert!(args.next().is_none(), "Unexpected extra arguments; {USAGE}");
        Self {
            mode: Mode::new(&backend_type, mem_file),
            socket_path,
        }
    }

    /// Waits for Firecracker to connect and returns a runtime for that connection.
    pub fn into_runtime(self) -> Runtime {
        // Firecracker connects to the socket for the handshake.
        let listener = UnixListener::bind(self.socket_path).expect("Cannot bind to socket path");
        let (stream, _) = listener.accept().expect("Cannot listen on UDS socket");

        Runtime::new(stream, self.mode)
    }
}

#[derive(Debug)]
pub struct Runtime {
    stream: UnixStream,
    /// Holds the snapshot memory file page faults are populated from, on a restore.
    mode: Mode,
    backing_memory: *mut u8,
    backing_memory_size: usize,
    uffds: HashMap<i32, UffdHandler>,
    /// The guest memory memfd, when Firecracker shares it (`SharedMemfd` on restore, or
    /// `machine-config.mem_backend` at boot). These example handlers only hold on to it.
    memfd: Option<File>,
}

impl Runtime {
    pub fn new(stream: UnixStream, mode: Mode) -> Self {
        let backing_file = match &mode {
            Mode::UffdRestore { mem_file } | Mode::SharedMemfdRestore { mem_file } => {
                Some(mem_file)
            }
            Mode::SharedMemfdBoot => None,
        };
        let (backing_memory, backing_memory_size) = match backing_file {
            Some(backing_file) => {
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
                (ret.cast(), backing_memory_size)
            }
            None => (ptr::null_mut(), 0),
        };

        Self {
            stream,
            mode,
            backing_memory,
            backing_memory_size,
            uffds: HashMap::default(),
            memfd: None,
        }
    }

    /// The guest memory memfd received from Firecracker, if it shared one.
    pub fn memfd(&self) -> Option<&File> {
        self.memfd.as_ref()
    }

    /// Starts serving page faults on `uffd` for `mappings`, from the memory file.
    fn add_uffd(
        &mut self,
        pollfds: &mut Vec<libc::pollfd>,
        mappings: Vec<GuestRegionMapping>,
        uffd: Uffd,
    ) {
        let handler = UffdHandler::new(
            mappings,
            uffd,
            self.backing_memory,
            self.backing_memory_size,
        );
        pollfds.push(libc::pollfd {
            fd: handler.uffd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
        self.uffds.insert(handler.uffd.as_raw_fd(), handler);
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

    /// Polls the `UnixStream` and UFFD fds in a loop.
    /// When stream is polled, the handshake is received: a new uffd to
    /// serve page faults for, the guest memory memfd, or both.
    /// When uffd is polled, page fault is handled by
    /// calling `pf_event_dispatch` with corresponding
    /// uffd object passed in.
    pub fn run(&mut self, pf_event_dispatch: impl Fn(&mut UffdHandler)) {
        let mut pollfds = vec![];

        // Poll the stream for Firecracker's handshake
        pollfds.push(libc::pollfd {
            fd: self.stream.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });

        loop {
            let pollfd_ptr = pollfds.as_mut_ptr();
            let pollfd_size = pollfds.len() as u64;

            // # Safety:
            // Pollfds vector is valid
            let mut nready = unsafe { libc::poll(pollfd_ptr, pollfd_size, -1) };

            if nready == -1 {
                panic!("Could not poll for events!")
            }

            for i in 0..pollfds.len() {
                if nready == 0 {
                    break;
                }
                if pollfds[i].revents & libc::POLLIN != 0 {
                    nready -= 1;
                    if pollfds[i].fd == self.stream.as_raw_fd() {
                        // Handle the handshake from the stream.
                        let Handshake { mappings, fds } =
                            Handshake::receive(&self.stream, &self.mode);
                        match fds {
                            Fds::Uffd(uffd) => self.add_uffd(&mut pollfds, mappings, uffd),
                            Fds::UffdAndMemfd(uffd, memfd) => {
                                self.memfd = Some(memfd);
                                self.add_uffd(&mut pollfds, mappings, uffd);
                            }
                            Fds::Memfd(memfd) => self.memfd = Some(memfd),
                        }
                    } else {
                        // Handle one of uffd page faults
                        pf_event_dispatch(self.uffds.get_mut(&pollfds[i].fd).unwrap());
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

        let mut uninit_runtime = Box::new(MaybeUninit::<Runtime>::uninit());
        // We will use this pointer to bypass a bunch of Rust Safety
        // for the sake of convenience.
        let runtime_ptr = uninit_runtime.as_ptr().cast::<Runtime>();

        let runtime_thread = std::thread::spawn(move || {
            let tmp_file = TempFile::new().unwrap();
            tmp_file.as_file().set_len(0x1000).unwrap();
            let mode = Mode::UffdRestore {
                mem_file: File::open(tmp_file.as_path()).unwrap(),
            };

            let listener =
                UnixListener::bind(dummy_socket_path).expect("Cannot bind to socket path");
            let (stream, _) = listener.accept().expect("Cannot listen on UDS socket");
            // Update runtime with actual runtime
            let runtime = uninit_runtime.write(Runtime::new(stream, mode));
            runtime.run(|_: &mut UffdHandler| {});
        });

        // wait for runtime thread to initialize itself
        std::thread::sleep(std::time::Duration::from_millis(100));

        let stream =
            UnixStream::connect(dummy_socket_path_clone).expect("Cannot connect to the socket");

        let dummy_memory_region = vec![GuestRegionMapping {
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
        let error_memory_region = vec![GuestRegionMapping {
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

    /// A handler started for a boot (no memory file) receives the guest memory memfd alone,
    /// keeps it, and has no uffd to serve.
    #[test]
    fn test_runtime_memfd_only() {
        let tmp_dir = TempDir::new().unwrap();
        let socket_path = tmp_dir.as_path().join("memfd_socket");
        let socket_path_clone = socket_path.clone();

        let mut uninit_runtime = Box::new(MaybeUninit::<Runtime>::uninit());
        let runtime_ptr = uninit_runtime.as_ptr().cast::<Runtime>();

        let runtime_thread = std::thread::spawn(move || {
            let listener = UnixListener::bind(socket_path).expect("Cannot bind to socket path");
            let (stream, _) = listener.accept().expect("Cannot listen on UDS socket");
            let runtime = uninit_runtime.write(Runtime::new(stream, Mode::SharedMemfdBoot));
            runtime.run(|_: &mut UffdHandler| panic!("no page faults to serve"));
        });
        std::thread::sleep(std::time::Duration::from_millis(100));

        let stream = UnixStream::connect(socket_path_clone).expect("Cannot connect to the socket");
        let regions = vec![GuestRegionMapping {
            base_host_virt_addr: 0,
            size: 0x2000,
            offset: 0,
            page_size: 4096,
        }];
        let regions_json = serde_json::to_string(&regions).unwrap();

        // Stands in for the memfd: a regular file as large as the regions.
        let memfd = TempFile::new().unwrap();
        memfd.as_file().set_len(0x2000).unwrap();
        stream
            .send_with_fd(regions_json.as_bytes(), memfd.as_file().as_raw_fd())
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        unsafe {
            assert!((*runtime_ptr).uffds.is_empty());
            let received = (*runtime_ptr).memfd().expect("memfd not received");
            assert_eq!(received.metadata().unwrap().len(), 0x2000);
        }

        // A memfd whose size does not match the regions is refused.
        let bad_memfd = TempFile::new().unwrap();
        bad_memfd.as_file().set_len(0x1000).unwrap();
        stream
            .send_with_fd(regions_json.as_bytes(), bad_memfd.as_file().as_raw_fd())
            .unwrap();
        runtime_thread.join().unwrap_err();
    }

    /// A `Uffd` handler attached with `backend_type: SharedMemfd` is sent `[uffd, memfd]`, which
    /// is not what it expects, and refuses the handshake.
    #[test]
    fn test_runtime_uffd_handler_refuses_memfd() {
        let tmp_dir = TempDir::new().unwrap();
        let socket_path = tmp_dir.as_path().join("uffd_socket");
        let socket_path_clone = socket_path.clone();

        let mut uninit_runtime = Box::new(MaybeUninit::<Runtime>::uninit());

        let runtime_thread = std::thread::spawn(move || {
            let mem_file = TempFile::new().unwrap();
            mem_file.as_file().set_len(0x1000).unwrap();
            let mode = Mode::UffdRestore {
                mem_file: File::open(mem_file.as_path()).unwrap(),
            };
            let listener = UnixListener::bind(socket_path).expect("Cannot bind to socket path");
            let (stream, _) = listener.accept().expect("Cannot listen on UDS socket");
            let runtime = uninit_runtime.write(Runtime::new(stream, mode));
            runtime.run(|_: &mut UffdHandler| {});
        });
        std::thread::sleep(std::time::Duration::from_millis(100));

        let stream = UnixStream::connect(socket_path_clone).expect("Cannot connect to the socket");
        let regions = vec![GuestRegionMapping {
            base_host_virt_addr: 0,
            size: 0x1000,
            offset: 0,
            page_size: 4096,
        }];
        let regions_json = serde_json::to_string(&regions).unwrap();

        let uffd = TempFile::new().unwrap();
        let memfd = TempFile::new().unwrap();
        stream
            .send_with_fds(
                &[regions_json.as_bytes()],
                &[uffd.as_file().as_raw_fd(), memfd.as_file().as_raw_fd()],
            )
            .unwrap();
        runtime_thread.join().unwrap_err();
    }
}
