// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provides functionality for a userspace page fault handler
//! which loads the whole region from the backing memory file
//! when a page fault occurs.

mod common;
mod handler;

use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::{mem, process, ptr};
use userfaultfd::Uffd;

use common::{
    create_mem_regions, parse_unix_stream, GuestRegionUffdMapping, MemPageState, MemRegion,
};
use handler::UffdPfHandler;

const EXIT_CODE_ERROR: i32 = 1;

fn create_handler() -> UffdPfHandler {
    let uffd_sock_path = std::env::args().nth(1).expect("No socket path given");
    let mem_file_path = std::env::args().nth(2).expect("No memory file given");

    let file = File::open(mem_file_path).expect("Cannot open memfile");
    let size = file.metadata().unwrap().len() as usize;

    // mmap a memory area used to bring in the faulting regions.
    // SAFETY: Safe because the parameters are valid.
    let memfile_buffer = unsafe {
        libc::mmap(
            ptr::null_mut(),
            size,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            file.as_raw_fd(),
            0,
        )
    };
    if memfile_buffer == libc::MAP_FAILED {
        panic!("mmap failed");
    }

    // Get Uffd from UDS. We'll use the uffd to handle PFs for Firecracker.
    let listener = UnixListener::bind(uffd_sock_path).expect("Cannot bind to socket path");

    let (stream, _) = listener.accept().expect("Cannot listen on UDS socket");

    let (file, msg_body) = parse_unix_stream(&stream);
    // SAFETY: Safe because it wraps the Uffd object around the valid raw file descriptor.
    let uffd = unsafe { Uffd::from_raw_fd(file.into_raw_fd()) };

    // Create guest memory regions from mappings received from Firecracker process.
    let mappings = serde_json::from_str::<Vec<GuestRegionUffdMapping>>(&msg_body)
        .expect("Cannot deserialize memory mappings.");
    let memsize: usize = mappings.iter().map(|r| r.size).sum();
    let mem_regions = create_mem_regions(&mappings);

    // Make sure memory size matches backing data size.
    assert_eq!(memsize, size);

    // Get credentials of Firecracker process sent through the stream.
    let creds: libc::ucred = get_peer_process_credentials(stream);

    UffdPfHandler::new(mem_regions, memfile_buffer, uffd, creds.pid as u32)
}

fn get_peer_process_credentials(stream: UnixStream) -> libc::ucred {
    let mut creds: libc::ucred = libc::ucred {
        pid: 0,
        gid: 0,
        uid: 0,
    };
    let mut creds_size = mem::size_of::<libc::ucred>() as u32;
    let creds_ref: *mut libc::ucred = &mut creds as *mut _;

    // Retrieve socket options in order to obtain credentials of peer process
    // (in our case, Firecracker's credentials).
    // SAFETY: Safe because all parameters are valid.
    let ret = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            creds_ref.cast::<libc::c_void>(),
            &mut creds_size as *mut libc::socklen_t,
        )
    };
    if ret != 0 {
        panic!("Failed to get peer process credentials");
    }

    creds
}

fn main() {
    let mut uffd_handler = create_handler();

    let mut pollfd = libc::pollfd {
        fd: uffd_handler.uffd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };

    // Loop, handling incoming events on the userfaultfd file descriptor.
    loop {
        // SAFETY: Safe because fd, nfds and timeout are valid parameters.
        let nready = unsafe { libc::poll(&mut pollfd, 1, -1) };
        if nready == -1 {
            panic!("Could not poll for events!")
        }

        // Read an event from the userfaultfd.
        let event = uffd_handler
            .uffd
            .read_event()
            .expect("Failed to read uffd_msg")
            .expect("uffd_msg not ready");

        // We expect to receive either a Page Fault or Removed
        // event (if the balloon device is enabled).
        match event {
            userfaultfd::Event::Pagefault { addr, .. } => uffd_handler.serve_pf(addr as usize),
            userfaultfd::Event::Remove { start, end } => uffd_handler.update_mem_state_mappings(
                start as usize,
                end as usize,
                MemPageState::Removed,
            ),
            _ => {
                println!("Unexpected event received on userfaultfd.");
                process::exit(EXIT_CODE_ERROR)
            }
        }
    }
}
