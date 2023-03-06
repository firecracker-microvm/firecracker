// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provides functionality for a malicious page fault handler
//! which panics when a page fault occurs.

use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::net::UnixListener;

use nix::unistd::Pid;
use uffd_handler::common::{get_peer_process_credentials, parse_unix_stream, send_sigbus};
use userfaultfd::Uffd;

fn main() {
    let uffd_sock_path = std::env::args().nth(1).expect("No socket path given");

    // Communicate with the Firecracker process to receive the file
    // descriptor to poll for page fault events on.
    let listener = UnixListener::bind(&uffd_sock_path).expect("Cannot bind to socket path");
    let (stream, _) = listener.accept().expect("Cannot listen on UDS socket");

    // Get credentials of Firecracker process sent through the stream.
    let (creds, code) = get_peer_process_credentials(stream.as_raw_fd());
    if code != 0 {
        panic!("Failed to get Firecracker's credentials");
    }
    let firecracker_pid = Pid::from_raw(creds.pid);

    // Parse unix stream to get userfaultfd.
    let (file, _) = parse_unix_stream(&stream).expect("Failed to parse unix stream.");
    let uffd = unsafe { Uffd::from_raw_fd(file.into_raw_fd()) };

    let mut pollfd = libc::pollfd {
        fd: uffd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };

    // Loop, handling incoming events on the userfaultfd file descriptor.
    loop {
        let nready = unsafe { libc::poll(&mut pollfd, 1, -1) };
        if nready == -1 {
            panic!("Could not poll for events!")
        }

        // Read an event from the userfaultfd.
        let event = uffd
            .read_event()
            .expect("Failed to read uffd_msg")
            .expect("uffd_msg not ready");

        // Panic on PageFault event.
        if let userfaultfd::Event::Pagefault { .. } = event {
            send_sigbus(firecracker_pid);
            panic!("Fear me! I am the malicious page fault handler.")
        }
    }
}
