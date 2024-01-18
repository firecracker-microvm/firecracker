// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provides functionality for a userspace page fault handler
//! which loads the whole region from the backing memory file
//! when a page fault occurs.

mod uffd_utils;

use std::fs::File;
use std::os::unix::net::UnixListener;

use uffd_utils::{MemPageState, Runtime, UffdHandler};
use utils::get_page_size;

fn main() {
    let mut args = std::env::args();
    let uffd_sock_path = args.nth(1).expect("No socket path given");
    let mem_file_path = args.next().expect("No memory file given");

    let file = File::open(mem_file_path).expect("Cannot open memfile");

    // Get Uffd from UDS. We'll use the uffd to handle PFs for Firecracker.
    let listener = UnixListener::bind(uffd_sock_path).expect("Cannot bind to socket path");
    let (stream, _) = listener.accept().expect("Cannot listen on UDS socket");

    // Populate a single page from backing memory file.
    // This is just an example, probably, with the worst-case latency scenario,
    // of how memory can be loaded in guest RAM.
    let len = get_page_size().unwrap();

    let mut runtime = Runtime::new(stream, file);
    runtime.run(|uffd_handler: &mut UffdHandler| {
        // Read an event from the userfaultfd.
        let event = uffd_handler
            .read_event()
            .expect("Failed to read uffd_msg")
            .expect("uffd_msg not ready");

        // We expect to receive either a Page Fault or Removed
        // event (if the balloon device is enabled).
        match event {
            userfaultfd::Event::Pagefault { addr, .. } => uffd_handler.serve_pf(addr.cast(), len),
            userfaultfd::Event::Remove { start, end } => uffd_handler.update_mem_state_mappings(
                start as u64,
                end as u64,
                &MemPageState::Removed,
            ),
            _ => panic!("Unexpected event on userfaultfd"),
        }
    });
}
