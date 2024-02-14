// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provides functionality for a userspace page fault handler
//! which loads the whole region from the backing memory file
//! when a page fault occurs.

mod uffd_utils;

use std::fs::File;
use std::os::unix::net::UnixListener;

use uffd_utils::{Runtime, UffdHandler};
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
    let len = get_page_size().unwrap(); // page size does not matter, we fault in everything on the first fault

    let mut runtime = Runtime::new(stream, file);
    runtime.run(len, |uffd_handler: &mut UffdHandler| {
        // Read an event from the userfaultfd.
        let event = uffd_handler
            .read_event()
            .expect("Failed to read uffd_msg")
            .expect("uffd_msg not ready");

        match event {
            userfaultfd::Event::Pagefault { .. } => {
                for region in uffd_handler.mem_regions.clone() {
                    uffd_handler
                        .serve_pf(region.mapping.base_host_virt_addr as _, region.mapping.size)
                }
            }
            _ => panic!("Unexpected event on userfaultfd"),
        }
    });
}
