// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provides functionality for a userspace page fault handler
//! which loads the whole region from the backing memory file
//! when a page fault occurs.

mod uffd_utils;

use std::fs::File;
use std::os::unix::net::UnixListener;

use uffd_utils::{Runtime, UffdHandler};
use utils::time::{ClockType, get_time_us};

fn main() {
    let mut args = std::env::args();
    let uffd_sock_path = args.nth(1).expect("No socket path given");
    // The snapshot memory file to populate page faults from. A handler started as the memory
    // backend of a boot has none: it only receives the guest memory memfd.
    let mem_file = args
        .next()
        .map(|path| File::open(path).expect("Cannot open memfile"));

    // Get Uffd from UDS. We'll use the uffd to handle PFs for Firecracker.
    let listener = UnixListener::bind(uffd_sock_path).expect("Cannot bind to socket path");
    let (stream, _) = listener.accept().expect("Cannot listen on UDS socket");

    let mut runtime = Runtime::new(stream, mem_file);
    runtime.install_panic_hook();
    runtime.run(|uffd_handler: &mut UffdHandler| {
        // Read an event from the userfaultfd.
        let event = uffd_handler
            .read_event()
            .expect("Failed to read uffd_msg")
            .expect("uffd_msg not ready");

        match event {
            userfaultfd::Event::Pagefault { .. } => {
                let start = get_time_us(ClockType::Monotonic);
                for region in uffd_handler.mem_regions.clone() {
                    uffd_handler.serve_pf(region.base_host_virt_addr as _, region.size);
                }
                let end = get_time_us(ClockType::Monotonic);

                println!("Finished Faulting All: {}us", end - start);
            }
            _ => panic!("Unexpected event on userfaultfd"),
        }
    });
}
