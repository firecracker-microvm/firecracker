// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provides functionality for a userspace page fault handler
//! which loads the whole region from the backing memory file
//! when a page fault occurs.

mod uffd_utils;

use std::os::unix::io::AsRawFd;

use uffd_utils::{create_pf_handler, MemPageState};
use utils::get_page_size;

fn main() {
    let mut uffd_handler = create_pf_handler();

    // Populate a single page from backing memory file.
    // This is just an example, probably, with the worst-case latency scenario,
    // of how memory can be loaded in guest RAM.
    let len = get_page_size().unwrap();

    let mut pollfd = libc::pollfd {
        fd: uffd_handler.uffd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // Loop, handling incoming events on the userfaultfd file descriptor.
    loop {
        // See what poll() tells us about the userfaultfd.
        let nready = unsafe { libc::poll(&mut pollfd, 1, -1) };

        if nready == -1 {
            panic!("Could not poll for events!")
        }

        let revents = pollfd.revents;

        println!(
            "poll() returns: nready = {}; POLLIN = {}; POLLERR = {}",
            nready,
            revents & libc::POLLIN,
            revents & libc::POLLERR,
        );

        // Read an event from the userfaultfd.
        let event = uffd_handler
            .uffd
            .read_event()
            .expect("Failed to read uffd_msg")
            .expect("uffd_msg not ready");

        // We expect to receive either a Page Fault or Removed
        // event (if the balloon device is enabled).
        match event {
            userfaultfd::Event::Pagefault { addr, .. } => {
                uffd_handler.serve_pf(addr as *mut u8, len)
            }
            userfaultfd::Event::Remove { start, end } => uffd_handler.update_mem_state_mappings(
                start as *mut u8 as u64,
                end as *mut u8 as u64,
                &MemPageState::Removed,
            ),
            _ => panic!("Unexpected event on userfaultfd"),
        }
    }
}
