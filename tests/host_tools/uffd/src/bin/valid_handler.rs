// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provides functionality for a userspace page fault handler
//! which loads the whole region from the backing memory file
//! when a page fault occurs.

use nix::poll::{poll, PollFd, PollFlags};
use std::os::unix::io::AsRawFd;

use uffd::uffd_utils::{create_pf_handler, MemPageState};

fn main() {
    let mut uffd_handler = create_pf_handler();

    let pollfd = PollFd::new(uffd_handler.uffd.as_raw_fd(), PollFlags::POLLIN);

    // Loop, handling incoming events on the userfaultfd file descriptor.
    loop {
        // See what poll() tells us about the userfaultfd.
        let nready = poll(&mut [pollfd], -1).expect("Failed to poll");

        let revents = pollfd.revents().unwrap();
        println!(
            "poll() returns: nready = {}; POLLIN = {}; POLLERR = {}",
            nready,
            revents.contains(PollFlags::POLLIN),
            revents.contains(PollFlags::POLLERR),
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
            userfaultfd::Event::Pagefault { addr, .. } => uffd_handler.serve_pf(addr as *mut u8),
            userfaultfd::Event::Remove { start, end } => uffd_handler.update_mem_state_mappings(
                start as *mut u8 as u64,
                end as *mut u8 as u64,
                &MemPageState::Removed,
            ),
            _ => panic!("Unexpected event on userfaultfd"),
        }
    }
}
