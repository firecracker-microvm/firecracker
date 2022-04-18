// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provides functionality for a malicious page fault handler
//! which panics when a page fault occurs.

use nix::poll::{poll, PollFd, PollFlags};
use std::os::unix::io::AsRawFd;
use uffd::uffd_utils::create_pf_handler;

fn main() {
    let uffd_handler = create_pf_handler();
    let pollfd = PollFd::new(uffd_handler.uffd.as_raw_fd(), PollFlags::POLLIN);

    // Loop, handling incoming events on the userfaultfd file descriptor.
    loop {
        let _ = poll(&mut [pollfd], -1).expect("Failed to poll");

        // Read an event from the userfaultfd.
        let event = uffd_handler
            .uffd
            .read_event()
            .expect("Failed to read uffd_msg")
            .expect("uffd_msg not ready");

        // We expect to receive either a Page Fault or Removed
        // event (if the balloon device is enabled).
        if let userfaultfd::Event::Pagefault { .. } = event {
            panic!("Fear me! I am the malicious page fault handler.")
        }
    }
}
