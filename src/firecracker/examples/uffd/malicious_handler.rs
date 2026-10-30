// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provides functionality for a malicious page fault handler
//! which panics when a page fault occurs.

mod uffd_utils;

use uffd_utils::{Args, UffdHandler};

fn main() {
    // Wait for Firecracker's handshake: a uffd to serve page faults for (populated from the
    // snapshot memory file), the guest memory memfd (shared at boot or on restore), or both,
    // as the command line says to expect.
    let mut runtime = Args::parse().into_runtime();
    runtime.run(|uffd_handler: &mut UffdHandler| {
        // Read an event from the userfaultfd.
        let event = uffd_handler
            .read_event()
            .expect("Failed to read uffd_msg")
            .expect("uffd_msg not ready");

        if let userfaultfd::Event::Pagefault { .. } = event {
            panic!("Fear me! I am the malicious page fault handler.")
        }
    });
}
