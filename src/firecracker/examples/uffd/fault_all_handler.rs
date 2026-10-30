// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provides functionality for a userspace page fault handler
//! which loads the whole region from the backing memory file
//! when a page fault occurs.

mod uffd_utils;

use uffd_utils::{Args, UffdHandler};
use utils::time::{ClockType, get_time_us};

fn main() {
    // Wait for Firecracker's handshake: a uffd to serve page faults for (populated from the
    // snapshot memory file), the guest memory memfd (shared at boot or on restore), or both,
    // as the command line says to expect.
    let mut runtime = Args::parse().into_runtime();
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
