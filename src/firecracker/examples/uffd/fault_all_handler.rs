// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provides functionality for a userspace page fault handler
//! which loads the whole region from the backing memory file
//! when a page fault occurs.

#![allow(clippy::cast_possible_truncation)]

mod uffd_utils;

use std::fs::File;
use std::os::unix::net::UnixListener;

use uffd_utils::{Runtime, UffdHandler};
use utils::time::{ClockType, get_time_us};

fn main() {
    let mut args = std::env::args();
    let uffd_sock_path = args.nth(1).expect("No socket path given");
    let mem_file_path = args.next().expect("No memory file given");

    let file = File::open(mem_file_path).expect("Cannot open memfile");

    // Get Uffd from UDS. We'll use the uffd to handle PFs for Firecracker.
    let listener = UnixListener::bind(uffd_sock_path).expect("Cannot bind to socket path");
    let (stream, _) = listener.accept().expect("Cannot listen on UDS socket");
    stream
        .set_nonblocking(true)
        .expect("Cannot set non-blocking");

    let mut runtime = Runtime::new(stream, file);
    runtime.install_panic_hook();
    runtime.run(
        |uffd_handler: &mut UffdHandler| {
            // Read an event from the userfaultfd.
            let event = uffd_handler
                .read_event()
                .expect("Failed to read uffd_msg")
                .expect("uffd_msg not ready");

            if let userfaultfd::Event::Pagefault { addr, .. } = event {
                let bit =
                    uffd_handler.addr_to_offset(addr.cast()) as usize / uffd_handler.page_size;

                // If Secret Free, we know if this is the first fault based on the userfault
                // bitmap state. Otherwise, we assume that we will ever only receive a single fault
                // event via UFFD.
                let are_we_faulted_yet = uffd_handler
                    .userfault_bitmap
                    .as_mut()
                    .is_some_and(|bitmap| !bitmap.is_bit_set(bit));

                if are_we_faulted_yet {
                    // TODO: we currently ignore the result as we may attempt to
                    // populate the page that is already present as we may receive
                    // multiple minor fault events per page.
                    _ = uffd_handler
                        .uffd
                        .r#continue(addr, uffd_handler.page_size, true)
                        .inspect_err(|err| println!("Error during uffdio_continue: {:?}", err));
                } else {
                    fault_all(uffd_handler, addr);
                }
            }
        },
        |_uffd_handler: &mut UffdHandler, _offset: usize| {},
    );
}

fn fault_all(uffd_handler: &mut UffdHandler, fault_addr: *mut libc::c_void) {
    let start = get_time_us(ClockType::Monotonic);
    for region in uffd_handler.mem_regions.clone() {
        match uffd_handler.guest_memfd {
            None => {
                uffd_handler.serve_pf(region.base_host_virt_addr as _, region.size);
            }
            Some(_) => {
                let written = uffd_handler.populate_via_write(region.offset as usize, region.size);

                // This code is written under the assumption that the first fault triggered by
                // Firecracker is either due to an MSR write (on x86) or due to device restoration
                // reading from guest memory to check the virtio queues are sane (on
                // ARM). This will be reported via a UFFD minor fault which needs to
                // be handled via memcpy. Importantly, we get to the UFFD handler
                // with the actual guest_memfd page already faulted in, meaning pwrite will stop
                // once it gets to the offset of that page (e.g. written < region.size above).
                // Thus, to fault in everything, we now need to skip this one page, write the
                // remaining region, and then deal with the "gap" via uffd_handler.serve_pf().

                if written < region.size - uffd_handler.page_size {
                    let r = uffd_handler.populate_via_write(
                        region.offset as usize + written + uffd_handler.page_size,
                        region.size - written - uffd_handler.page_size,
                    );
                    assert_eq!(written + r, region.size - uffd_handler.page_size);
                }
            }
        }
    }
    uffd_handler.serve_pf(fault_addr.cast(), uffd_handler.page_size);
    let end = get_time_us(ClockType::Monotonic);

    println!("Finished Faulting All: {}us", end - start);
}
