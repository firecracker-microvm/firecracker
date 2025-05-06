// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provides functionality for a userspace page fault handler
//! which loads the whole region from the backing memory file
//! when a page fault occurs.

mod uffd_utils;

use std::fs::File;
use std::os::unix::net::UnixListener;

use uffd_utils::{Runtime, UffdHandler};

fn main() {
    let mut args = std::env::args();
    let uffd_sock_path = args.nth(1).expect("No socket path given");
    let mem_file_path = args.next().expect("No memory file given");

    let file = File::open(mem_file_path).expect("Cannot open memfile");

    // Get Uffd from UDS. We'll use the uffd to handle PFs for Firecracker.
    let listener = UnixListener::bind(uffd_sock_path).expect("Cannot bind to socket path");
    let (stream, _) = listener.accept().expect("Cannot listen on UDS socket");

    let mut runtime = Runtime::new(stream, file);
    runtime.install_panic_hook();
    runtime.run(|uffd_handler: &mut UffdHandler| {
        // !DISCLAIMER!
        // When using UFFD together with the balloon device, this handler needs to deal with
        // `remove` and `pagefault` events. There are multiple things to keep in mind in
        // such setups:
        //
        // As long as any `remove` event is pending in the UFFD queue, all ioctls return EAGAIN
        // -----------------------------------------------------------------------------------
        //
        // This means we cannot process UFFD events simply one-by-one anymore - if a `remove` event
        // arrives, we need to pre-fetch all other events up to the `remove` event, to unblock the
        // UFFD, and then go back to the process the pre-fetched events.
        //
        // UFFD might receive events in not in their causal order
        // -----------------------------------------------------
        //
        // For example, the guest
        // kernel might first respond to a balloon inflation by freeing some memory, and
        // telling Firecracker about this. Firecracker will then madvise(MADV_DONTNEED) the
        // free memory range, which causes a `remove` event to be sent to UFFD. Then, the
        // guest kernel might immediately fault the page in again (for example because
        // default_on_oom was set). which causes a `pagefault` event to be sent to UFFD.
        //
        // However, the pagefault will be triggered from inside KVM on the vCPU thread, while the
        // balloon device is handled by Firecracker on its VMM thread. This means that potentially
        // this handler can receive the `pagefault` _before_ the `remove` event.
        //
        // This means that the simple "greedy" strategy of simply prefetching _all_ UFFD events
        // to make sure no `remove` event is blocking us can result in the handler acting on
        // the `pagefault` event before the `remove` message (despite the `remove` event being
        // in the causal past of the `pagefault` event), which means that we will fault in a page
        // from the snapshot file, while really we should be faulting in a zero page.
        //
        // In this example handler, we ignore this problem, to avoid
        // complexity (under the assumption that the guest kernel will zero a newly faulted in
        // page anyway). A production handler will most likely want to ensure that `remove`
        // events for a specific range are always handled before `pagefault` events.
        //
        // Lastly, we still need to deal with the race condition where a `remove` event arrives
        // in the UFFD queue after we got done reading all events, in which case we need to go
        // back to reading more events before we can continue processing `pagefault`s.
        let mut deferred_events = Vec::new();

        loop {
            // First, try events that we couldn't handle last round
            let mut events_to_handle = Vec::from_iter(deferred_events.drain(..));

            // Read all events from the userfaultfd.
            while let Some(event) = uffd_handler.read_event().expect("Failed to read uffd_msg") {
                events_to_handle.push(event);
            }

            for event in events_to_handle.drain(..) {
                // We expect to receive either a Page Fault or `remove`
                // event (if the balloon device is enabled).
                match event {
                    userfaultfd::Event::Pagefault { addr, .. } => {
                        if !uffd_handler.serve_pf(addr.cast(), uffd_handler.page_size) {
                            deferred_events.push(event);
                        }
                    }
                    userfaultfd::Event::Remove { start, end } => {
                        uffd_handler.mark_range_removed(start as u64, end as u64)
                    }
                    _ => panic!("Unexpected event on userfaultfd"),
                }
            }

            // We assume that really only the above removed/pagefault interaction can result in
            // deferred events. In that scenario, the loop will always terminate (unless
            // newly arriving `remove` events end up indefinitely blocking it, but there's nothing
            // we can do about that, and it's a largely theoretical problem).
            if deferred_events.is_empty() {
                break;
            }
        }
    });
}
