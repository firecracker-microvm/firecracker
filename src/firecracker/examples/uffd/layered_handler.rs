// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! A userspace page fault handler that serves guest memory from a chain of
//! snapshot memory layers: a root (Full) memory file followed by any number of
//! Diff memory files, each taken from a VM restored from the previous one.
//!
//! Usage: `uffd_layered_handler <socket> <root.mem> [<diff.mem> ...]`
//!
//! Layers are given oldest first. A page is served from the newest layer that
//! has data for it. See `docs/snapshotting/snapshot-tree.md`.

mod layered_mem;
mod uffd_utils;

use std::fs::File;
use std::os::unix::net::UnixListener;

use layered_mem::LayeredMemory;
use uffd_utils::{Runtime, UffdHandler};

fn main() {
    let mut args = std::env::args().skip(1);
    let uffd_sock_path = args.next().expect("No socket path given");
    let layer_paths: Vec<String> = args.collect();
    assert!(!layer_paths.is_empty(), "No memory layers given");

    let layers = layer_paths
        .iter()
        .map(|p| File::open(p).unwrap_or_else(|e| panic!("Cannot open layer {p}: {e}")))
        .collect();
    let memory = LayeredMemory::new(layers).expect("Cannot build layered memory view");
    println!(
        "Serving {} bytes from {} layers ({} extents)",
        memory.len(),
        layer_paths.len(),
        memory.extent_count
    );

    let listener = UnixListener::bind(uffd_sock_path).expect("Cannot bind to socket path");
    let (stream, _) = listener.accept().expect("Cannot listen on UDS socket");

    // `memory` lives until the end of main, i.e. for as long as the runtime.
    let mut runtime = Runtime::with_backing_memory(stream, memory.as_ptr(), memory.len());
    runtime.install_panic_hook();
    runtime.run(|uffd_handler: &mut UffdHandler| {
        // Same event handling as `on_demand_handler.rs`; see the notes there on
        // `remove` events from the balloon device and why faults may be deferred.
        let mut deferred_events = Vec::new();

        loop {
            let mut events_to_handle = Vec::from_iter(deferred_events.drain(..));

            while let Some(event) = uffd_handler.read_event().expect("Failed to read uffd_msg") {
                events_to_handle.push(event);
            }

            for event in events_to_handle.drain(..) {
                match event {
                    userfaultfd::Event::Pagefault { addr, .. } => {
                        if !uffd_handler.serve_pf(addr.cast(), uffd_handler.page_size) {
                            deferred_events.push(event);
                        }
                    }
                    userfaultfd::Event::Remove { start, end } => {
                        uffd_handler.unregister_range(start, end)
                    }
                    _ => panic!("Unexpected event on userfaultfd"),
                }
            }

            if deferred_events.is_empty() {
                break;
            }
        }
    });
}
