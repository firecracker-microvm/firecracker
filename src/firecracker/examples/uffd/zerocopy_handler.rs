// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Zero-copy UFFD page fault handler example.
//!
//! Unlike the standard handlers that use UFFDIO_COPY to populate pages,
//! this handler responds to page faults by sending back blob file descriptors
//! that the VMM maps directly (MAP_FIXED) over the faulting region, avoiding
//! any data copy.
//!
//! Protocol:
//! 1. Receive `GuestRegionUffdMapping` JSON + uffd fd from VMM
//! 2. Monitor uffd for page faults
//! 3. For each fault, send a `PageFaultResponse` JSON + backing file fd back
//!    to the VMM via the socket. The VMM's `UffdBlock` does the MAP_FIXED mmap.
//!
//! Usage: zerocopy_handler <socket_path> <backing_file_path> [--rw]

mod uffd_utils;

use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::net::UnixListener;

use serde::{Deserialize, Serialize};
use userfaultfd::Uffd;
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

use uffd_utils::GuestRegionUffdMapping;

/// Message type enum (mirrors vmm::uffd_block::MessageType).
#[derive(Debug, Default, Deserialize)]
#[repr(u8)]
enum MessageType {
    #[default]
    Handshake = 0,
    PageFault = 1,
}

/// Fault handling policy (mirrors vmm::uffd_block::FaultPolicy).
#[derive(Debug, Default, Deserialize)]
#[repr(u8)]
enum FaultPolicy {
    #[default]
    Zerocopy = 0,
    Copy = 1,
}

/// Formal handshake request (mirrors vmm::uffd_block::HandshakeRequest).
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct HandshakeRequest {
    #[serde(default)]
    r#type: MessageType,
    regions: Vec<VmaRegion>,
    #[serde(default)]
    policy: FaultPolicy,
}

/// VMA region from formal handshake (mirrors vmm::uffd_block::VmaRegion).
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct VmaRegion {
    base_host_virt_addr: u64,
    size: usize,
    offset: u64,
    page_size: usize,
    #[serde(default)]
    page_size_kib: usize,
    #[serde(default)]
    prot: i32,
    #[serde(default)]
    flags: i32,
}

/// Page fault response sent back to the VMM.
#[derive(Debug, Serialize)]
struct PageFaultResponse {
    ranges: Vec<BlobRange>,
}

/// A single range within a page fault response.
#[derive(Debug, Serialize)]
struct BlobRange {
    len: usize,
    blob_offset: u64,
    block_offset: u64,
}

fn main() {
    let mut args = std::env::args();
    let uffd_sock_path = args.nth(1).expect("No socket path given");
    let backing_file_path = args.next().expect("No backing file given");
    let rw_mode = args.next().is_some_and(|a| a == "--rw");

    let backing_file = if rw_mode {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&backing_file_path)
            .expect("Cannot open backing file in rw mode")
    } else {
        File::open(&backing_file_path).expect("Cannot open backing file")
    };
    let backing_file_size = backing_file
        .metadata()
        .expect("Cannot get file metadata")
        .len();

    let listener = UnixListener::bind(&uffd_sock_path).expect("Cannot bind to socket path");
    println!("Listening on {uffd_sock_path}");

    let (stream, _) = listener.accept().expect("Cannot accept connection");

    // Receive handshake: GuestRegionUffdMapping JSON + uffd fd
    let mut buf = vec![0u8; 4096];
    let (bytes_read, uffd_file) = stream.recv_with_fd(&mut buf).unwrap();
    let uffd_file = uffd_file.expect("No uffd fd received");
    buf.truncate(bytes_read);

    let body = String::from_utf8(buf).expect("Invalid UTF-8 in handshake");

    // Try formal HandshakeRequest first, then fall back to legacy Vec<GuestRegionUffdMapping>
    let regions: Vec<VmaRegion> = if let Ok(req) = serde_json::from_str::<HandshakeRequest>(&body) {
        println!(
            "Handshake: {} region(s), policy {:?}",
            req.regions.len(),
            req.policy
        );
        req.regions
    } else {
        let legacy: Vec<GuestRegionUffdMapping> =
            serde_json::from_str(&body).expect("Cannot parse mappings");
        legacy
            .into_iter()
            .map(|m| VmaRegion {
                base_host_virt_addr: m.base_host_virt_addr,
                size: m.size,
                offset: m.offset,
                page_size: m.page_size,
                page_size_kib: 0,
                prot: 0,
                flags: 0,
            })
            .collect()
    };

    println!(
        "Received {} region(s), backing file size: {}",
        regions.len(),
        backing_file_size
    );
    for (i, m) in regions.iter().enumerate() {
        println!(
            "  region[{}]: addr=0x{:x} size=0x{:x} offset=0x{:x}",
            i, m.base_host_virt_addr, m.size, m.offset
        );
    }

    // SAFETY: uffd fd received from the VMM is valid.
    let uffd = unsafe { Uffd::from_raw_fd(uffd_file.into_raw_fd()) };

    // Event loop: monitor uffd for page faults
    let mut pollfds = vec![libc::pollfd {
        fd: uffd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    }];

    loop {
        // SAFETY: pollfds is a valid slice.
        let nready = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as u64, -1) };
        if nready <= 0 {
            continue;
        }

        if pollfds[0].revents & libc::POLLIN == 0 {
            continue;
        }

        // Read the page fault event
        let event = match uffd.read_event() {
            Ok(Some(event)) => event,
            Ok(None) => continue,
            Err(e) => {
                eprintln!("Failed to read uffd event: {e:?}");
                continue;
            }
        };

        match event {
            userfaultfd::Event::Pagefault { addr, .. } => {
                let fault_addr = addr as u64;

                // Find the region containing this fault
                let region = regions.iter().find(|r| {
                    fault_addr >= r.base_host_virt_addr
                        && fault_addr < r.base_host_virt_addr + r.size as u64
                });
                let region = match region {
                    Some(r) => r,
                    None => {
                        eprintln!("Fault at 0x{fault_addr:x} not in any region");
                        continue;
                    }
                };

                // Calculate page-aligned offset within the region
                let page_size = region.page_size;
                let page_addr = fault_addr & !(page_size as u64 - 1);
                let offset_in_region = page_addr - region.base_host_virt_addr;
                let block_offset = region.offset + offset_in_region;
                let blob_offset = block_offset;

                let response = PageFaultResponse {
                    ranges: vec![BlobRange {
                        len: page_size,
                        blob_offset,
                        block_offset,
                    }],
                };

                let json = serde_json::to_string(&response).expect("Cannot serialize response");

                // Send response with the backing file fd — VMM will MAP_FIXED mmap it
                if let Err(e) = stream.send_with_fd(json.as_bytes(), backing_file.as_raw_fd()) {
                    eprintln!("Failed to send response: {e}");
                    break;
                }
            }
            userfaultfd::Event::Remove { .. } => {
                // Balloon device removed a range, nothing to do for zerocopy
            }
            _ => {
                eprintln!("Unexpected uffd event");
            }
        }
    }
}
