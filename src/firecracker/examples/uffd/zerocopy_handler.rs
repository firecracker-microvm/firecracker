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
//! 1. Receive binary UFFD HANDSHAKE + uffd fd from VMM
//! 2. Monitor uffd for page faults
//! 3. For each fault, send a binary UFFD PAGE_RESPONSE + backing file fd back
//!    to the VMM via the socket. The VMM's `UffdBlock` does the MAP_FIXED mmap.
//!
//! Usage: zerocopy_handler <socket_path> <backing_file_path> [--rw]

mod uffd_utils;

use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::net::UnixListener;

use userfaultfd::Uffd;
use vmm::uffd_block::{BlobRange, VmaRegion};
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

use uffd_utils::GuestRegionUffdMapping;

const UFFD_MAGIC: u32 = 0x5546_4644;
const MSG_HANDSHAKE: u16 = 0x01;
const MSG_PAGE_RESPONSE: u16 = 0x81;
const HEADER_SIZE: usize = 20;
const REGION_SIZE: usize = 40;
const RANGE_SIZE: usize = 24;
const HANDSHAKE_FLAG_COPY: u8 = 0x01;

#[derive(Debug, Clone, Copy)]
struct Header {
    magic: u32,
    flags: u16,
    msg_type: u16,
    cookie: u64,
    len: u32,
}

impl Header {
    fn new(msg_type: u16, payload_len: u32) -> Self {
        Self {
            magic: UFFD_MAGIC,
            flags: 0,
            msg_type,
            cookie: 0,
            len: payload_len,
        }
    }

    fn to_bytes(self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(&self.magic.to_le_bytes());
        buf[4..6].copy_from_slice(&self.flags.to_le_bytes());
        buf[6..8].copy_from_slice(&self.msg_type.to_le_bytes());
        buf[8..16].copy_from_slice(&self.cookie.to_le_bytes());
        buf[16..20].copy_from_slice(&self.len.to_le_bytes());
        buf
    }

    fn from_bytes(buf: &[u8; HEADER_SIZE]) -> Self {
        Self {
            magic: u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            flags: u16::from_le_bytes(buf[4..6].try_into().unwrap()),
            msg_type: u16::from_le_bytes(buf[6..8].try_into().unwrap()),
            cookie: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            len: u32::from_le_bytes(buf[16..20].try_into().unwrap()),
        }
    }
}

fn decode_binary_handshake(buf: &[u8]) -> Option<Vec<VmaRegion>> {
    if buf.len() < HEADER_SIZE + 4 {
        return None;
    }
    let header = Header::from_bytes(buf[..HEADER_SIZE].try_into().ok()?);
    if header.magic != UFFD_MAGIC
        || header.flags != 0
        || header.msg_type != MSG_HANDSHAKE
        || header.cookie != 0
    {
        return None;
    }

    let payload_len = header.len as usize;
    if buf.len() != HEADER_SIZE + payload_len || payload_len < 4 {
        return None;
    }

    let payload = &buf[HEADER_SIZE..];
    if payload[2] & HANDSHAKE_FLAG_COPY != 0 {
        return None;
    }

    let region_count = payload[3] as usize;
    if payload_len != 4 + region_count * REGION_SIZE {
        return None;
    }

    let mut regions = Vec::with_capacity(region_count);
    let mut offset = 4;
    for _ in 0..region_count {
        regions.push(VmaRegion {
            base_host_virt_addr: u64::from_le_bytes(payload[offset..offset + 8].try_into().ok()?),
            size: usize::try_from(u64::from_le_bytes(
                payload[offset + 8..offset + 16].try_into().ok()?,
            ))
            .ok()?,
            offset: u64::from_le_bytes(payload[offset + 16..offset + 24].try_into().ok()?),
            page_size: usize::try_from(u64::from_le_bytes(
                payload[offset + 24..offset + 32].try_into().ok()?,
            ))
            .ok()?,
            prot: i32::from_le_bytes(payload[offset + 32..offset + 36].try_into().ok()?),
            flags: i32::from_le_bytes(payload[offset + 36..offset + 40].try_into().ok()?),
        });
        offset += REGION_SIZE;
    }

    Some(regions)
}

fn encode_binary_page_response(ranges: &[BlobRange]) -> Vec<u8> {
    let payload_len = 4 + ranges.len() * RANGE_SIZE;
    let payload_len_u32 = u32::try_from(payload_len).unwrap();
    let range_count = u32::try_from(ranges.len()).unwrap();
    let mut buf = Vec::with_capacity(HEADER_SIZE + payload_len);
    buf.extend_from_slice(&Header::new(MSG_PAGE_RESPONSE, payload_len_u32).to_bytes());
    buf.extend_from_slice(&range_count.to_le_bytes());
    for range in ranges {
        buf.extend_from_slice(&range.block_offset.to_le_bytes());
        buf.extend_from_slice(&range.blob_offset.to_le_bytes());
        buf.extend_from_slice(&(range.len as u64).to_le_bytes());
    }
    buf
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

    // Receive handshake: binary UFFD frame + uffd fd.
    let mut buf = vec![0u8; 4096];
    let (bytes_read, uffd_file) = stream.recv_with_fd(&mut buf).unwrap();
    let uffd_file = uffd_file.expect("No uffd fd received");
    buf.truncate(bytes_read);

    // Try binary protocol first, then fall back to legacy JSON for older VMMs.
    let regions: Vec<VmaRegion> = if let Some(regions) = decode_binary_handshake(&buf) {
        println!("Binary handshake: {} region(s)", regions.len());
        regions
    } else {
        let body = String::from_utf8(buf).expect("Invalid UTF-8 in handshake");
        let legacy: Vec<GuestRegionUffdMapping> =
            serde_json::from_str(&body).expect("Cannot parse mappings");
        println!("Legacy mapping handshake: {} region(s)", legacy.len());
        legacy
            .into_iter()
            .map(|m| VmaRegion {
                base_host_virt_addr: m.base_host_virt_addr,
                size: m.size,
                offset: m.offset,
                page_size: m.page_size,
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

                let ranges = vec![BlobRange {
                    len: page_size,
                    blob_offset,
                    block_offset,
                }];
                let bytes = encode_binary_page_response(&ranges);

                // Send response with the backing file fd — VMM will MAP_FIXED mmap it.
                if let Err(e) = stream.send_with_fd(bytes.as_slice(), backing_file.as_raw_fd()) {
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
