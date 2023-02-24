// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::File;
use std::os::unix::net::UnixStream;
use utils::{get_page_size, GuestRegionUffdMapping};

use utils::sock_ctrl_msg::ScmSocket;

/// Parse the unix stream received from the Firecracker process to obtain
/// the userfaultfd used to poll for events and the message containing memory mappings.
pub fn parse_unix_stream(stream: &UnixStream) -> (File, String) {
    let mut message_buf = vec![0u8; 1024];
    let (bytes_read, file) = stream
        .recv_with_fd(&mut message_buf[..])
        .expect("Cannot recv_with_fd");
    message_buf.resize(bytes_read, 0);

    let body = String::from_utf8(message_buf).unwrap();
    let file = file.expect("Uffd not passed through UDS!");

    (file, body)
}

pub struct MemRegion {
    pub mapping: GuestRegionUffdMapping,
    pub page_states: HashMap<usize, MemPageState>,
}

#[derive(Clone, Copy)]
pub enum MemPageState {
    Uninitialized,
    FromFile,
    Removed,
    Anonymous,
}

/// Convert the guest memory mappings received from the Firecracker process
/// into a vector of `MemRegion`s containing the guest mappings and page
/// state information.
pub fn create_mem_regions(mappings: &Vec<GuestRegionUffdMapping>) -> Vec<MemRegion> {
    let page_size = get_page_size().unwrap();
    let mut mem_regions: Vec<MemRegion> = Vec::with_capacity(mappings.len());

    for r in mappings.iter() {
        let mapping = r.clone();
        let mut addr = r.base_host_virt_addr;
        let end_addr = r.base_host_virt_addr + r.size;
        let mut page_states = HashMap::new();

        while addr < end_addr {
            page_states.insert(addr, MemPageState::Uninitialized);
            addr += page_size;
        }
        mem_regions.push(MemRegion {
            mapping,
            page_states,
        });
    }

    mem_regions
}
