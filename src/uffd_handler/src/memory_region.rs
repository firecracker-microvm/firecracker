// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use utils::{get_page_size, GuestRegionUffdMapping};

use crate::{Error, Result};

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
pub fn create_mem_regions(mappings: Vec<GuestRegionUffdMapping>) -> Vec<MemRegion> {
    let page_size = get_page_size().unwrap();
    let mut mem_regions: Vec<MemRegion> = Vec::with_capacity(mappings.len());

    for r in mappings.iter() {
        let mapping = *r;
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

/// Deserialize memory mappings received through UDS from Firecracker.
pub fn deserialize_mappings(msg: &str, size: usize) -> Result<Vec<GuestRegionUffdMapping>> {
    let mappings = serde_json::from_str::<Vec<GuestRegionUffdMapping>>(msg)
        .map_err(Error::DeserializeMemoryMappings)?;
    let memsize: usize = mappings.iter().map(|r| r.size).sum();
    // The mappings' memory size must match the size of the snapshot memory file, otherwise
    // the memory mappings might be corrupted.
    if memsize != size {
        return Err(Error::CorruptedMemoryMappings);
    }

    Ok(mappings)
}
