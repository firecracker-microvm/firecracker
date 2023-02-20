// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use utils::{get_page_size, GuestRegionUffdMapping};

use crate::{Error, Result};

#[derive(Debug)]
pub struct MemRegion {
    pub mapping: GuestRegionUffdMapping,
    pub page_states: HashMap<usize, MemPageState>,
}

#[derive(Clone, Copy, Debug)]
#[cfg_attr(test, derive(PartialEq))]
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

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE_SIZE: usize = 4096;

    #[test]
    fn test_create_mem_regions() {
        let mappings = vec![
            // Add a region with size 5 * PAGE_SIZE starting from 0x0 address.
            GuestRegionUffdMapping {
                base_host_virt_addr: 0x0,
                size: PAGE_SIZE * 5,
                offset: 0,
            },
            // Add a region with size 3 * PAGE_SIZE starting from 0x6000 address.
            GuestRegionUffdMapping {
                base_host_virt_addr: 0x6000,
                size: PAGE_SIZE * 3,
                offset: 0x1000,
            },
        ];
        let memory_regions = create_mem_regions(mappings.clone());

        assert_eq!(memory_regions.len(), mappings.len());
        // Ensure the regions' size is 5 * PAGE_SIZE + 3 * PAGE_SIZE = 8 * PAGE_SIZE.
        assert_eq!(
            memory_regions.iter().map(|r| r.mapping.size).sum::<usize>(),
            PAGE_SIZE * 8
        );
        // Ensure all page states are `Uninitialized`.
        assert!(memory_regions
            .iter()
            .flat_map(|region| region.page_states.values())
            .all(|state| matches!(state, MemPageState::Uninitialized)));
        // Check pages number.
        assert_eq!(memory_regions[0].page_states.len(), 5);
        assert_eq!(memory_regions[1].page_states.len(), 3);
    }

    #[test]
    fn test_deserialize_mappings_success() {
        // Create mappings with size PAGE_SIZE * 5.
        let expected_mappings = vec![
            GuestRegionUffdMapping {
                base_host_virt_addr: 0x1000,
                size: PAGE_SIZE * 2,
                offset: 0,
            },
            GuestRegionUffdMapping {
                base_host_virt_addr: 0x5000,
                size: PAGE_SIZE * 3,
                offset: 0,
            },
        ];

        let msg = serde_json::to_string(&expected_mappings).unwrap();
        let mappings = deserialize_mappings(&msg, PAGE_SIZE * 5).unwrap();
        assert_eq!(mappings, expected_mappings);
    }

    #[test]
    fn test_deserialize_mappings_corrupted() {
        let mappings = [GuestRegionUffdMapping {
            base_host_virt_addr: 0x1000,
            size: PAGE_SIZE,
            offset: 0,
        }];
        let expected_size = PAGE_SIZE - 1;
        let msg = serde_json::to_string(&mappings).unwrap();

        // Deserialization fails because mappings don't match the expected size,
        // thus they are corrupted.
        let res = deserialize_mappings(&msg, expected_size);
        assert!(res.is_err());
        assert_eq!(
            Error::CorruptedMemoryMappings.to_string(),
            res.err().unwrap().to_string()
        );
    }

    #[test]
    fn test_deserialize_mappings_invalid() {
        let res = deserialize_mappings("foo bar", 0);
        assert!(res.is_err());
        assert!(matches!(
            res.err().unwrap(),
            Error::DeserializeMemoryMappings(_)
        ));
    }
}
