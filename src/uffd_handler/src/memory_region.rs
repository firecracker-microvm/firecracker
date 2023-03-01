// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use utils::{get_page_size, GuestRegionUffdMapping};

use crate::Error;

#[derive(Debug, thiserror::Error)]
pub enum MemRegionError {
    #[error("Host virtual address of region end overflows usize.")]
    EndRegionOverflow,
    #[error("The mapping exceeds the file end.")]
    MappingPastEof,
    #[error("The specified file offset and length cause overflow when added.")]
    InvalidOffsetLength,
    #[error("Size of snapshot memory file differs from the size of memory mappings.")]
    SizeMismatch,
}

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

/// Construct memory regions from stream received from Firecracker process.
pub fn mem_regions_from_stream(msg: &str, mem_file_size: usize) -> Result<Vec<MemRegion>, Error> {
    let mappings = deserialize_mappings(msg)?;
    memory_mappings_sanity_checks(&mappings, mem_file_size)
        .map_err(Error::CorruptedMemoryMappings)?;

    Ok(create_mem_regions(mappings))
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
        // This cannot overflow because it has been previously validated during mappings sanity
        // checks (see `memory_mappings_sanity_checks`).
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

/// Perform sanity checks for deserialized mappings to ensure they are not corrupted:
/// - The regions must not exceed memory file end.
/// - The specified file offset and region size must not overflow when added.
/// - The region end must not overflow usize.
/// - The total mappings size must match the memory file size.
fn memory_mappings_sanity_checks(
    mappings: &Vec<GuestRegionUffdMapping>,
    file_size: usize,
) -> Result<(), MemRegionError> {
    for region in mappings {
        if let Some(region_end) = region.offset.checked_add(region.size as u64) {
            if region_end > file_size as u64 {
                // The region goes beyond file end.
                return Err(MemRegionError::MappingPastEof);
            }
        } else {
            // The specified file offset and region size cause overflow when added.
            return Err(MemRegionError::InvalidOffsetLength);
        }

        if region
            .base_host_virt_addr
            .checked_add(region.size)
            .is_none()
        {
            // The region end overflows usize.
            return Err(MemRegionError::EndRegionOverflow);
        }
    }

    let memsize: usize = mappings.iter().map(|r| r.size).sum();
    // The mappings' memory size must match the size of the snapshot memory file.
    if memsize != file_size {
        return Err(MemRegionError::SizeMismatch);
    }

    Ok(())
}

/// Deserialize memory mappings received through UDS from Firecracker.
fn deserialize_mappings(msg: &str) -> Result<Vec<GuestRegionUffdMapping>, Error> {
    serde_json::from_str::<Vec<GuestRegionUffdMapping>>(msg)
        .map_err(Error::DeserializeMemoryMappings)
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
        let mappings = deserialize_mappings(&msg).unwrap();
        assert!(memory_mappings_sanity_checks(&mappings, PAGE_SIZE * 5).is_ok());
        assert_eq!(mappings, expected_mappings);
    }

    #[test]
    fn test_deserialize_mappings_invalid() {
        let res = deserialize_mappings("foo bar");
        assert!(res.is_err());
        assert!(matches!(
            res.err().unwrap(),
            Error::DeserializeMemoryMappings(_)
        ));

        let res = deserialize_mappings("");
        assert!(res.is_err());
        assert!(matches!(
            res.err().unwrap(),
            Error::DeserializeMemoryMappings(_)
        ));
    }

    #[test]
    fn test_mappings_sanity_checks_corrupted() {
        let mut mappings = vec![GuestRegionUffdMapping {
            base_host_virt_addr: 0x1000,
            size: PAGE_SIZE,
            offset: 0,
        }];

        // Sanity checks fail because mappings size doesn't match the expected file size.
        let res = memory_mappings_sanity_checks(&mappings, PAGE_SIZE + 1);
        assert!(res.is_err());
        assert!(matches!(res.err().unwrap(), MemRegionError::SizeMismatch));

        // Sanity checks fail because the region does not fit into the file entirely.
        // The region begins at offset=0x100 and ends at 0x1100, while the file's size is
        // PAGE_SIZE=0x1000.
        mappings[0].offset = 0x100;
        let res = memory_mappings_sanity_checks(&mappings, PAGE_SIZE);
        assert!(res.is_err());
        assert!(matches!(res.err().unwrap(), MemRegionError::MappingPastEof));

        // Sanity checks fail because the specified file offset and length
        // cause overflow when added.
        mappings[0].offset = u64::MAX;
        let res = memory_mappings_sanity_checks(&mappings, PAGE_SIZE);
        assert!(res.is_err());
        assert!(matches!(
            res.err().unwrap(),
            MemRegionError::InvalidOffsetLength
        ));

        // Sanity checks fail because the host address of the region end overflows usize.
        mappings[0].offset = 0;
        mappings[0].base_host_virt_addr = usize::MAX;
        let res = memory_mappings_sanity_checks(&mappings, PAGE_SIZE);
        assert!(res.is_err());
        assert!(matches!(
            res.err().unwrap(),
            MemRegionError::EndRegionOverflow
        ));
    }
}
