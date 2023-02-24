// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use utils::get_page_size;

use crate::handler::{page_start_of_addr, HandlerError};
use crate::memory_region::MemRegion;
use crate::Error;

#[derive(Default)]
pub struct UffdPrefaulter {
    bytes_after: usize,
}

impl UffdPrefaulter {
    pub fn new(after: usize) -> Result<Self, Error> {
        let page_size = get_page_size()
            .map_err(HandlerError::PageSize)
            .map_err(Error::UffdHandler)?;

        Ok(UffdPrefaulter {
            bytes_after: after
                .checked_mul(page_size)
                .ok_or_else(|| Error::InvalidAmount(after))?,
        })
    }

    /// Prefaulter is configured by default to start from the faulting address to avoid extra
    /// complexity of keeping track of the status of pages. Otherwise we would need to check that
    /// every page starting from the faulting address down to the start of prefaulting region is
    /// `Uninitialized`.
    pub fn get_prefaulting_start_address(
        &self,
        page_fault_addr: usize,
    ) -> Result<usize, HandlerError> {
        page_start_of_addr(page_fault_addr)
    }

    /// Return the end address of the chunk to prefault into memory. The address is obtained
    /// by adding `bytes_after` amount to the end of the faulting page. If the end address
    /// exceeds the current region, the chunk is truncated to fit into the memory region
    /// (the end of the current memory region is returned).
    /// When there is no customized prefaulting configured, the minimum chunk to copy to RAM
    /// is the faulting page.
    pub fn get_prefaulting_end_address(
        &self,
        page_fault_start_addr: usize,
        region: &MemRegion,
    ) -> Result<usize, HandlerError> {
        let page_size = get_page_size().map_err(HandlerError::PageSize)?;

        // This will not overflow because it has been verified beforehand during mappings
        // deserialization.
        let region_end = region.mapping.base_host_virt_addr + region.mapping.size;
        // We add `page_size` because we always want to at least bring into RAM the faulting page,
        // even if customized prefaulting is not configured. If the result exceeds the current
        // region, the end of the region is returned instead.
        Ok(self
            .bytes_after
            // `page_fault_start_addr` + `page_size` cannot overflow because it has been verified
            // beforehand that the faulting page belongs to the current region.
            .checked_add(page_fault_start_addr + page_size)
            .unwrap_or(region_end)
            .min(region_end))
    }
}

#[cfg(test)]
mod tests {
    use utils::GuestRegionUffdMapping;

    use super::*;
    use crate::memory_region::create_mem_regions;

    fn setup_region() -> Vec<MemRegion> {
        let page_size = get_page_size().unwrap();
        // Create a memory region with size 5 * page_size starting from 0x0 address.
        let mappings = vec![GuestRegionUffdMapping {
            base_host_virt_addr: 0x0,
            size: page_size * 5,
            offset: 0,
        }];

        create_mem_regions(mappings)
    }

    #[test]
    fn test_init_prefaulter() {
        let page_size = get_page_size().unwrap();
        let prefaulter = UffdPrefaulter::new(1024).unwrap();
        assert_eq!(prefaulter.bytes_after, 1024 * page_size);

        let res = UffdPrefaulter::new(usize::MAX);
        assert!(res.is_err());
        assert_eq!(
            res.err().unwrap().to_string(),
            Error::InvalidAmount(usize::MAX).to_string()
        );
    }

    #[test]
    fn test_get_prefaulting_start_address() {
        let page_size = get_page_size().unwrap();
        let prefaulter = UffdPrefaulter::new(0).unwrap();
        let _memory_regions = setup_region();

        // No customized prefaulter. Start address is the same as the current faulting address.
        let faulting_address = page_size * 2;
        assert_eq!(
            prefaulter
                .get_prefaulting_start_address(faulting_address)
                .unwrap(),
            faulting_address
        );
    }

    #[test]
    fn test_get_prefaulting_end_address() {
        let page_size = get_page_size().unwrap();
        let mut prefaulter = UffdPrefaulter::new(0).unwrap();
        let memory_regions = setup_region();
        let region = &memory_regions[0];

        // No customized prefaulter. End address is the end of the current faulting page.
        let faulting_address = page_size * 2;
        assert_eq!(
            prefaulter
                .get_prefaulting_end_address(faulting_address, region)
                .unwrap(),
            faulting_address + page_size
        );

        // Customize prefaulter to bring in 5 pages after the current one.
        prefaulter.bytes_after = page_size * 5;

        // Faulting page is page_size * 2 and prefaulter is configured to bring in 5 more pages
        // after the faulting address. However, the current region only has 5 pages in total.
        // Check that we don't exceed current region.
        assert_eq!(
            prefaulter
                .get_prefaulting_end_address(faulting_address, region)
                .unwrap(),
            region.mapping.base_host_virt_addr + region.mapping.size
        );
    }

    #[test]
    fn test_no_customized_prefaulting() {
        let page_size = get_page_size().unwrap();
        let prefaulter = UffdPrefaulter::new(0).unwrap();
        let memory_regions = setup_region();
        let region = &memory_regions[0];
        let faulting_address = 0;

        let start_addr = prefaulter
            .get_prefaulting_start_address(faulting_address)
            .unwrap();
        let end_addr = prefaulter
            .get_prefaulting_end_address(faulting_address, region)
            .unwrap();
        // No customized prefaulting is configured, we just bring in one page.
        assert_eq!(end_addr - start_addr, page_size);
    }

    #[test]
    fn test_customized_prefaulting() {
        let page_size = get_page_size().unwrap();
        // Bring in and 2 pages after the faulting page.
        let prefaulter = UffdPrefaulter::new(2).unwrap();

        // Create a memory region with size 5 * page_size starting from 0x0 address.
        let memory_regions = setup_region();
        let region = &memory_regions[0];

        // Receive a page fault for the second page in the region.
        let faulting_address = page_size;
        let start_addr = prefaulter
            .get_prefaulting_start_address(faulting_address)
            .unwrap();
        // Customized prefaulting is configured to bring in 3 pages (current page and 2 after).
        assert_eq!(start_addr, faulting_address);
        let end_addr = prefaulter
            .get_prefaulting_end_address(faulting_address, region)
            .unwrap();
        assert_eq!(end_addr - start_addr, page_size * 3);

        // Receive a page fault for the fifth page in the region.
        let faulting_address = page_size * 4;
        let start_addr = prefaulter
            .get_prefaulting_start_address(faulting_address)
            .unwrap();
        // Customized prefaulting is configured to bring in 3 pages (current page and 2 after).
        // However, the faulting page is the last in this region, so we must bring in only the
        // current page.
        assert_eq!(start_addr, faulting_address);
        let end_addr = prefaulter
            .get_prefaulting_end_address(faulting_address, region)
            .unwrap();
        assert_eq!(end_addr - start_addr, page_size);
    }
}
