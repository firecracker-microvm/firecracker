// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;

use vm_memory::{GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};
use super::{MAX_PAGES_IN_DESC, RemoveRegionError};

/// This takes a vector of page frame numbers, and compacts them
/// into ranges of consecutive pages. The result is a vector
/// of (start_page_frame_number, range_length) pairs.
pub(crate) fn compact_page_frame_numbers(v: &mut Vec<u32>) -> Vec<(u32, u32)> {
    if v.is_empty() {
        return vec![];
    }

    // Since the total number of pages that can be
    // received at once from a single descriptor is `MAX_PAGES_IN_DESC`,
    // this sort does not change the complexity of handling
    // an inflation.
    v.sort();

    // Since there are at most `MAX_PAGES_IN_DESC` pages, setting the
    // capacity of `result` to this makes sense.
    let mut result = Vec::with_capacity(MAX_PAGES_IN_DESC);

    // The most recent range of pages is [previous..previous + length).
    let mut previous = v[0];
    let mut length = 1;

    for page_frame_number in &v[1..] {
        // Check if the current page frame number is adjacent to the most recent page range.
        if *page_frame_number == previous + length {
            // If so, extend that range.
            length += 1;
        } else {
            // Otherwise, push (previous, length) to the result vector.
            result.push((previous, length));
            // And update the most recent range of pages.
            previous = *page_frame_number;
            length = 1;
        }
    }

    // Don't forget to push the last range to the result.
    result.push((previous, length));

    result
}

pub(crate) fn remove_range(
    guest_memory: &GuestMemoryMmap,
    range: (GuestAddress, u64),
) -> std::result::Result<(), RemoveRegionError> {
    let (guest_address, range_len) = range;

    if let Some(region) = guest_memory.find_region(guest_address) {
        if guest_address.0 + range_len > region.start_addr().0 + region.len() {
            return Err(RemoveRegionError::MalformedRange);
        }
        let phys_address = guest_memory
            .get_host_address(guest_address)
            .map_err(|_| RemoveRegionError::AddressTranslation)?;

        // Mmap a new anonymous region over the present one in order to create a hole.
        // This workaround is (only) needed after resuming from a snapshot because the guest memory
        // is mmaped from file as private and there is no `madvise` flag that works for this case.
        let ret = unsafe {
            libc::mmap(
                phys_address as *mut _,
                range_len as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_FIXED | libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        if ret < 0 as *mut _ || ret != phys_address as *mut _ {
            return Err(RemoveRegionError::MmapFail(io::Error::last_os_error()));
        }

        // Madvise the region in order to mark it as not used.
        let ret = unsafe {
            libc::madvise(
                phys_address as *mut _,
                range_len as usize,
                libc::MADV_DONTNEED,
            )
        };
        if ret < 0 {
            return Err(RemoveRegionError::MadviseFail(io::Error::last_os_error()));
        }

        Ok(())
    } else {
        Err(RemoveRegionError::RegionNotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vm_memory::Bytes;

    /// This asserts that $lhs matches $rhs.
    macro_rules! assert_match {
        ($lhs:expr, $rhs:pat) => {{
            assert!(match $lhs {
                $rhs => true,
                _ => false,
            })
        }};
    }

    #[test]
    fn test_compact_page_indices() {
        // Test empty input.
        assert!(compact_page_frame_numbers(&mut vec![]).is_empty());

        // Test single compact range.
        assert_eq!(
            compact_page_frame_numbers(&mut (0 as u32..100 as u32).collect()),
            vec![(0, 100)]
        );

        // `compact_page_frame_numbers` works even when given out of order input.
        assert_eq!(
            compact_page_frame_numbers(&mut (0 as u32..100 as u32).rev().collect()),
            vec![(0, 100)]
        );

        // Test with 100 distinct ranges.
        assert_eq!(
            compact_page_frame_numbers(
                &mut (0 as u32..10000 as u32)
                    .step_by(100)
                    .flat_map(|x| (x..x + 10).rev())
                    .collect()
            ),
            (0 as u32..10000 as u32)
                .step_by(100)
                .map(|x| (x, 10 as u32))
                .collect::<Vec<(u32, u32)>>()
        );
    }

    #[test]
    fn test_remove_range() {
        let page_size: usize = 0x1000;
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 2 * page_size)]).unwrap();

        // Fill the memory with ones.
        let ones = vec![1u8; 2 * page_size];
        mem.write(&ones[..], GuestAddress(0)).unwrap();

        // Remove the first page.
        assert!(remove_range(&mem, (GuestAddress(0), page_size as u64)).is_ok());

        // Check that the first page is zeroed.
        let mut actual_page = vec![0u8; page_size];
        mem.read(&mut actual_page.as_mut_slice(), GuestAddress(0))
            .unwrap();
        assert_eq!(vec![0u8; page_size], actual_page);
        // Check that the second page still contains ones.
        mem.read(
            &mut actual_page.as_mut_slice(),
            GuestAddress(page_size as u64),
        )
        .unwrap();
        assert_eq!(vec![1u8; page_size], actual_page);

        // Malformed range: the len is too big.
        assert_match!(
            remove_range(&mem, (GuestAddress(0), 0x10000)).unwrap_err(),
            RemoveRegionError::MalformedRange
        );

        // Region not mapped.
        assert_match!(
            remove_range(&mem, (GuestAddress(0x10000), 0x10)).unwrap_err(),
            RemoveRegionError::RegionNotFound
        );

        // Mmap fail: the guest address is not aligned to the page size.
        assert_match!(
            remove_range(&mem, (GuestAddress(0x20), page_size as u64)).unwrap_err(),
            RemoveRegionError::MmapFail(_)
        );
    }
}