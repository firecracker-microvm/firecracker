// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;

use super::{RemoveRegionError, MAX_PAGE_COMPACT_BUFFER};
use logger::error;
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

/// This takes a vector of page frame numbers, and compacts them
/// into ranges of consecutive pages. The result is a vector
/// of (start_page_frame_number, range_length) pairs.
pub(crate) fn compact_page_frame_numbers(v: &mut [u32]) -> Vec<(u32, u32)> {
    if v.is_empty() {
        return vec![];
    }

    // Since the total number of pages that can be
    // received at once is `MAX_PAGE_COMPACT_BUFFER`,
    // this sort does not change the complexity of handling
    // an inflation.
    v.sort_unstable();

    // Since there are at most `MAX_PAGE_COMPACT_BUFFER` pages, setting the
    // capacity of `result` to this makes sense.
    let mut result = Vec::with_capacity(MAX_PAGE_COMPACT_BUFFER);

    // The most recent range of pages is [previous..previous + length).
    let mut previous = 0;
    let mut length = 1;

    for pfn_index in 1..v.len() {
        let page_frame_number = v[pfn_index];

        // Skip duplicate pages. This will ensure we only consider
        // distinct PFNs.
        if page_frame_number == v[pfn_index - 1] {
            error!("Skipping duplicate PFN {}.", page_frame_number);
            continue;
        }

        // Check if the current page frame number is adjacent to the most recent page range.
        // This operation will never overflow because for whatever value `v[previous]`
        // has in the u32 range, we know there are at least `length` consecutive numbers
        // greater than it in the array (the greatest so far being `page_frame_number`),
        // since `v[previous]` is before all of them in the sorted array and `length`
        // was incremented for each consecutive one. This is true only because we skip
        // duplicates.
        if page_frame_number == v[previous] + length {
            // If so, extend that range.
            length += 1;
        } else {
            // Otherwise, push (previous, length) to the result vector.
            result.push((v[previous], length));
            // And update the most recent range of pages.
            previous = pfn_index;
            length = 1;
        }
    }

    // Don't forget to push the last range to the result.
    result.push((v[previous], length));

    result
}

pub(crate) fn remove_range(
    guest_memory: &GuestMemoryMmap,
    range: (GuestAddress, u64),
    restored: bool,
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
        if restored {
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
            if ret == libc::MAP_FAILED {
                return Err(RemoveRegionError::MmapFail(io::Error::last_os_error()));
            }
        };

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
            assert!(matches!($lhs, $rhs))
        }};
    }

    #[test]
    fn test_compact_page_indices() {
        // Test empty input.
        assert!(compact_page_frame_numbers(&mut []).is_empty());

        // Test single compact range.
        assert_eq!(
            compact_page_frame_numbers(&mut (0_u32..100_u32).collect::<Vec<u32>>().as_mut_slice()),
            vec![(0, 100)]
        );

        // `compact_page_frame_numbers` works even when given out of order input.
        assert_eq!(
            compact_page_frame_numbers(
                &mut (0_u32..100_u32).rev().collect::<Vec<u32>>().as_mut_slice()
            ),
            vec![(0, 100)]
        );

        // Test with 100 distinct ranges.
        assert_eq!(
            compact_page_frame_numbers(
                &mut (0_u32..10000_u32)
                    .step_by(100)
                    .flat_map(|x| (x..x + 10).rev())
                    .collect::<Vec<u32>>()
            ),
            (0_u32..10000_u32)
                .step_by(100)
                .map(|x| (x, 10_u32))
                .collect::<Vec<(u32, u32)>>()
        );

        // Test range with duplicates.
        assert_eq!(
            compact_page_frame_numbers(
                &mut (0_u32..10000_u32).map(|x| x / 2).collect::<Vec<u32>>()
            ),
            vec![(0, 5000)]
        );

        // Test there is no overflow when there are duplicate max values.
        assert_eq!(
            compact_page_frame_numbers(&mut [u32::MAX, u32::MAX]),
            vec![(u32::MAX, 1)]
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
        assert!(remove_range(&mem, (GuestAddress(0), page_size as u64), false).is_ok());

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
            remove_range(&mem, (GuestAddress(0), 0x10000), false).unwrap_err(),
            RemoveRegionError::MalformedRange
        );

        // Region not mapped.
        assert_match!(
            remove_range(&mem, (GuestAddress(0x10000), 0x10), false).unwrap_err(),
            RemoveRegionError::RegionNotFound
        );

        // Madvise fail: the guest address is not aligned to the page size.
        assert_match!(
            remove_range(&mem, (GuestAddress(0x20), page_size as u64), false).unwrap_err(),
            RemoveRegionError::MadviseFail(_)
        );
    }

    #[test]
    fn test_remove_range_on_restored() {
        let page_size: usize = 0x1000;
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 2 * page_size)]).unwrap();

        // Fill the memory with ones.
        let ones = vec![1u8; 2 * page_size];
        mem.write(&ones[..], GuestAddress(0)).unwrap();

        // Remove the first page.
        assert!(remove_range(&mem, (GuestAddress(0), page_size as u64), true).is_ok());

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
            remove_range(&mem, (GuestAddress(0), 0x10000), true).unwrap_err(),
            RemoveRegionError::MalformedRange
        );

        // Region not mapped.
        assert_match!(
            remove_range(&mem, (GuestAddress(0x10000), 0x10), true).unwrap_err(),
            RemoveRegionError::RegionNotFound
        );

        // Mmap fail: the guest address is not aligned to the page size.
        assert_match!(
            remove_range(&mem, (GuestAddress(0x20), page_size as u64), true).unwrap_err(),
            RemoveRegionError::MmapFail(_)
        );
    }

    /// -------------------------------------
    /// BEGIN PROPERTY BASED TESTING
    use proptest::prelude::*;

    fn random_pfn_u32_max() -> impl Strategy<Value = Vec<u32>> {
        // Create a randomly sized vec (max MAX_PAGE_COMPACT_BUFFER elements) filled with random u32 elements.
        prop::collection::vec(0..std::u32::MAX, 0..MAX_PAGE_COMPACT_BUFFER)
    }

    fn random_pfn_100() -> impl Strategy<Value = Vec<u32>> {
        // Create a randomly sized vec (max MAX_PAGE_COMPACT_BUFFER/8) filled with random u32 elements (0 - 100).
        prop::collection::vec(0..100u32, 0..MAX_PAGE_COMPACT_BUFFER / 8)
    }

    // The uncompactor will output deduplicated and sorted elements as compaction algorithm
    // guarantees it.
    fn uncompact(compacted: Vec<(u32, u32)>) -> Vec<u32> {
        let mut result = Vec::new();
        for (start, len) in compacted {
            result.extend(start..start + len);
        }
        result
    }

    fn sort_and_dedup<T: Ord + Clone>(v: &[T]) -> Vec<T> {
        let mut sorted_v = v.to_vec();
        sorted_v.sort_unstable();
        sorted_v.dedup();
        sorted_v
    }

    // The below prop tests will validate the following output propreties:
    // - vec elements are sorted by first tuple value
    // - no pfn duplicates are present
    // - no pfn is lost
    #[test]
    fn test_pfn_compact() {
        let cfg = ProptestConfig::with_cases(1500);
        proptest!(cfg, |(mut input1 in random_pfn_u32_max(), mut input2 in random_pfn_100())| {
            // The uncompactor will output sorted elements.
            prop_assert!(
                uncompact(compact_page_frame_numbers(input1.as_mut_slice()))
                    == sort_and_dedup(input1.as_slice())
            );
            // Input2 will ensure duplicate PFN cases are also covered.
            prop_assert!(
                uncompact(compact_page_frame_numbers(input2.as_mut_slice()))
                    == sort_and_dedup(input2.as_slice())
            );
        });
    }
}
