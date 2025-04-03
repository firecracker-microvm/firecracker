// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Module temporarily containing vendored in-review vm-memory features
//!
//! TODO: To be removed once https://github.com/rust-vmm/vm-memory/pull/312 is merged

use std::sync::Arc;

use vm_memory::{Error, GuestAddress, GuestMemory, GuestMemoryRegion};

/// [`GuestMemory`](trait.GuestMemory.html) implementation based on a homogeneous collection
/// of [`GuestMemoryRegion`] implementations.
///
/// Represents a sorted set of non-overlapping physical guest memory regions.
#[derive(Debug)]
pub struct GuestRegionCollection<R> {
    regions: Vec<Arc<R>>,
}

impl<R> Default for GuestRegionCollection<R> {
    fn default() -> Self {
        Self {
            regions: Vec::new(),
        }
    }
}

impl<R> Clone for GuestRegionCollection<R> {
    fn clone(&self) -> Self {
        GuestRegionCollection {
            regions: self.regions.iter().map(Arc::clone).collect(),
        }
    }
}

impl<R: GuestMemoryRegion> GuestRegionCollection<R> {
    /// Creates a new [`GuestRegionCollection`] from a vector of regions.
    ///
    /// # Arguments
    ///
    /// * `regions` - The vector of regions. The regions shouldn't overlap, and they should be
    ///   sorted by the starting address.
    pub fn from_regions(mut regions: Vec<R>) -> std::result::Result<Self, Error> {
        Self::from_arc_regions(regions.drain(..).map(Arc::new).collect())
    }

    /// Creates a new [`GuestRegionCollection`] from a vector of Arc regions.
    ///
    /// Similar to the constructor `from_regions()` as it returns a
    /// [`GuestRegionCollection`]. The need for this constructor is to provide a way for
    /// consumer of this API to create a new [`GuestRegionCollection`] based on existing
    /// regions coming from an existing [`GuestRegionCollection`] instance.
    ///
    /// # Arguments
    ///
    /// * `regions` - The vector of `Arc` regions. The regions shouldn't overlap and they should be
    ///   sorted by the starting address.
    pub fn from_arc_regions(regions: Vec<Arc<R>>) -> std::result::Result<Self, Error> {
        if regions.is_empty() {
            return Err(Error::NoMemoryRegion);
        }

        for window in regions.windows(2) {
            let prev = &window[0];
            let next = &window[1];

            if prev.start_addr() > next.start_addr() {
                return Err(Error::UnsortedMemoryRegions);
            }

            if prev.last_addr() >= next.start_addr() {
                return Err(Error::MemoryRegionOverlap);
            }
        }

        Ok(Self { regions })
    }

    /// Insert a region into the `GuestMemoryMmap` object and return a new `GuestMemoryMmap`.
    ///
    /// # Arguments
    /// * `region`: the memory region to insert into the guest memory object.
    pub fn insert_region(
        &self,
        region: Arc<R>,
    ) -> std::result::Result<GuestRegionCollection<R>, Error> {
        let mut regions = self.regions.clone();
        regions.push(region);
        regions.sort_by_key(|x| x.start_addr());

        Self::from_arc_regions(regions)
    }
}

impl<R: GuestMemoryRegion> GuestMemory for GuestRegionCollection<R> {
    type R = R;

    fn num_regions(&self) -> usize {
        self.regions.len()
    }

    fn find_region(&self, addr: GuestAddress) -> Option<&R> {
        let index = match self.regions.binary_search_by_key(&addr, |x| x.start_addr()) {
            Ok(x) => Some(x),
            // Within the closest region with starting address < addr
            Err(x) if (x > 0 && addr <= self.regions[x - 1].last_addr()) => Some(x - 1),
            _ => None,
        };
        index.map(|x| self.regions[x].as_ref())
    }

    fn iter(&self) -> impl Iterator<Item = &Self::R> {
        self.regions.iter().map(AsRef::as_ref)
    }
}
