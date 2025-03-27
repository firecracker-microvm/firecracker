// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Module temporarily containing vendored in-review vm-memory features
//!
//! TODO: To be removed once https://github.com/rust-vmm/vm-memory/pull/312 is merged

#![allow(clippy::cast_possible_truncation)] // vm-memory has different clippy configuration

use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use vm_memory::guest_memory::Result;
use vm_memory::{
    Address, AtomicAccess, Bytes, Error, GuestAddress, GuestMemory, GuestMemoryError,
    GuestMemoryRegion, MemoryRegionAddress,
};

use crate::vstate::memory::KvmRegion;

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

// This impl will be subsumed by the default impl in vm-memory#312
impl Bytes<MemoryRegionAddress> for KvmRegion {
    type E = GuestMemoryError;

    /// # Examples
    /// * Write a slice at guest address 0x1200.
    ///
    /// ```
    /// # #[cfg(feature = "backend-mmap")]
    /// # use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
    /// #
    /// # #[cfg(feature = "backend-mmap")]
    /// # {
    /// # let start_addr = GuestAddress(0x1000);
    /// # let mut gm = GuestMemoryMmap::<()>::from_ranges(&vec![(start_addr, 0x400)])
    /// #    .expect("Could not create guest memory");
    /// #
    /// let res = gm
    ///     .write(&[1, 2, 3, 4, 5], GuestAddress(0x1200))
    ///     .expect("Could not write to guest memory");
    /// assert_eq!(5, res);
    /// # }
    /// ```
    fn write(&self, buf: &[u8], addr: MemoryRegionAddress) -> Result<usize> {
        let maddr = addr.raw_value() as usize;
        self.as_volatile_slice()?
            .write(buf, maddr)
            .map_err(Into::into)
    }

    /// # Examples
    /// * Read a slice of length 16 at guestaddress 0x1200.
    ///
    /// ```
    /// # #[cfg(feature = "backend-mmap")]
    /// # use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
    /// #
    /// # #[cfg(feature = "backend-mmap")]
    /// # {
    /// # let start_addr = GuestAddress(0x1000);
    /// # let mut gm = GuestMemoryMmap::<()>::from_ranges(&vec![(start_addr, 0x400)])
    /// #    .expect("Could not create guest memory");
    /// #
    /// let buf = &mut [0u8; 16];
    /// let res = gm
    ///     .read(buf, GuestAddress(0x1200))
    ///     .expect("Could not read from guest memory");
    /// assert_eq!(16, res);
    /// # }
    /// ```
    fn read(&self, buf: &mut [u8], addr: MemoryRegionAddress) -> Result<usize> {
        let maddr = addr.raw_value() as usize;
        self.as_volatile_slice()?
            .read(buf, maddr)
            .map_err(Into::into)
    }

    fn write_slice(&self, buf: &[u8], addr: MemoryRegionAddress) -> Result<()> {
        let maddr = addr.raw_value() as usize;
        self.as_volatile_slice()?
            .write_slice(buf, maddr)
            .map_err(Into::into)
    }

    fn read_slice(&self, buf: &mut [u8], addr: MemoryRegionAddress) -> Result<()> {
        let maddr = addr.raw_value() as usize;
        self.as_volatile_slice()?
            .read_slice(buf, maddr)
            .map_err(Into::into)
    }

    fn store<T: AtomicAccess>(
        &self,
        val: T,
        addr: MemoryRegionAddress,
        order: Ordering,
    ) -> Result<()> {
        self.as_volatile_slice().and_then(|s| {
            s.store(val, addr.raw_value() as usize, order)
                .map_err(Into::into)
        })
    }

    fn load<T: AtomicAccess>(&self, addr: MemoryRegionAddress, order: Ordering) -> Result<T> {
        self.as_volatile_slice()
            .and_then(|s| s.load(addr.raw_value() as usize, order).map_err(Into::into))
    }

    // All remaining functions are deprecated and have been removed in vm-memory/main.
    // Firecracker does not use them, so no point in writing out implementations here.
    fn read_from<F>(
        &self,
        _addr: MemoryRegionAddress,
        _src: &mut F,
        _count: usize,
    ) -> std::result::Result<usize, Self::E>
    where
        F: Read,
    {
        unimplemented!()
    }

    fn read_exact_from<F>(
        &self,
        _addr: MemoryRegionAddress,
        _src: &mut F,
        _count: usize,
    ) -> std::result::Result<(), Self::E>
    where
        F: Read,
    {
        unimplemented!()
    }

    fn write_to<F>(
        &self,
        _addr: MemoryRegionAddress,
        _dst: &mut F,
        _count: usize,
    ) -> std::result::Result<usize, Self::E>
    where
        F: Write,
    {
        unimplemented!()
    }

    fn write_all_to<F>(
        &self,
        _addr: MemoryRegionAddress,
        _dst: &mut F,
        _count: usize,
    ) -> std::result::Result<(), Self::E>
    where
        F: Write,
    {
        unimplemented!()
    }
}
