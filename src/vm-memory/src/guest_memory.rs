// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Track memory regions that are mapped to the guest microVM.

use std::io::{Read, Write};
use std::sync::Arc;
use std::{mem, result};

use guest_address::{Address, GuestAddress};
use mmap::{self, MemoryMapping};
use {ByteValued, Bytes};

/// Errors associated with handling guest memory regions.
#[derive(Debug)]
pub enum Error {
    /// Failure in finding a guest address in any memory regions mapped by this guest.
    InvalidGuestAddress(GuestAddress),
    /// Failure in finding a guest address range in any memory regions mapped by this guest.
    InvalidGuestAddressRange(GuestAddress, usize),
    /// Failure in accessing the memory located at some address.
    MemoryAccess(GuestAddress, mmap::Error),
    /// Failure in creating an anonymous shared mapping.
    MemoryMappingFailed(mmap::Error),
    /// Failure in initializing guest memory.
    MemoryNotInitialized,
    /// Two of the memory regions are overlapping.
    MemoryRegionOverlap,
    /// No memory regions were provided for initializing the guest memory.
    NoMemoryRegions,
}

type Result<T> = result::Result<T, Error>;

/// Represents a continuous region of guest physical memory.
#[allow(clippy::len_without_is_empty)]
pub trait GuestMemoryRegion {
    /// Get the size of the region.
    fn len(&self) -> usize;

    /// Get minimum (inclusive) address managed by the region.
    fn start_addr(&self) -> GuestAddress;

    /// Get maximum (inclusive) address managed by the region.
    fn last_addr(&self) -> GuestAddress;
}

/// Tracks a mapping of anonymous memory in the current process and the corresponding base address
/// in the guest's memory space.
pub struct MemoryRegion {
    mapping: MemoryMapping,
    guest_base: GuestAddress,
}

impl MemoryRegion {}

impl GuestMemoryRegion for MemoryRegion {
    fn len(&self) -> usize {
        self.mapping.size()
    }

    fn start_addr(&self) -> GuestAddress {
        self.guest_base
    }

    fn last_addr(&self) -> GuestAddress {
        // unchecked_add is safe as the region bounds were checked when it was created.
        self.guest_base
            .unchecked_add((self.mapping.size() - 1) as u64)
    }
}

/// Represents a container for a collection of GuestMemoryRegion objects.
///
/// The main responsibilities of the GuestMemory trait are:
/// - hide the detail of accessing guest's physical address.
/// - map a request address to a GuestMemoryRegion object and relay the request to it.
/// - handle cases where an access request spanning two or more GuestMemoryRegion objects.
///
/// Note: all regions in a GuestMemory object must not intersect with each other.
pub trait GuestMemory {
    /// Type of objects hosted by the address space.
    type R: GuestMemoryRegion;
}

/// Tracks all memory regions allocated for the guest in the current process.
#[derive(Clone)]
pub struct GuestMemoryMmap {
    regions: Arc<Vec<MemoryRegion>>,
}

impl GuestMemoryMmap {
    /// Creates a container for guest memory regions.
    /// Valid memory regions are specified as a Vec of (Address, Size) tuples sorted by Address.
    pub fn new(ranges: &[(GuestAddress, usize)]) -> Result<GuestMemoryMmap> {
        if ranges.is_empty() {
            return Err(Error::NoMemoryRegions);
        }

        let mut regions = Vec::<MemoryRegion>::new();
        for range in ranges.iter() {
            if let Some(last) = regions.last() {
                if last
                    .guest_base
                    .checked_add(last.mapping.size() as u64)
                    .map_or(true, |a| a > range.0)
                {
                    return Err(Error::MemoryRegionOverlap);
                }
            }

            let mapping = MemoryMapping::new(range.1).map_err(Error::MemoryMappingFailed)?;
            regions.push(MemoryRegion {
                mapping,
                guest_base: range.0,
            });
        }

        Ok(GuestMemoryMmap {
            regions: Arc::new(regions),
        })
    }

    /// Returns the last address of memory.
    ///
    /// # Examples
    ///
    /// ```
    /// use vm_memory::{Address, GuestAddress, GuestMemoryMmap, MemoryMapping};
    /// fn test_last_addr() -> Result<(), ()> {
    ///     let start_addr = GuestAddress(0x1000);
    ///     let mut gm = GuestMemoryMmap::new(&vec![(start_addr, 0x400)]).map_err(|_| ())?;
    ///     assert_eq!(start_addr.checked_add(0x3ff), Some(gm.last_addr()));
    ///     Ok(())
    /// }
    /// ```
    pub fn last_addr(&self) -> GuestAddress {
        self.regions
            .iter()
            .max_by_key(|region| region.guest_base)
            .map_or(GuestAddress(0), |region| region.last_addr())
    }

    /// Returns true if the given address is within the memory range available to the guest.
    pub fn address_in_range(&self, addr: GuestAddress) -> bool {
        for region in self.regions.iter() {
            if addr >= region.guest_base && addr <= region.last_addr() {
                return true;
            }
        }
        false
    }

    /// Returns the address plus the offset if the result falls within a valid memory region. The
    /// resulting address and base address may belong to different memory regions, and the base
    /// might not even exist in a valid region.
    pub fn checked_offset(&self, base: GuestAddress, offset: usize) -> Option<GuestAddress> {
        let addr = base.checked_add(offset as u64)?;
        if self.address_in_range(addr) {
            return Some(addr);
        }

        None
    }

    /// Returns the size of the memory region.
    pub fn num_regions(&self) -> usize {
        self.regions.len()
    }

    /// Returns the size of the region identified by passed index
    pub fn region_size(&self, index: usize) -> Result<usize> {
        if index >= self.regions.len() {
            return Err(Error::NoMemoryRegions);
        }

        Ok(self.regions[index].mapping.size())
    }

    /// Perform the specified action on each region's addresses.
    pub fn with_regions<F, E>(&self, cb: F) -> result::Result<(), E>
    where
        F: Fn(usize, GuestAddress, usize, usize) -> result::Result<(), E>,
    {
        for (index, region) in self.regions.iter().enumerate() {
            cb(
                index,
                region.guest_base,
                region.mapping.size(),
                region.mapping.as_ptr() as usize,
            )?;
        }
        Ok(())
    }

    /// Perform the specified action on each region's addresses mutably.
    pub fn with_regions_mut<F, E>(&self, mut cb: F) -> result::Result<(), E>
    where
        F: FnMut(usize, GuestAddress, usize, usize) -> result::Result<(), E>,
    {
        for (index, region) in self.regions.iter().enumerate() {
            cb(
                index,
                region.guest_base,
                region.mapping.size(),
                region.mapping.as_ptr() as usize,
            )?;
        }
        Ok(())
    }

    /// Converts a GuestAddress into a pointer in the address space of this
    /// process. This should only be necessary for giving addresses to the
    /// kernel, as with vhost ioctls. Normal reads/writes to guest memory should
    /// be done through `write_from_memory`, `read_obj_from_addr`, etc.
    ///
    /// # Arguments
    /// * `guest_addr` - Guest address to convert.
    ///
    /// # Examples
    ///
    /// ```
    /// use vm_memory::{GuestAddress, GuestMemoryMmap};
    /// fn test_host_addr() -> Result<(), ()> {
    ///     let start_addr = GuestAddress(0x1000);
    ///     let mut gm = GuestMemoryMmap::new(&vec![(start_addr, 0x500)]).map_err(|_| ())?;
    ///     let addr = gm.get_host_address(GuestAddress(0x1200)).unwrap();
    ///     println!("Host address is {:p}", addr);
    ///     Ok(())
    /// }
    /// ```
    pub fn get_host_address(&self, guest_addr: GuestAddress) -> Result<*const u8> {
        self.do_in_region(guest_addr, 1, |mapping, offset| {
            // This is safe; `do_in_region` already checks that offset is in
            // bounds.
            Ok(unsafe { mapping.as_ptr().add(offset) } as *const u8)
        })
    }

    /// Applies two functions, specified as callbacks, on the inner memory regions.
    ///
    /// # Arguments
    /// * `init` - Starting value of the accumulator for the `foldf` function.
    /// * `mapf` - "Map" function, applied to all the inner memory regions. It returns an array of
    ///            the same size as the memory regions array, containing the function's results
    ///            for each region.
    /// * `foldf` - "Fold" function, applied to the array returned by `mapf`. It acts as an
    ///             operator, applying itself to the `init` value and to each subsequent elemnent
    ///             in the array returned by `mapf`.
    ///
    /// # Examples
    ///
    /// * Compute the total size of all memory mappings in KB by iterating over the memory regions
    ///   and dividing their sizes to 1024, then summing up the values in an accumulator.
    ///
    /// ```
    /// use vm_memory::{GuestAddress, GuestMemoryMmap, GuestMemoryRegion};
    /// fn test_map_fold() -> Result<(), ()> {
    ///     let start_addr1 = GuestAddress(0x0);
    ///     let start_addr2 = GuestAddress(0x400);
    ///     let mem = GuestMemoryMmap::new(&vec![(start_addr1, 1024), (start_addr2, 2048)]).unwrap();
    ///     let total_size = mem.map_and_fold(
    ///         0,
    ///         |(_, region)| region.len() / 1024,
    ///         |acc, size| acc + size,
    ///     );
    ///     println!("Total memory size = {} KB", total_size);
    ///     Ok(())
    /// }
    /// ```
    pub fn map_and_fold<F, G, T>(&self, init: T, mapf: F, foldf: G) -> T
    where
        F: Fn((usize, &MemoryRegion)) -> T,
        G: Fn(T, T) -> T,
    {
        self.regions.iter().enumerate().map(mapf).fold(init, foldf)
    }

    /// Read the whole object from a single MemoryRegion
    pub fn do_in_region<F, T>(&self, guest_addr: GuestAddress, size: usize, cb: F) -> Result<T>
    where
        F: FnOnce(&MemoryMapping, usize) -> Result<T>,
    {
        for region in self.regions.iter() {
            if guest_addr >= region.guest_base && guest_addr <= region.last_addr() {
                // it's safe to use unchecked_offset_from because
                // guest_addr >= region.guest_base
                // it's safe to convert the result to usize since region.size() is usize
                let offset = guest_addr.unchecked_offset_from(region.guest_base) as usize;
                if size <= region.mapping.size() - offset {
                    return cb(&region.mapping, offset);
                }
                break;
            }
        }
        Err(Error::InvalidGuestAddressRange(guest_addr, size))
    }

    /// Read the whole or partial content from a single MemoryRegion
    fn do_in_region_partial<F>(&self, guest_addr: GuestAddress, cb: F) -> Result<()>
    where
        F: FnOnce(&MemoryMapping, usize) -> Result<()>,
    {
        for region in self.regions.iter() {
            if guest_addr >= region.guest_base && guest_addr <= region.last_addr() {
                return cb(
                    &region.mapping,
                    // it's safe to use unchecked_offset_from because
                    // guest_addr >= region.guest_base
                    // it's safe to convert the result to usize since region.size() is usize
                    guest_addr.unchecked_offset_from(region.guest_base) as usize,
                );
            }
        }
        Err(Error::InvalidGuestAddress(guest_addr))
    }
}

impl GuestMemory for GuestMemoryMmap {
    type R = MemoryRegion;
}

impl Bytes<GuestAddress> for GuestMemoryMmap {
    type E = Error;

    /// # Examples
    /// * Write a slice at guestaddress 0x200.
    ///
    /// ```
    /// use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap, MemoryMapping};
    /// fn test_write_u64() -> Result<(), ()> {
    ///     let start_addr = GuestAddress(0x1000);
    ///     let mut gm = GuestMemoryMmap::new(&vec![(start_addr, 0x400)]).map_err(|_| ())?;
    ///     let res = gm
    ///         .write_slice(&[1, 2, 3, 4, 5], GuestAddress(0x200))
    ///         .map_err(|_| ())?;
    ///     Ok(())
    /// }
    /// ```
    fn write_slice(&self, buf: &[u8], addr: GuestAddress) -> std::result::Result<(), Self::E> {
        self.do_in_region_partial(addr, move |mapping, offset| {
            mapping
                .write_slice(buf, offset)
                .map_err(|e| Error::MemoryAccess(addr, e))
        })
    }

    /// # Examples
    /// * Read a slice of length 16 at guestaddress 0x200.
    ///
    /// ```
    /// use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap, MemoryMapping};
    /// fn test_write_u64() -> Result<(), ()> {
    ///     let start_addr = GuestAddress(0x1000);
    ///     let mut gm = GuestMemoryMmap::new(&vec![(start_addr, 0x400)]).map_err(|_| ())?;
    ///     let buf = &mut [0u8; 16];
    ///     let res = gm
    ///         .read_slice(buf, GuestAddress(0x200))
    ///         .map_err(|_| ())?;
    ///     Ok(())
    /// }
    /// ```
    fn read_slice(&self, buf: &mut [u8], addr: GuestAddress) -> std::result::Result<(), Self::E> {
        self.do_in_region_partial(addr, move |mapping, offset| {
            mapping
                .read_slice(buf, offset)
                .map_err(|e| Error::MemoryAccess(addr, e))
        })
    }

    /// # Examples
    /// * Write a u64 at guest address 0x1100.
    ///
    /// ```
    /// use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap, MemoryMapping};
    /// fn test_write_u64() -> Result<(), ()> {
    ///     let start_addr = GuestAddress(0x1000);
    ///     let mut gm = GuestMemoryMmap::new(&vec![(start_addr, 0x400)]).map_err(|_| ())?;
    ///     gm.write_obj(55u64, GuestAddress(0x1100))
    ///         .map_err(|_| ())
    /// }
    /// ```
    fn write_obj<T: ByteValued>(
        &self,
        val: T,
        addr: GuestAddress,
    ) -> std::result::Result<(), Self::E> {
        self.do_in_region(addr, mem::size_of::<T>(), move |mapping, offset| {
            mapping
                .write_obj(val, offset)
                .map_err(|e| Error::MemoryAccess(addr, e))
        })
    }

    /// # Examples
    /// * Read a u64 from two areas of guest memory backed by separate mappings.
    ///
    /// ```
    /// use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap, MemoryMapping};
    /// fn test_read_u64() -> Result<u64, ()> {
    ///     let start_addr1 = GuestAddress(0x0);
    ///     let start_addr2 = GuestAddress(0x400);
    ///     let mut gm =
    ///         GuestMemoryMmap::new(&vec![(start_addr1, 0x400), (start_addr2, 0x400)]).map_err(|_| ())?;
    ///     let num1: u64 = gm.read_obj(GuestAddress(32)).map_err(|_| ())?;
    ///     let num2: u64 = gm
    ///         .read_obj(GuestAddress(0x400 + 32))
    ///         .map_err(|_| ())?;
    ///     Ok(num1 + num2)
    /// }
    /// ```
    fn read_obj<T: ByteValued>(&self, addr: GuestAddress) -> std::result::Result<T, Self::E> {
        self.do_in_region(addr, mem::size_of::<T>(), |mapping, offset| {
            mapping
                .read_obj(offset)
                .map_err(|e| Error::MemoryAccess(addr, e))
        })
    }

    /// # Examples
    ///
    /// * Read bytes from /dev/urandom
    ///
    /// ```
    /// use vm_memory::{Address, Bytes, GuestAddress, GuestMemoryMmap, MemoryMapping};
    /// use std::fs::File;
    /// use std::path::Path;
    /// fn test_read_random() -> Result<u32, ()> {
    ///     let start_addr = GuestAddress(0x1000);
    ///     let gm = GuestMemoryMmap::new(&vec![(start_addr, 0x400)]).map_err(|_| ())?;
    ///     let mut file = File::open(Path::new("/dev/urandom")).map_err(|_| ())?;
    ///     let addr = GuestAddress(0x1010);
    ///     gm.read_from(addr, &mut file, 128).map_err(|_| ())?;
    ///     let read_addr = addr.checked_add(8).ok_or(())?;
    ///     let rand_val: u32 = gm.read_obj(read_addr).map_err(|_| ())?;
    ///     Ok(rand_val)
    /// }
    /// ```
    fn read_from<F>(
        &self,
        addr: GuestAddress,
        src: &mut F,
        count: usize,
    ) -> std::result::Result<usize, Self::E>
    where
        F: Read,
    {
        self.do_in_region(addr, count, move |mapping, offset| {
            mapping
                .read_to_memory(offset, src, count)
                .map_err(|e| Error::MemoryAccess(addr, e))?;
            Ok(count)
        })
    }

    /// # Examples
    ///
    /// * Write 128 bytes to /dev/null
    ///
    /// ```
    /// use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap, MemoryMapping};
    /// use std::fs::File;
    /// use std::path::Path;
    /// fn test_write_null() -> Result<(), ()> {
    ///     let start_addr = GuestAddress(0x1000);
    ///     let gm = GuestMemoryMmap::new(&vec![(start_addr, 0x400)]).map_err(|_| ())?;
    ///     let mut file = File::open(Path::new("/dev/null")).map_err(|_| ())?;
    ///     let addr = GuestAddress(0x1010);
    ///     gm.write_to(addr, &mut file, 128).map_err(|_| ())?;
    ///     Ok(())
    /// }
    /// ```
    fn write_to<F>(
        &self,
        addr: GuestAddress,
        dst: &mut F,
        count: usize,
    ) -> std::result::Result<usize, Self::E>
    where
        F: Write,
    {
        self.do_in_region(addr, count, move |mapping, offset| {
            mapping
                .write_from_memory(offset, dst, count)
                .map_err(|e| Error::MemoryAccess(addr, e))?;
            Ok(count)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::mem;
    use std::path::Path;

    #[test]
    fn test_regions() {
        // No regions provided should return error.
        assert_eq!(
            format!("{:?}", GuestMemoryMmap::new(&[]).err().unwrap()),
            format!("{:?}", Error::NoMemoryRegions)
        );

        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x800);
        let guest_mem =
            GuestMemoryMmap::new(&[(start_addr1, 0x400), (start_addr2, 0x400)]).unwrap();
        assert_eq!(guest_mem.num_regions(), 2);
        assert!(guest_mem.address_in_range(GuestAddress(0x200)));
        assert!(!guest_mem.address_in_range(GuestAddress(0x600)));
        assert!(guest_mem.address_in_range(GuestAddress(0xa00)));

        let last_addr = GuestAddress(0xc00);
        assert!(!guest_mem.address_in_range(last_addr));
        assert_eq!(guest_mem.last_addr(), last_addr.checked_sub(1).unwrap());

        // Begins and ends within first region.
        assert_eq!(
            guest_mem.checked_offset(start_addr1, 0x300),
            Some(GuestAddress(0x300))
        );

        // Begins in the first region, and ends in the second, crossing the gap.
        assert_eq!(
            guest_mem.checked_offset(start_addr1, 0x900),
            Some(GuestAddress(0x900))
        );

        // Goes past the end of the first region, into the gap.
        assert!(guest_mem.checked_offset(start_addr1, 0x700).is_none());

        // Starts in the second region, and goes past the end of it.
        assert!(guest_mem.checked_offset(start_addr2, 0xc00).is_none());

        // Exists entirely within the gap.
        assert!(guest_mem
            .checked_offset(GuestAddress(0x500), 0x100)
            .is_none());

        // Starts inside the gap, crosses into the second region.
        assert_eq!(
            guest_mem.checked_offset(GuestAddress(0x500), 0x400),
            Some(GuestAddress(0x900))
        );
    }

    #[test]
    fn overlap_memory() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let res = GuestMemoryMmap::new(&[(start_addr1, 0x2000), (start_addr2, 0x2000)]);
        assert_eq!(
            format!("{:?}", res.err().unwrap()),
            format!("{:?}", Error::MemoryRegionOverlap)
        );
    }

    #[test]
    fn test_read_u64() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let bad_addr = GuestAddress(0x2001);
        let bad_addr2 = GuestAddress(0x1ffc);

        let gm = GuestMemoryMmap::new(&[(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();

        let val1: u64 = 0xaa55_aa55_aa55_aa55;
        let val2: u64 = 0x55aa_55aa_55aa_55aa;
        assert_eq!(
            format!("{:?}", gm.write_obj(val1, bad_addr).err().unwrap()),
            format!(
                "InvalidGuestAddressRange({:?}, {:?})",
                bad_addr,
                std::mem::size_of::<u64>()
            )
        );
        assert_eq!(
            format!("{:?}", gm.write_obj(val1, bad_addr2).err().unwrap()),
            format!(
                "InvalidGuestAddressRange({:?}, {:?})",
                bad_addr2,
                std::mem::size_of::<u64>()
            )
        );

        gm.write_obj(val1, GuestAddress(0x500)).unwrap();
        gm.write_obj(val2, GuestAddress(0x1000 + 32)).unwrap();
        let num1: u64 = gm.read_obj(GuestAddress(0x500)).unwrap();
        let num2: u64 = gm.read_obj(GuestAddress(0x1000 + 32)).unwrap();
        assert_eq!(val1, num1);
        assert_eq!(val2, num2);
    }

    #[test]
    fn write_and_read_slice() {
        let mut start_addr = GuestAddress(0x1000);
        let gm = GuestMemoryMmap::new(&[(start_addr, 0x400)]).unwrap();
        let sample_buf = &[1, 2, 3, 4, 5];

        assert!(gm.write_slice(sample_buf, start_addr).is_ok());

        let buf = &mut [0u8; 5];
        assert!(gm.read_slice(buf, start_addr).is_ok());
        assert_eq!(buf, sample_buf);

        start_addr = GuestAddress(0x13ff);
        assert!(gm.write_slice(sample_buf, start_addr).is_err());
        assert!(gm.read_slice(buf, start_addr).is_err());
        assert_eq!(buf[0], sample_buf[0]);
    }

    #[test]
    fn read_to_and_write_from_mem() {
        let gm = GuestMemoryMmap::new(&[(GuestAddress(0x1000), 0x400)]).unwrap();
        let addr = GuestAddress(0x1010);
        gm.write_obj(!0u32, addr).unwrap();
        gm.read_from(
            addr,
            &mut File::open(Path::new("/dev/zero")).unwrap(),
            mem::size_of::<u32>(),
        )
        .unwrap();
        let value: u32 = gm.read_obj(addr).unwrap();
        assert_eq!(value, 0);

        let mut sink = Vec::new();
        gm.write_to(addr, &mut sink, mem::size_of::<u32>()).unwrap();
        assert_eq!(sink, vec![0; mem::size_of::<u32>()]);
    }

    #[test]
    fn create_vec_with_regions() {
        let region_size = 0x400;
        let regions = vec![
            (GuestAddress(0x0), region_size),
            (GuestAddress(0x1000), region_size),
        ];
        let mut iterated_regions = Vec::new();
        let gm = GuestMemoryMmap::new(&regions).unwrap();

        let res: Result<()> = gm.with_regions(|_, _, size, _| {
            assert_eq!(size, region_size);
            Ok(())
        });
        assert!(res.is_ok());

        let res: Result<()> = gm.with_regions_mut(|_, guest_addr, size, _| {
            iterated_regions.push((guest_addr, size));
            Ok(())
        });
        assert!(res.is_ok());
        assert_eq!(regions, iterated_regions);
        assert_eq!(gm.clone().regions[0].guest_base, regions[0].0);
        assert_eq!(gm.clone().regions[1].guest_base, regions[1].0);
    }

    // Get the base address of the mapping for a GuestAddress.
    fn get_mapping(mem: &GuestMemoryMmap, addr: GuestAddress) -> Result<*const u8> {
        mem.do_in_region(addr, 1, |mapping, _| Ok(mapping.as_ptr() as *const u8))
    }

    #[test]
    fn test_guest_to_host() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x100);
        let mem = GuestMemoryMmap::new(&[(start_addr1, 0x100), (start_addr2, 0x400)]).unwrap();

        assert!(mem.get_host_address(start_addr1).is_ok());

        assert!(mem
            .get_host_address(start_addr2.checked_add(0x100).unwrap())
            .is_ok());

        // Verify the host addresses match what we expect from the mappings.
        let addr1_base = get_mapping(&mem, start_addr1).unwrap();
        let addr2_base = get_mapping(&mem, start_addr2).unwrap();
        let host_addr1 = mem.get_host_address(start_addr1).unwrap();
        let host_addr2 = mem.get_host_address(start_addr2).unwrap();
        assert_eq!(host_addr1, addr1_base);
        assert_eq!(host_addr2, addr2_base);

        // Check that a bad address returns an error.
        let bad_addr = GuestAddress(0x12_3456);
        assert!(mem.get_host_address(bad_addr).is_err());
    }

    #[test]
    fn test_map_fold() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x400);
        let mem = GuestMemoryMmap::new(&[(start_addr1, 1024), (start_addr2, 2048)]).unwrap();

        assert_eq!(
            mem.map_and_fold(0, |(_, region)| region.len() / 1024, |acc, size| acc + size),
            3
        );
    }

    #[test]
    fn test_region_size() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let mem = GuestMemoryMmap::new(&[(start_addr1, 0x100), (start_addr2, 0x400)]).unwrap();

        assert_eq!(mem.region_size(0).unwrap(), 0x100);
        assert_eq!(mem.region_size(1).unwrap(), 0x400);
        assert!(mem.region_size(2).is_err());
    }
}
