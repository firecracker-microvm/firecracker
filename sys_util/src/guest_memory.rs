// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Track memory regions that are mapped to the guest VM.

use std::io::{Read, Write};
use std::result;
use std::sync::Arc;

use memory_model::DataInit;
use memory_model::volatile_memory::*;
use guest_address::GuestAddress;
use mmap::{self, MemoryMapping};

#[derive(Debug)]
pub enum Error {
    InvalidGuestAddress(GuestAddress),
    MemoryAccess(GuestAddress, mmap::Error),
    MemoryMappingFailed(mmap::Error),
    MemoryRegionOverlap,
    NoMemoryRegions,
    RegionOperationFailed,
}
pub type Result<T> = result::Result<T, Error>;

struct MemoryRegion {
    mapping: MemoryMapping,
    guest_base: GuestAddress,
}

fn region_end(region: &MemoryRegion) -> GuestAddress {
    // unchecked_add is safe as the region bounds were checked when it was created.
    region.guest_base.unchecked_add(region.mapping.size())
}

/// Tracks a memory region and where it is mapped in the guest.
#[derive(Clone)]
pub struct GuestMemory {
    regions: Arc<Vec<MemoryRegion>>,
}

impl GuestMemory {
    /// Creates a container for guest memory regions.
    /// Valid memory regions are specified as a Vec of (Address, Size) tuples sorted by Address.
    pub fn new(ranges: &[(GuestAddress, usize)]) -> Result<GuestMemory> {
        if ranges.is_empty() {
            return Err(Error::NoMemoryRegions);
        }

        let mut regions = Vec::<MemoryRegion>::new();
        for range in ranges.iter() {
            if let Some(last) = regions.last() {
                if last.guest_base
                    .checked_add(last.mapping.size())
                    .map_or(true, |a| a > range.0)
                {
                    return Err(Error::MemoryRegionOverlap);
                }
            }

            let mapping = MemoryMapping::new(range.1).map_err(Error::MemoryMappingFailed)?;
            regions.push(MemoryRegion {
                mapping: mapping,
                guest_base: range.0,
            });
        }

        Ok(GuestMemory {
            regions: Arc::new(regions),
        })
    }

    /// Returns the end address of memory.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sys_util::{GuestAddress, GuestMemory, MemoryMapping};
    /// # fn test_end_addr() -> Result<(), ()> {
    ///     let start_addr = GuestAddress(0x1000);
    ///     let mut gm = GuestMemory::new(&vec![(start_addr, 0x400)]).map_err(|_| ())?;
    ///     assert_eq!(start_addr.checked_add(0x400), Some(gm.end_addr()));
    ///     Ok(())
    /// # }
    /// ```
    pub fn end_addr(&self) -> GuestAddress {
        self.regions
            .iter()
            .max_by_key(|region| region.guest_base)
            .map_or(GuestAddress(0), |region| region_end(region))
    }

    /// Returns true if the given address is within the memory range available to the guest.
    pub fn address_in_range(&self, addr: GuestAddress) -> bool {
        addr < self.end_addr()
    }

    /// Returns the address plus the offset if it is in range.
    pub fn checked_offset(&self, addr: GuestAddress, offset: usize) -> Option<GuestAddress> {
        addr.checked_add(offset)
            .and_then(|a| if a < self.end_addr() { Some(a) } else { None })
    }

    /// Returns the size of the memory region in bytes.
    pub fn num_regions(&self) -> usize {
        self.regions.len()
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
    /// Writes a slice to guest memory at the specified guest address.
    /// Returns the number of bytes written.  The number of bytes written can
    /// be less than the length of the slice if there isn't enough room in the
    /// memory region.
    ///
    /// # Examples
    /// * Write a slice at guestaddress 0x200.
    ///
    /// ```
    /// # use sys_util::{GuestAddress, GuestMemory, MemoryMapping};
    /// # fn test_write_u64() -> Result<(), ()> {
    /// #   let start_addr = GuestAddress(0x1000);
    /// #   let mut gm = GuestMemory::new(&vec![(start_addr, 0x400)]).map_err(|_| ())?;
    ///     let res = gm.write_slice_at_addr(&[1,2,3,4,5], GuestAddress(0x200)).map_err(|_| ())?;
    ///     assert_eq!(5, res);
    ///     Ok(())
    /// # }
    /// ```
    pub fn write_slice_at_addr(&self, buf: &[u8], guest_addr: GuestAddress) -> Result<usize> {
        self.do_in_region(guest_addr, move |mapping, offset| {
            mapping
                .write_slice(buf, offset)
                .map_err(|e| Error::MemoryAccess(guest_addr, e))
        })
    }

    /// Reads to a slice from guest memory at the specified guest address.
    /// Returns the number of bytes read.  The number of bytes read can
    /// be less than the length of the slice if there isn't enough room in the
    /// memory region.
    ///
    /// # Examples
    /// * Read a slice of length 16 at guestaddress 0x200.
    ///
    /// ```
    /// # use sys_util::{GuestAddress, GuestMemory, MemoryMapping};
    /// # fn test_write_u64() -> Result<(), ()> {
    /// #   let start_addr = GuestAddress(0x1000);
    /// #   let mut gm = GuestMemory::new(&vec![(start_addr, 0x400)]).map_err(|_| ())?;
    ///     let buf = &mut [0u8; 16];
    ///     let res = gm.read_slice_at_addr(buf, GuestAddress(0x200)).map_err(|_| ())?;
    ///     assert_eq!(16, res);
    ///     Ok(())
    /// # }
    /// ```
    pub fn read_slice_at_addr(
        &self,
        mut buf: &mut [u8],
        guest_addr: GuestAddress,
    ) -> Result<usize> {
        self.do_in_region(guest_addr, move |mapping, offset| {
            mapping
                .read_slice(buf, offset)
                .map_err(|e| Error::MemoryAccess(guest_addr, e))
        })
    }

    /// Reads an object from guest memory at the given guest address.
    /// Reading from a volatile area isn't strictly safe as it could change
    /// mid-read.  However, as long as the type T is plain old data and can
    /// handle random initialization, everything will be OK.
    ///
    /// # Examples
    /// * Read a u64 from two areas of guest memory backed by separate mappings.
    ///
    /// ```
    /// # use sys_util::{GuestAddress, GuestMemory, MemoryMapping};
    /// # fn test_read_u64() -> Result<u64, ()> {
    /// #     let start_addr1 = GuestAddress(0x0);
    /// #     let start_addr2 = GuestAddress(0x400);
    /// #     let mut gm = GuestMemory::new(&vec![(start_addr1, 0x400), (start_addr2, 0x400)])
    /// #         .map_err(|_| ())?;
    ///       let num1: u64 = gm.read_obj_from_addr(GuestAddress(32)).map_err(|_| ())?;
    ///       let num2: u64 = gm.read_obj_from_addr(GuestAddress(0x400+32)).map_err(|_| ())?;
    /// #     Ok(num1 + num2)
    /// # }
    /// ```
    pub fn read_obj_from_addr<T: DataInit>(&self, guest_addr: GuestAddress) -> Result<T> {
        self.do_in_region(guest_addr, |mapping, offset| {
            mapping
                .read_obj(offset)
                .map_err(|e| Error::MemoryAccess(guest_addr, e))
        })
    }

    /// Writes an object to the memory region at the specified guest address.
    /// Returns Ok(()) if the object fits, or Err if it extends past the end.
    ///
    /// # Examples
    /// * Write a u64 at guest address 0x1100.
    ///
    /// ```
    /// # use sys_util::{GuestAddress, GuestMemory, MemoryMapping};
    /// # fn test_write_u64() -> Result<(), ()> {
    /// #   let start_addr = GuestAddress(0x1000);
    /// #   let mut gm = GuestMemory::new(&vec![(start_addr, 0x400)]).map_err(|_| ())?;
    ///     gm.write_obj_at_addr(55u64, GuestAddress(0x1100))
    ///         .map_err(|_| ())
    /// # }
    /// ```
    pub fn write_obj_at_addr<T: DataInit>(&self, val: T, guest_addr: GuestAddress) -> Result<()> {
        self.do_in_region(guest_addr, move |mapping, offset| {
            mapping
                .write_obj(val, offset)
                .map_err(|e| Error::MemoryAccess(guest_addr, e))
        })
    }

    /// Reads data from a readable object like a File and writes it to guest memory.
    ///
    /// # Arguments
    /// * `guest_addr` - Begin writing memory at this offset.
    /// * `src` - Read from `src` to memory.
    /// * `count` - Read `count` bytes from `src` to memory.
    ///
    /// # Examples
    ///
    /// * Read bytes from /dev/urandom
    ///
    /// ```
    /// # use sys_util::{GuestAddress, GuestMemory, MemoryMapping};
    /// # use std::fs::File;
    /// # use std::path::Path;
    /// # fn test_read_random() -> Result<u32, ()> {
    /// #     let start_addr = GuestAddress(0x1000);
    /// #     let gm = GuestMemory::new(&vec![(start_addr, 0x400)]).map_err(|_| ())?;
    ///       let mut file = File::open(Path::new("/dev/urandom")).map_err(|_| ())?;
    ///       let addr = GuestAddress(0x1010);
    ///       gm.read_to_memory(addr, &mut file, 128).map_err(|_| ())?;
    ///       let read_addr = addr.checked_add(8).ok_or(())?;
    ///       let rand_val: u32 = gm.read_obj_from_addr(read_addr).map_err(|_| ())?;
    /// #     Ok(rand_val)
    /// # }
    /// ```
    pub fn read_to_memory<F>(
        &self,
        guest_addr: GuestAddress,
        src: &mut F,
        count: usize,
    ) -> Result<()>
    where
        F: Read,
    {
        self.do_in_region(guest_addr, move |mapping, offset| {
            mapping
                .read_to_memory(offset, src, count)
                .map_err(|e| Error::MemoryAccess(guest_addr, e))
        })
    }

    /// Writes data from memory to a writable object.
    ///
    /// # Arguments
    /// * `guest_addr` - Begin reading memory from this offset.
    /// * `dst` - Write from memory to `dst`.
    /// * `count` - Read `count` bytes from memory to `src`.
    ///
    /// # Examples
    ///
    /// * Write 128 bytes to /dev/null
    ///
    /// ```
    /// # use sys_util::{GuestAddress, GuestMemory, MemoryMapping};
    /// # use std::fs::File;
    /// # use std::path::Path;
    /// # fn test_write_null() -> Result<(), ()> {
    /// #     let start_addr = GuestAddress(0x1000);
    /// #     let gm = GuestMemory::new(&vec![(start_addr, 0x400)]).map_err(|_| ())?;
    ///       let mut file = File::open(Path::new("/dev/null")).map_err(|_| ())?;
    ///       let addr = GuestAddress(0x1010);
    ///       gm.write_from_memory(addr, &mut file, 128).map_err(|_| ())?;
    /// #     Ok(())
    /// # }
    /// ```
    pub fn write_from_memory<F>(
        &self,
        guest_addr: GuestAddress,
        dst: &mut F,
        count: usize,
    ) -> Result<()>
    where
        F: Write,
    {
        self.do_in_region(guest_addr, move |mapping, offset| {
            mapping
                .write_from_memory(offset, dst, count)
                .map_err(|e| Error::MemoryAccess(guest_addr, e))
        })
    }

    /// Convert a GuestAddress into a pointer in the address space of this
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
    /// # use sys_util::{GuestAddress, GuestMemory};
    /// # fn test_host_addr() -> Result<(), ()> {
    ///     let start_addr = GuestAddress(0x1000);
    ///     let mut gm = GuestMemory::new(&vec![(start_addr, 0x500)]).map_err(|_| ())?;
    ///     let addr = gm.get_host_address(GuestAddress(0x1200)).unwrap();
    ///     println!("Host address is {:p}", addr);
    ///     Ok(())
    /// # }
    /// ```
    pub fn get_host_address(&self, guest_addr: GuestAddress) -> Result<*const u8> {
        self.do_in_region(guest_addr, |mapping, offset| {
            // This is safe; `do_in_region` already checks that offset is in
            // bounds.
            Ok(unsafe { mapping.as_ptr().offset(offset as isize) } as *const u8)
        })
    }

    pub fn do_in_region<F, T>(&self, guest_addr: GuestAddress, cb: F) -> Result<T>
    where
        F: FnOnce(&MemoryMapping, usize) -> Result<T>,
    {
        for region in self.regions.iter() {
            if guest_addr >= region.guest_base && guest_addr < region_end(region) {
                return cb(&region.mapping, guest_addr.offset_from(region.guest_base));
            }
        }
        Err(Error::InvalidGuestAddress(guest_addr))
    }
}

impl VolatileMemory for GuestMemory {
    fn get_slice(&self, offset: usize, count: usize) -> VolatileMemoryResult<VolatileSlice> {
        for region in self.regions.iter() {
            if offset >= region.guest_base.0 && offset < region_end(region).0 {
                return region
                    .mapping
                    .get_slice(offset - region.guest_base.0, count);
            }
        }
        Err(VolatileMemoryError::OutOfBounds { addr: offset })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;
    use std::path::Path;
    use std::fs::File;

    #[test]
    fn two_regions() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x400);
        let guest_mem =
            GuestMemory::new(&vec![(start_addr1, 0x400), (start_addr2, 0x400)]).unwrap();
        assert_eq!(guest_mem.num_regions(), 2);
        assert!(guest_mem.address_in_range(GuestAddress(0x200)));
        assert!(guest_mem.address_in_range(GuestAddress(0x600)));
        let end_addr = GuestAddress(0x800);
        assert!(!guest_mem.address_in_range(end_addr));
        assert_eq!(guest_mem.end_addr(), end_addr);
        assert!(guest_mem.checked_offset(start_addr1, 0x700).is_some());
        assert!(guest_mem.checked_offset(start_addr2, 0x800).is_none());
    }

    #[test]
    fn overlap_memory() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        assert!(GuestMemory::new(&vec![(start_addr1, 0x2000), (start_addr2, 0x2000)]).is_err());
    }

    #[test]
    fn test_read_u64() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let gm = GuestMemory::new(&vec![(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();

        let val1: u64 = 0xaa55aa55aa55aa55;
        let val2: u64 = 0x55aa55aa55aa55aa;
        gm.write_obj_at_addr(val1, GuestAddress(0x500)).unwrap();
        gm.write_obj_at_addr(val2, GuestAddress(0x1000 + 32))
            .unwrap();
        let num1: u64 = gm.read_obj_from_addr(GuestAddress(0x500)).unwrap();
        let num2: u64 = gm.read_obj_from_addr(GuestAddress(0x1000 + 32)).unwrap();
        assert_eq!(val1, num1);
        assert_eq!(val2, num2);
    }

    #[test]
    fn test_ref_load_u64() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let gm = GuestMemory::new(&vec![(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();

        let val1: u64 = 0xaa55aa55aa55aa55;
        let val2: u64 = 0x55aa55aa55aa55aa;
        gm.write_obj_at_addr(val1, GuestAddress(0x500)).unwrap();
        gm.write_obj_at_addr(val2, GuestAddress(0x1000 + 32))
            .unwrap();
        let num1: u64 = gm.get_ref(0x500).unwrap().load();
        let num2: u64 = gm.get_ref(0x1000 + 32).unwrap().load();
        assert_eq!(val1, num1);
        assert_eq!(val2, num2);
    }

    #[test]
    fn test_ref_store_u64() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let gm = GuestMemory::new(&vec![(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();

        let val1: u64 = 0xaa55aa55aa55aa55;
        let val2: u64 = 0x55aa55aa55aa55aa;
        gm.get_ref(0x500).unwrap().store(val1);
        gm.get_ref(0x1000 + 32).unwrap().store(val2);
        let num1: u64 = gm.read_obj_from_addr(GuestAddress(0x500)).unwrap();
        let num2: u64 = gm.read_obj_from_addr(GuestAddress(0x1000 + 32)).unwrap();
        assert_eq!(val1, num1);
        assert_eq!(val2, num2);
    }

    // Get the base address of the mapping for a GuestAddress.
    fn get_mapping(mem: &GuestMemory, addr: GuestAddress) -> Result<*const u8> {
        mem.do_in_region(addr, |mapping, _| Ok(mapping.as_ptr() as *const u8))
    }

    #[test]
    fn guest_to_host() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x100);
        let mem = GuestMemory::new(&vec![(start_addr1, 0x100), (start_addr2, 0x400)]).unwrap();

        // Verify the host addresses match what we expect from the mappings.
        let addr1_base = get_mapping(&mem, start_addr1).unwrap();
        let addr2_base = get_mapping(&mem, start_addr2).unwrap();
        let host_addr1 = mem.get_host_address(start_addr1).unwrap();
        let host_addr2 = mem.get_host_address(start_addr2).unwrap();
        assert_eq!(host_addr1, addr1_base);
        assert_eq!(host_addr2, addr2_base);

        // Check that a bad address returns an error.
        let bad_addr = GuestAddress(0x123456);
        assert!(mem.get_host_address(bad_addr).is_err());
        format!("{:?}", mem.get_host_address(bad_addr));
    }

    #[test]
    fn write_and_read_slice() {
        let start_addr = GuestAddress(0x1000);
        let gm = GuestMemory::new(&vec![(start_addr, 0x400)]).unwrap();
        let sample_buf = &[1, 2, 3, 4, 5];

        assert_eq!(gm.write_slice_at_addr(sample_buf, start_addr).unwrap(), 5);

        let buf = &mut [0u8; 5];
        assert_eq!(gm.read_slice_at_addr(buf, start_addr).unwrap(), 5);
        assert_eq!(buf, sample_buf);
    }

    #[test]
    fn read_to_and_write_from_mem() {
        let gm = GuestMemory::new(&vec![(GuestAddress(0x1000), 0x400)]).unwrap();
        let addr = GuestAddress(0x1010);
        gm.write_obj_at_addr(!0u32, addr).unwrap();
        gm.read_to_memory(
            addr,
            &mut File::open(Path::new("/dev/zero")).unwrap(),
            mem::size_of::<u32>(),
        ).unwrap();
        let value: u32 = gm.read_obj_from_addr(addr).unwrap();
        assert_eq!(value, 0);

        let mut sink = Vec::new();
        gm.write_from_memory(addr, &mut sink, mem::size_of::<u32>())
            .unwrap();
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
        let gm = GuestMemory::new(&regions).unwrap();

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
}
