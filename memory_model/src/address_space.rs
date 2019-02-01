// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Represent the physical address space of a virtual machine, which is composed
//! by address ranges for memory and memory-mapped IO areas.

use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};

use guest_address::GuestAddress;
use guest_memory::{Error, GuestMemory, MemoryRegion};
use mmap::MemoryMapping;

/// Type of address regions.
/// On physical machines, physical memory may have different properties, such as
/// volatile vs non-volatile, read-only vs read-write, non-executable vs
/// executable etc. On virtual machines, the concept of memory property may be
/// extended to support better cooperation between the hypervisor and the guest
/// kernel. Here type means what the memory will be used for by the guest, and
/// different permissions and policies may be applied to different region types.
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum AddressRegionType {
    /// Normal memory accessible by CPUs and IO devices
    DefaultMemory,
    /// Memory reserved for BIOS/VGA
    BiosMemory,
    /// Memory accessible by CPUs only
    HighMemory,
    /// Memory for IO/DMA buffers
    IoBufferMemory,
    /// Device MMIO address
    DeviceMemory,
    /// Memory for guest boot info, requiring system permission
    BootInfo,
    /// Memory for guest kernel code, requiring system permission
    KernelText,
    /// Memory for guest kernel read only data, requiring system permission
    KernelRoData,
    /// Memory for guest kernel data, requiring system permission
    KernelData,
}

/// Represent a guest address region.
pub struct AddressRegion {
    ty: AddressRegionType,
    base: GuestAddress,
    size: usize,
    fd: Option<Arc<AsRawFd>>,
    offset: usize,
}

impl AddressRegion {
    /// Create a memory region backed up by anonymous memory.
    pub fn new(ty: AddressRegionType, base: GuestAddress, size: usize) -> Self {
        AddressRegion {
            ty,
            base,
            size,
            fd: None,
            offset: 0,
        }
    }

    /// Create a memory region mapping content from a file descriptor.
    pub fn from_fd(
        ty: AddressRegionType,
        base: GuestAddress,
        size: usize,
        fd: Arc<AsRawFd>,
        offset: usize,
    ) -> Self {
        AddressRegion {
            ty,
            base,
            size,
            fd: Some(fd),
            offset,
        }
    }

    /// Get type of memory region.
    pub fn get_type(&self) -> AddressRegionType {
        self.ty
    }

    /// Get memory region base.
    pub fn get_base(&self) -> GuestAddress {
        self.base
    }

    /// Get memory region size.
    pub fn get_size(&self) -> usize {
        self.size
    }

    /// Get optional file descriptor backing the memory region.
    pub fn get_fd(&self) -> Option<Arc<AsRawFd>> {
        match self.fd {
            Some(ref fd) => Some(fd.clone()),
            None => None,
        }
    }

    /// Get file offset to mmap().
    pub fn get_offset(&self) -> usize {
        self.offset
    }

    /// Check whether memory region has associated file descriptor
    pub fn has_fd(&self) -> bool {
        self.fd.is_some()
    }

    /// Check whether memory region is valid.
    pub fn is_valid(&self) -> bool {
        !(self.base.checked_add(self.size).is_none() || (self.fd.is_none() && self.offset != 0))
    }

    /// Check whether intersects with another address region.
    pub fn intersect_with(&self, other: &AddressRegion) -> bool {
        // Treat invalid address region as intersecting always
        let end1 = match self.base.checked_add(self.size) {
            Some(addr) => addr,
            None => return true,
        };
        let end2 = match other.base.checked_add(other.size) {
            Some(addr) => addr,
            None => return true,
        };

        if self.base >= other.base && self.base < end2 {
            return true;
        } else if end1 > other.base && end1 <= end2 {
            return true;
        } else if other.base >= self.base && other.base < end1 {
            return true;
        } else if end2 > self.base && end2 <= end1 {
            return true;
        }

        false
    }
}

impl AsRawFd for AddressRegion {
    fn as_raw_fd(&self) -> RawFd {
        match self.fd {
            Some(ref fd) => fd.as_raw_fd(),
            None => panic!("memory region has no associated file descriptor!"),
        }
    }
}

/// Maintain address space information for a virtual machine.
pub struct AddressSpace {
    regions: Mutex<Vec<Arc<AddressRegion>>>,
}

impl AddressSpace {
    /// Create an address space.
    pub fn new(vec: Vec<Arc<AddressRegion>>) -> Self {
        AddressSpace {
            regions: Mutex::new(vec),
        }
    }

    /// Create an empty address space.
    pub fn with_capacity(size: usize) -> Self {
        // with a default capacity enough for most cases
        let cap = match size {
            0 => 10,
            _ => size,
        };

        AddressSpace {
            regions: Mutex::new(Vec::with_capacity(cap)),
        }
    }

    /// Create an address region mapping content from a file descriptor.
    ///
    /// # Arguments
    /// * `ty` - Type of the address region
    /// * `base` - Base address in VM to map content
    /// * `size` - Length of content to map
    /// * `fd` - File descriptor to map content from
    /// * `offset` - The offset into file to start mapping
    pub fn add_region(
        &mut self,
        ty: AddressRegionType,
        base: GuestAddress,
        size: usize,
        fd: Option<Arc<AsRawFd>>,
        offset: usize,
    ) -> Result<usize, Error> {
        let region = match fd {
            Some(fd1) => Arc::new(AddressRegion::from_fd(ty, base, size, fd1, offset)),
            None => Arc::new(AddressRegion::new(ty, base, size)),
        };
        self.insert_region(region)
    }

    /// Create an address region mapping anonymous memory.
    ///
    /// # Arguments
    /// * `base` - Base address in VM to map content
    /// * `size` - Length of content to map
    pub fn add_default_memory(&mut self, base: GuestAddress, size: usize) -> Result<usize, Error> {
        self.add_region(AddressRegionType::DefaultMemory, base, size, None, 0)
    }

    /// Create an address region for device MMIO.
    ///
    /// # Arguments
    /// * `base` - Base address in VM to map content
    /// * `size` - Length of content to map
    pub fn add_device_memory(&mut self, base: GuestAddress, size: usize) -> Result<usize, Error> {
        let region = Arc::new(AddressRegion::new(
            AddressRegionType::DeviceMemory,
            base,
            size,
        ));
        self.insert_region(region)
    }

    /// Get number of memory regions.
    pub fn len(&self) -> usize {
        // Assuming the lock is healthy otherwise we are already in trouble
        self.regions.lock().unwrap().len()
    }

    /// Get specific space region by index
    pub fn get_region(&self, index: usize) -> Option<Arc<AddressRegion>> {
        // Assuming the lock is healthy otherwise we are already in trouble
        let regions = self.regions.lock().unwrap();
        if index < regions.len() {
            Some(regions[index].clone())
        } else {
            None
        }
    }

    /// Get regions of specific type
    pub fn get_regions_by_type(&self, ty: AddressRegionType) -> Vec<Arc<AddressRegion>> {
        let mut vec = Vec::new();
        let regions = self.regions.lock().unwrap();
        for region in regions.iter() {
            if region.get_type() == ty {
                vec.push(region.clone());
            }
        }
        vec
    }

    /// Map memory regions of specific type into current process.
    pub fn map_guest_memory(&self, types: &[AddressRegionType]) -> Result<GuestMemory, Error> {
        // Can't map regions of device MMIO into current process
        if types.contains(&AddressRegionType::DeviceMemory) {
            return Err(Error::InvalidASOperation);
        }
        let mut regions = Vec::<MemoryRegion>::new();
        self.map_regions_by_types(types, &mut regions)?;
        Ok(GuestMemory::from_regions(regions))
    }

    /// Perform the specified action on each address region.
    pub fn with_regions<F, E>(&self, mut cb: F) -> Result<(), E>
    where
        F: FnMut(&AddressRegion) -> Result<(), E>,
    {
        // Assuming the lock is healthy otherwise we are already in trouble
        let regions = self.regions.lock().unwrap();
        for region in regions.iter() {
            cb(region)?;
        }
        Ok(())
    }

    fn map_regions_by_types(
        &self,
        types: &[AddressRegionType],
        regions: &mut Vec<MemoryRegion>,
    ) -> Result<(), Error> {
        // Assuming the lock is healthy otherwise we are already in trouble
        let regs = self.regions.lock().unwrap();
        for region in regs.iter() {
            if types.contains(&region.ty) {
                let mapping = match region.fd {
                    Some(ref fd) => {
                        MemoryMapping::from_fd_offset(&**fd, region.size, region.offset)
                            .map_err(Error::MemoryMappingFailed)?
                    }
                    None => MemoryMapping::new(region.size).map_err(Error::MemoryMappingFailed)?,
                };
                regions.push(MemoryRegion::new(mapping, region.base));
            }
        }
        Ok(())
    }

    fn insert_region(&mut self, region: Arc<AddressRegion>) -> Result<usize, Error> {
        if !region.is_valid() {
            return Err(Error::InvalidGuestAddressRange(
                region.get_base(),
                region.get_size(),
            ));
        }

        // Assuming the lock is healthy otherwise we are already in trouble
        let mut regions = self.regions.lock().unwrap();
        for reg in regions.iter() {
            if region.intersect_with(reg) {
                return Err(Error::InvalidGuestAddressRange(
                    region.get_base(),
                    region.get_size(),
                ));
            }
        }

        regions.push(region);
        Ok(regions.len() - 1)
    }
}

#[cfg(test)]
mod tests {
    extern crate tempfile;

    use self::tempfile::tempfile;
    use super::*;
    use guest_address::GuestAddress;
    use std::io::Write;

    #[test]
    fn test_memory_region_valid() {
        let reg1 = AddressRegion::new(
            AddressRegionType::DefaultMemory,
            GuestAddress(0xFFFFFFFFFFFFF000),
            0x2000,
        );
        assert!(!reg1.is_valid());
        let reg1 = AddressRegion::new(
            AddressRegionType::DefaultMemory,
            GuestAddress(0xFFFFFFFFFFFFF000),
            0x1000,
        );
        assert!(!reg1.is_valid());
        let reg1 = AddressRegion::new(
            AddressRegionType::DefaultMemory,
            GuestAddress(0xFFFFFFFFFFFFE000),
            0x1000,
        );
        assert!(reg1.is_valid());

        let mut f = Arc::new(tempfile().unwrap());
        let sample_buf = &[1, 2, 3, 4, 5];
        assert!(Arc::get_mut(&mut f).unwrap().write_all(sample_buf).is_ok());
        let reg2 = AddressRegion::from_fd(
            AddressRegionType::DefaultMemory,
            GuestAddress(0x1000),
            0x1000,
            f.clone(),
            0x0,
        );
        assert!(reg2.is_valid());
    }

    #[test]
    fn test_memory_region_intersect() {
        let reg1 = AddressRegion::new(
            AddressRegionType::DefaultMemory,
            GuestAddress(0x1000),
            0x1000,
        );
        let reg2 = AddressRegion::new(
            AddressRegionType::DefaultMemory,
            GuestAddress(0x2000),
            0x1000,
        );
        let reg3 = AddressRegion::new(
            AddressRegionType::DefaultMemory,
            GuestAddress(0x1000),
            0x1001,
        );
        let reg4 = AddressRegion::new(
            AddressRegionType::DefaultMemory,
            GuestAddress(0x1100),
            0x100,
        );
        let reg5 = AddressRegion::new(
            AddressRegionType::DefaultMemory,
            GuestAddress(0xFFFFFFFFFFFFF000),
            0x2000,
        );

        assert!(!reg1.intersect_with(&reg2));
        assert!(!reg2.intersect_with(&reg1));

        // intersect with self
        assert!(reg1.intersect_with(&reg1));

        // intersect with others
        assert!(reg3.intersect_with(&reg2));
        assert!(reg2.intersect_with(&reg3));
        assert!(reg1.intersect_with(&reg4));
        assert!(reg4.intersect_with(&reg1));
        assert!(reg1.intersect_with(&reg5));
        assert!(reg5.intersect_with(&reg1));
    }

    #[test]
    fn create_address_space() {
        let mut f = Arc::new(tempfile().unwrap());
        let sample_buf = &[1, 2, 3, 4, 5];
        assert!(Arc::get_mut(&mut f).unwrap().write_all(sample_buf).is_ok());

        let mut space = AddressSpace::with_capacity(0);
        space
            .add_region(
                AddressRegionType::KernelText,
                GuestAddress(0x100000),
                0x1000,
                Some(f.clone()),
                0x0,
            )
            .unwrap();
        let region = space.get_region(0).unwrap();
        assert_eq!(region.get_fd().unwrap().as_raw_fd(), f.as_raw_fd());
        assert_eq!(region.get_offset(), 0);
        assert!(region.has_fd());

        let regions = space.get_regions_by_type(AddressRegionType::DefaultMemory);
        assert_eq!(regions.len(), 0);
        let regions = space.get_regions_by_type(AddressRegionType::KernelText);
        assert_eq!(regions.len(), 1);

        space.add_default_memory(GuestAddress(0), 0x100000).unwrap();
        assert_eq!(space.len(), 2);
        assert!(space.get_region(2).is_none());
        space
            .with_regions(|region| {
                if region.get_size() == 0x100000 {
                    return Err(Error::InvalidASOperation);
                }
                Ok(())
            })
            .unwrap_err();

        let region = space.get_region(1).unwrap();
        assert_eq!(region.get_base().offset(), 0x0);
        assert_eq!(region.get_size(), 0x100000);
        assert_eq!(region.get_offset(), 0);
        assert!(region.get_fd().is_none());
        assert!(!region.has_fd());

        let m = space.map_guest_memory(&[AddressRegionType::DeviceMemory]);
        assert!(m.is_err());

        let m = space
            .map_guest_memory(&[
                AddressRegionType::KernelData,
                AddressRegionType::KernelRoData,
            ])
            .unwrap();
        assert_eq!(m.num_regions(), 0);

        let m = space
            .map_guest_memory(&[AddressRegionType::KernelText])
            .unwrap();
        assert_eq!(m.num_regions(), 1);
        let mut val: u8 = m.read_obj_from_addr(GuestAddress(0x100001)).unwrap();
        assert_eq!(val, 2);

        val = 0xa5;
        m.write_obj_at_addr(val, GuestAddress(0x100001)).unwrap();
        val = m.read_obj_from_addr(GuestAddress(0x100001)).unwrap();
        assert_eq!(val, 0xa5);

        // Update middle of mapped memory region
        val = m.read_obj_from_addr(GuestAddress(0x100000)).unwrap();
        assert_eq!(val, 1);
        val = m.read_obj_from_addr(GuestAddress(0x100002)).unwrap();
        assert_eq!(val, 3);
        val = m.read_obj_from_addr(GuestAddress(0x100005)).unwrap();
        assert_eq!(val, 0);

        // Read ahead of mapped memory region
        assert!(m.read_obj_from_addr::<u8>(GuestAddress(0x101000)).is_err());
    }

    #[test]
    #[should_panic]
    fn region_as_rawfd() {
        let reg1 = AddressRegion::new(
            AddressRegionType::DefaultMemory,
            GuestAddress(0x1000),
            0x1000,
        );
        let _ = reg1.as_raw_fd();
    }
}
