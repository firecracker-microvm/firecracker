// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::os::unix::fs::MetadataExt;

use vm_memory::{GuestAddress, GuestMemory, ReadVolatile, VolatileMemoryError};

use crate::arch::initrd_load_addr;
use crate::utils::u64_to_usize;
use crate::vmm_config::boot_source::BootConfig;
use crate::vstate::memory::GuestMemoryMmap;

/// Errors associated with initrd loading.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum InitrdError {
    /// Failed to compute the initrd address.
    Address,
    /// Cannot load initrd due to an invalid memory configuration.
    Load,
    /// Cannot image metadata: {0}
    Metadata(std::io::Error),
    /// Cannot copy initrd file fd: {0}
    CloneFd(std::io::Error),
    /// Cannot load initrd due to an invalid image: {0}
    Read(VolatileMemoryError),
}

/// Type for passing information about the initrd in the guest memory.
#[derive(Debug)]
pub struct InitrdConfig {
    /// Load address of initrd in guest memory
    pub address: GuestAddress,
    /// Size of initrd in guest memory
    pub size: usize,
}

impl InitrdConfig {
    /// Load initrd into guest memory based on the boot config.
    pub fn from_config(
        boot_cfg: &BootConfig,
        vm_memory: &GuestMemoryMmap,
    ) -> Result<Option<Self>, InitrdError> {
        Ok(match &boot_cfg.initrd_file {
            Some(f) => {
                let f = f.try_clone().map_err(InitrdError::CloneFd)?;
                Some(Self::from_file(vm_memory, f)?)
            }
            None => None,
        })
    }

    /// Loads the initrd from a file into guest memory.
    pub fn from_file(vm_memory: &GuestMemoryMmap, mut file: File) -> Result<Self, InitrdError> {
        let size = file.metadata().map_err(InitrdError::Metadata)?.size();
        let size = u64_to_usize(size);
        let Some(address) = initrd_load_addr(vm_memory, size) else {
            return Err(InitrdError::Address);
        };
        let mut slice = vm_memory
            .get_slice(GuestAddress(address), size)
            .map_err(|_| InitrdError::Load)?;
        file.read_exact_volatile(&mut slice)
            .map_err(InitrdError::Read)?;

        Ok(InitrdConfig {
            address: GuestAddress(address),
            size,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom, Write};

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::arch::GUEST_PAGE_SIZE;
    use crate::test_utils::{single_region_mem, single_region_mem_at};

    fn make_test_bin() -> Vec<u8> {
        let mut fake_bin = Vec::new();
        fake_bin.resize(1_000_000, 0xAA);
        fake_bin
    }

    #[test]
    // Test that loading the initrd is successful on different archs.
    fn test_load_initrd() {
        let image = make_test_bin();

        let mem_size: usize = image.len() * 2 + GUEST_PAGE_SIZE;

        let tempfile = TempFile::new().unwrap();
        let mut tempfile = tempfile.into_file();
        tempfile.write_all(&image).unwrap();

        #[cfg(target_arch = "x86_64")]
        let gm = single_region_mem(mem_size);

        #[cfg(target_arch = "aarch64")]
        let gm = single_region_mem(mem_size + crate::arch::aarch64::layout::FDT_MAX_SIZE);

        // Need to reset the cursor to read initrd properly.
        tempfile.seek(SeekFrom::Start(0)).unwrap();
        let initrd = InitrdConfig::from_file(&gm, tempfile).unwrap();
        assert!(gm.address_in_range(initrd.address));
        assert_eq!(initrd.size, image.len());
    }

    #[test]
    fn test_load_initrd_no_memory() {
        let gm = single_region_mem(79);
        let image = make_test_bin();
        let tempfile = TempFile::new().unwrap();
        let mut tempfile = tempfile.into_file();
        tempfile.write_all(&image).unwrap();

        // Need to reset the cursor to read initrd properly.
        tempfile.seek(SeekFrom::Start(0)).unwrap();
        let res = InitrdConfig::from_file(&gm, tempfile);
        assert!(matches!(res, Err(InitrdError::Address)), "{:?}", res);
    }

    #[test]
    fn test_load_initrd_unaligned() {
        let image = vec![1, 2, 3, 4];
        let tempfile = TempFile::new().unwrap();
        let mut tempfile = tempfile.into_file();
        tempfile.write_all(&image).unwrap();
        let gm = single_region_mem_at(GUEST_PAGE_SIZE as u64 + 1, image.len() * 2);

        // Need to reset the cursor to read initrd properly.
        tempfile.seek(SeekFrom::Start(0)).unwrap();
        let res = InitrdConfig::from_file(&gm, tempfile);
        assert!(matches!(res, Err(InitrdError::Address)), "{:?}", res);
    }
}
