// Copyright 2026 Tencent, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io;

use imago::SyncFormatAccess;
use imago::file::File as ImagoFile;
use imago::format::gate::PermissiveImplicitOpenGate;
use imago::vmdk::Vmdk;
use imago::FormatDriverBuilder;
use vm_memory::GuestMemoryError;

use crate::vstate::memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

/// Errors specific to the VMDK IO engine.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VmdkIoError {
    /// Failed to open VMDK image: {0}
    Open(io::Error),
    /// VMDK read error: {0}
    Read(io::Error),
    /// VMDK write not supported (read-only image)
    WriteNotSupported,
    /// Guest memory error: {0}
    GuestMemory(GuestMemoryError),
    /// VMDK flush error: {0}
    Flush(io::Error),
}

pub struct VmdkFileEngine {
    access: SyncFormatAccess<ImagoFile>,
    disk_size: u64,
}

impl std::fmt::Debug for VmdkFileEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmdkFileEngine")
            .field("disk_size", &self.disk_size)
            .finish_non_exhaustive()
    }
}

// SAFETY: SyncFormatAccess wraps a tokio Runtime + FormatAccess which are Send.
// The underlying ImagoFile uses RwLock internally.
unsafe impl Send for VmdkFileEngine {}

impl VmdkFileEngine {
    pub fn from_file(file: File) -> Result<Self, VmdkIoError> {
        let imago_file: ImagoFile = file.try_into().map_err(VmdkIoError::Open)?;

        let vmdk = Vmdk::<ImagoFile>::builder(imago_file)
            .write(false)
            .open_sync(PermissiveImplicitOpenGate())
            .map_err(VmdkIoError::Open)?;

        let access = SyncFormatAccess::new(vmdk).map_err(VmdkIoError::Open)?;

        let disk_size = access.size();

        Ok(Self { access, disk_size })
    }

    pub fn disk_size(&self) -> u64 {
        self.disk_size
    }

    pub fn read(
        &self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    ) -> Result<u32, VmdkIoError> {
        let count_usize = count as usize;
        let mut buf = vec![0u8; count_usize];

        self.access
            .read(&mut buf[..], offset)
            .map_err(VmdkIoError::Read)?;

        mem.write_slice(&buf, addr)
            .map_err(VmdkIoError::GuestMemory)?;

        Ok(count)
    }

    pub fn write(
        &self,
        _offset: u64,
        _mem: &GuestMemoryMmap,
        _addr: GuestAddress,
        _count: u32,
    ) -> Result<u32, VmdkIoError> {
        Err(VmdkIoError::WriteNotSupported)
    }

    pub fn flush(&self) -> Result<(), VmdkIoError> {
        self.access.flush().map_err(VmdkIoError::Flush)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use vmm_sys_util::tempfile::TempFile;

    use super::super::{DiskImageFormat, VMDK4_MAGIC, detect_disk_format};
    use super::*;

    fn create_test_vmdk() -> (TempFile, TempFile) {
        let extent_file = TempFile::new().unwrap();
        let extent_size: u64 = 1024 * 1024;
        extent_file.as_file().set_len(extent_size).unwrap();

        let test_data = b"Hello VMDK from Firecracker!";
        extent_file.as_file().write_all(test_data).unwrap();

        let extent_path = extent_file.as_path().to_str().unwrap().to_string();
        let extent_sectors = extent_size / 512;

        let descriptor_file = TempFile::new().unwrap();
        let descriptor_content = format!(
            r#"# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType="monolithicFlat"

# Extent description
RW {extent_sectors} FLAT "{extent_path}" 0

# The Disk Data Base
#DDB
"#
        );
        descriptor_file
            .as_file()
            .write_all(descriptor_content.as_bytes())
            .unwrap();

        (descriptor_file, extent_file)
    }

    #[test]
    fn test_detect_raw_format() {
        let empty = TempFile::new().unwrap();
        let file = std::fs::File::open(empty.as_path()).unwrap();
        assert_eq!(detect_disk_format(&file).unwrap(), DiskImageFormat::Raw);

        let non_empty = TempFile::new().unwrap();
        non_empty.as_file().set_len(4096).unwrap();
        let file = std::fs::File::open(non_empty.as_path()).unwrap();
        assert_eq!(detect_disk_format(&file).unwrap(), DiskImageFormat::Raw);
    }

    #[test]
    fn test_detect_vmdk_text_format() {
        let descriptor = TempFile::new().unwrap();
        descriptor
            .as_file()
            .write_all(b"# Disk DescriptorFile\nversion=1\n")
            .unwrap();
        let file = std::fs::File::open(descriptor.as_path()).unwrap();
        assert_eq!(detect_disk_format(&file).unwrap(), DiskImageFormat::Vmdk);

        let createtype = TempFile::new().unwrap();
        createtype
            .as_file()
            .write_all(b"version=1\ncreateType=\"monolithicFlat\"\n")
            .unwrap();
        let file = std::fs::File::open(createtype.as_path()).unwrap();
        assert_eq!(detect_disk_format(&file).unwrap(), DiskImageFormat::Vmdk);
    }

    #[test]
    fn test_detect_vmdk_sparse_magic() {
        let f = TempFile::new().unwrap();
        let magic_bytes: [u8; 4] = VMDK4_MAGIC.to_le_bytes();
        f.as_file().write_all(&magic_bytes).unwrap();
        f.as_file().set_len(4096).unwrap();

        let file = std::fs::File::open(f.as_path()).unwrap();
        assert_eq!(detect_disk_format(&file).unwrap(), DiskImageFormat::Vmdk);
    }

    #[test]
    fn test_vmdk_engine_open_and_read() {
        let (descriptor, _extent) = create_test_vmdk();

        let file = std::fs::File::open(descriptor.as_path()).unwrap();
        let engine = VmdkFileEngine::from_file(file).unwrap();

        assert_eq!(engine.disk_size(), 1024 * 1024);

        let mut buf = vec![0u8; 512];
        engine.access.read(&mut buf[..], 0).unwrap();
        assert_eq!(&buf[..28], b"Hello VMDK from Firecracker!");
    }

    #[test]
    fn test_vmdk_engine_write_returns_error() {
        let (descriptor, _extent) = create_test_vmdk();

        let file = std::fs::File::open(descriptor.as_path()).unwrap();
        let engine = VmdkFileEngine::from_file(file).unwrap();

        use crate::vmm_config::machine_config::HugePageConfig;
        use crate::vstate::memory::{self, GuestRegionMmapExt};

        let mem = crate::vstate::memory::GuestMemoryMmap::from_regions(
            memory::anonymous(
                [(GuestAddress(0), 4096)].into_iter(),
                true,
                HugePageConfig::None,
            )
            .unwrap()
            .into_iter()
            .map(|region| GuestRegionMmapExt::dram_from_mmap_region(region, 0))
            .collect(),
        )
        .unwrap();

        let result = engine.write(0, &mem, GuestAddress(0), 512);
        assert!(matches!(result, Err(VmdkIoError::WriteNotSupported)));
    }
}
