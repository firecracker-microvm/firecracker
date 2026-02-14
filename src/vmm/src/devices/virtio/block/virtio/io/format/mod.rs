// Copyright (c) 2026 Tencent. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod vmdk;

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

pub use self::vmdk::{VmdkFileEngine, VmdkIoError};

/// VMDK4 sparse file magic: 'KDMV' in little-endian.
const VMDK4_MAGIC: u32 = 0x564d_444b;

/// The detected disk image format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskImageFormat {
    /// Raw disk image (no format header detected).
    Raw,
    /// VMDK disk image.
    Vmdk,
}

/// Detects the format of a disk image by reading its first bytes.
pub fn detect_disk_format(file: &mut File) -> io::Result<DiskImageFormat> {
    let mut header = [0u8; 512];
    file.seek(SeekFrom::Start(0))?;
    let bytes_read = file.read(&mut header)?;
    if bytes_read < 4 {
        return Ok(DiskImageFormat::Raw);
    }

    let magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    if magic == VMDK4_MAGIC {
        return Ok(DiskImageFormat::Vmdk);
    }

    if let Ok(text) = std::str::from_utf8(&header[..bytes_read])
        && (text.contains("# Disk DescriptorFile")
            || (text.contains("version") && text.contains("createType")))
    {
        return Ok(DiskImageFormat::Vmdk);
    }

    Ok(DiskImageFormat::Raw)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    #[test]
    fn test_detect_raw_format() {
        let empty = TempFile::new().unwrap();
        let mut file = File::open(empty.as_path()).unwrap();
        assert_eq!(detect_disk_format(&mut file).unwrap(), DiskImageFormat::Raw);

        let non_empty = TempFile::new().unwrap();
        non_empty.as_file().set_len(4096).unwrap();
        let mut file = File::open(non_empty.as_path()).unwrap();
        assert_eq!(detect_disk_format(&mut file).unwrap(), DiskImageFormat::Raw);
    }

    #[test]
    fn test_detect_vmdk_text_format() {
        let descriptor = TempFile::new().unwrap();
        descriptor
            .as_file()
            .write_all(b"# Disk DescriptorFile\nversion=1\n")
            .unwrap();
        let mut file = File::open(descriptor.as_path()).unwrap();
        assert_eq!(
            detect_disk_format(&mut file).unwrap(),
            DiskImageFormat::Vmdk
        );

        let createtype = TempFile::new().unwrap();
        createtype
            .as_file()
            .write_all(b"version=1\ncreateType=\"monolithicFlat\"\n")
            .unwrap();
        let mut file = File::open(createtype.as_path()).unwrap();
        assert_eq!(
            detect_disk_format(&mut file).unwrap(),
            DiskImageFormat::Vmdk
        );
    }

    #[test]
    fn test_detect_vmdk_sparse_magic() {
        let f = TempFile::new().unwrap();
        let magic_bytes: [u8; 4] = VMDK4_MAGIC.to_le_bytes();
        f.as_file().write_all(&magic_bytes).unwrap();
        f.as_file().set_len(4096).unwrap();

        let mut file = File::open(f.as_path()).unwrap();
        assert_eq!(
            detect_disk_format(&mut file).unwrap(),
            DiskImageFormat::Vmdk
        );
    }
}
