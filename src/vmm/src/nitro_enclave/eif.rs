// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! EIF (Enclave Image Format) builder.
//!
//! Builds an EIF image in memory from kernel, initrd, and command line,
//! matching the format expected by the Nitro Enclaves kernel module.
//!
//! The EIF format uses big-endian byte order throughout, matching the
//! `aws-nitro-enclaves-image-format` crate.
//!
//! TODO: Generalize <https://github.com/aws/aws-nitro-enclaves-image-format>
//! to accept `impl Write` (currently hardcoded to `&mut File`) and switch to
//! the upstream crate.  Until then we roll our own in-memory builder.

use std::fs::File;
use std::io::Read;
use std::mem::size_of;
use std::os::unix::fs::FileExt;

use crc32fast::Hasher as Crc32Hasher;
use zerocopy::byteorder::big_endian;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// EIF magic number.
const EIF_MAGIC: [u8; 4] = *b".eif";

/// EIF header version.
const EIF_HDR_VERSION: u16 = 4;

/// Section types (matching aws-nitro-enclaves-image-format).
const EIF_SECTION_KERNEL: u16 = 1;
const EIF_SECTION_CMDLINE: u16 = 2;
const EIF_SECTION_RAMDISK: u16 = 3;
const EIF_SECTION_METADATA: u16 = 5;

/// EIF header flag: PCIE device model (bit 6).
pub const EIF_HDR_FLAG_PCIE: u16 = 1 << 6;
/// EIF header flag: rigid vsock shape (bit 7).
pub const EIF_HDR_FLAG_PCIE_VSOCK: u16 = 1 << 7;
/// EIF header flag: hotplug support (bit 8).
pub const EIF_HDR_FLAG_PCIE_HOTPLUG: u16 = 1 << 8;
/// EIF header flag: permissive virtio (bit 9).
pub const EIF_HDR_FLAG_PCIE_VIRTIO: u16 = 1 << 9;

/// Architecture flag for the current platform (matching aws-nitro-enclaves-image-format).
#[cfg(target_arch = "aarch64")]
const EIF_ARCH_FLAG: u16 = 1;
#[cfg(target_arch = "x86_64")]
const EIF_ARCH_FLAG: u16 = 0;

/// Maximum number of sections in the fixed-size header arrays.
const MAX_NUM_SECTIONS: usize = 32;

/// EIF file header (big-endian on disk).
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
struct EifHeader {
    magic: [u8; 4],
    version: big_endian::U16,
    flags: big_endian::U16,
    default_mem: big_endian::U64,
    default_cpus: big_endian::U64,
    reserved: big_endian::U16,
    num_sections: big_endian::U16,
    section_offsets: [big_endian::U64; MAX_NUM_SECTIONS],
    section_sizes: [big_endian::U64; MAX_NUM_SECTIONS],
    unused: big_endian::U32,
    eif_crc32: big_endian::U32,
}

impl EifHeader {
    fn new(
        flags: u16,
        default_mem: u64,
        default_cpus: u64,
        num_sections: u16,
        offsets: [u64; MAX_NUM_SECTIONS],
        sizes: [u64; MAX_NUM_SECTIONS],
    ) -> Self {
        Self {
            magic: EIF_MAGIC,
            version: big_endian::U16::new(EIF_HDR_VERSION),
            flags: big_endian::U16::new(flags),
            default_mem: big_endian::U64::new(default_mem),
            default_cpus: big_endian::U64::new(default_cpus),
            reserved: big_endian::U16::ZERO,
            num_sections: big_endian::U16::new(num_sections),
            section_offsets: offsets.map(big_endian::U64::new),
            section_sizes: sizes.map(big_endian::U64::new),
            unused: big_endian::U32::ZERO,
            eif_crc32: big_endian::U32::ZERO,
        }
    }
}

/// EIF section header (big-endian on disk).
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
struct EifSectionHeader {
    section_type: big_endian::U16,
    flags: big_endian::U16,
    size: big_endian::U64,
}

impl EifSectionHeader {
    fn new(section_type: u16, size: u64) -> Self {
        Self {
            section_type: big_endian::U16::new(section_type),
            flags: big_endian::U16::ZERO,
            size: big_endian::U64::new(size),
        }
    }
}

const EIF_CRC32_OFFSET: usize = std::mem::offset_of!(EifHeader, eif_crc32);

/// Check whether a file is an EIF by reading the first 4 bytes (magic number).
pub fn is_eif(file: &File) -> bool {
    let mut magic = [0u8; 4];
    file.read_exact_at(&mut magic, 0).is_ok() && magic == EIF_MAGIC
}

/// Errors from EIF building.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum EifError {
    /// Failed to read kernel image: {0}
    ReadKernel(std::io::Error),
    /// Failed to read initrd image: {0}
    ReadInitrd(std::io::Error),
    /// Kernel image is empty
    EmptyKernel,
}

/// Build an EIF image from kernel, optional initrd, and command line.
///
/// `default_mem` is the enclave memory in bytes, `default_cpus` is the vCPU count.
/// These are written into the EIF header for the NE hypervisor.
///
/// If `initrd_file` is `None`, the ramdisk section is omitted. The kernel boots
/// directly into the root filesystem specified by `root=` in the command line.
///
/// Returns the assembled EIF blob ready to be loaded into enclave memory.
/// All multi-byte fields are big-endian.
pub fn build_eif(
    mut kernel_file: &File,
    initrd_file: Option<&File>,
    cmdline: &str,
    default_mem: u64,
    default_cpus: u64,
    pcie_flags: u16,
) -> Result<Vec<u8>, EifError> {
    let mut kernel_data = Vec::new();
    kernel_file
        .read_to_end(&mut kernel_data)
        .map_err(EifError::ReadKernel)?;
    if kernel_data.is_empty() {
        return Err(EifError::EmptyKernel);
    }
    let initrd_data = match initrd_file {
        Some(mut file) => {
            let mut data = Vec::new();
            file.read_to_end(&mut data).map_err(EifError::ReadInitrd)?;
            Some(data)
        }
        None => None,
    };
    let cmdline_data = cmdline.as_bytes();

    // Build minimal metadata JSON required by the NE hypervisor.
    let metadata = build_metadata();
    let metadata_data = metadata.as_bytes();

    // Section count: kernel + cmdline + metadata, plus ramdisk if initrd is provided.
    let has_ramdisk = initrd_data.is_some();
    let initrd_len = initrd_data.as_ref().map_or(0, Vec::len);
    let num_sections: u16 = if has_ramdisk { 4 } else { 3 };

    // Calculate total image size
    let sections_size = (size_of::<EifSectionHeader>() * num_sections as usize)
        + kernel_data.len()
        + cmdline_data.len()
        + metadata_data.len()
        + initrd_len;
    let total_size = size_of::<EifHeader>() + sections_size;

    // Compute section offsets (order: KERNEL, CMDLINE, [RAMDISK], METADATA).
    // Section order matches the NE hypervisor's expectations.
    let mut offsets = [0u64; MAX_NUM_SECTIONS];
    let mut sizes = [0u64; MAX_NUM_SECTIONS];

    let kernel_offset = size_of::<EifHeader>() as u64;
    offsets[0] = kernel_offset;
    sizes[0] = kernel_data.len() as u64;

    let cmdline_offset =
        kernel_offset + size_of::<EifSectionHeader>() as u64 + kernel_data.len() as u64;
    offsets[1] = cmdline_offset;
    sizes[1] = cmdline_data.len() as u64;

    let mut next_offset =
        cmdline_offset + size_of::<EifSectionHeader>() as u64 + cmdline_data.len() as u64;
    let mut idx = 2;

    if has_ramdisk {
        offsets[idx] = next_offset;
        sizes[idx] = initrd_len as u64;
        next_offset += size_of::<EifSectionHeader>() as u64 + initrd_len as u64;
        idx += 1;
    }

    offsets[idx] = next_offset;
    sizes[idx] = metadata_data.len() as u64;

    let header = EifHeader::new(
        EIF_ARCH_FLAG | pcie_flags,
        default_mem,
        default_cpus,
        num_sections,
        offsets,
        sizes,
    );

    let mut eif = Vec::with_capacity(total_size);
    eif.extend_from_slice(header.as_bytes());
    debug_assert_eq!(eif.len(), size_of::<EifHeader>());

    // --- Sections (order: KERNEL, CMDLINE, [RAMDISK], METADATA) ---
    write_section(&mut eif, EIF_SECTION_KERNEL, &kernel_data);
    write_section(&mut eif, EIF_SECTION_CMDLINE, cmdline_data);
    if let Some(ref initrd) = initrd_data {
        write_section(&mut eif, EIF_SECTION_RAMDISK, initrd);
    }
    write_section(&mut eif, EIF_SECTION_METADATA, metadata_data);

    // Compute EIF CRC32 over the entire image, excluding the 4-byte CRC field itself.
    let mut hasher = Crc32Hasher::new();
    hasher.update(&eif[..EIF_CRC32_OFFSET]);
    hasher.update(&eif[EIF_CRC32_OFFSET + 4..]);
    let crc = hasher.finalize();
    eif[EIF_CRC32_OFFSET..EIF_CRC32_OFFSET + 4].copy_from_slice(&crc.to_be_bytes());

    Ok(eif)
}

/// Build a minimal metadata JSON string required by the NE hypervisor.
// TODO(enclave): understand if we need to fill this information
fn build_metadata() -> String {
    r#"{"ImageName":"firecracker-enclave","ImageVersion":"","BuildMetadata":{"BuildTime":"","BuildTool":"firecracker","BuildToolVersion":"","OperatingSystem":"Linux","KernelVersion":""},"DockerInfo":{},"CustomMetadata":null}"#.to_string()
}

/// Write a section (header + data) to the EIF buffer.
fn write_section(eif: &mut Vec<u8>, section_type: u16, data: &[u8]) {
    let hdr = EifSectionHeader::new(section_type, data.len() as u64);
    eif.extend_from_slice(hdr.as_bytes());
    eif.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use std::fs;

    use vmm_sys_util::tempdir::TempDir;

    use super::*;

    #[test]
    fn test_eif_builder() {
        let dir = TempDir::new().unwrap();
        let kernel_path = dir.as_path().join("kernel");
        let initrd_path = dir.as_path().join("initrd");

        fs::write(&kernel_path, b"FAKE_KERNEL_DATA_1234").unwrap();
        fs::write(&initrd_path, b"FAKE_INITRD_DATA_5678").unwrap();

        let kernel_file = File::open(&kernel_path).unwrap();
        let initrd_file = File::open(&initrd_path).unwrap();

        let mem = 256 * 1024 * 1024; // 256 MiB
        let cpus = 2;
        let pci_flags = 0;
        let eif = build_eif(
            &kernel_file,
            Some(&initrd_file),
            "console=ttyS0",
            mem,
            cpus,
            pci_flags,
        )
        .unwrap();

        // Verify magic
        assert_eq!(&eif[0..4], &EIF_MAGIC);
        // Verify version (big-endian)
        assert_eq!(u16::from_be_bytes([eif[4], eif[5]]), EIF_HDR_VERSION);
        // Verify default_mem (big-endian u64 at offset 8)
        assert_eq!(u64::from_be_bytes(eif[8..16].try_into().unwrap()), mem);
        // Verify default_cpus (big-endian u64 at offset 16)
        assert_eq!(u64::from_be_bytes(eif[16..24].try_into().unwrap()), cpus);
        // Verify reserved(u16) + num_sections(u16) at offset 24
        assert_eq!(u16::from_be_bytes([eif[24], eif[25]]), 0); // reserved
        assert_eq!(u16::from_be_bytes([eif[26], eif[27]]), 4); // num_sections
        // Verify total size is reasonable
        assert!(eif.len() > size_of::<EifHeader>());
        // Verify first section type is KERNEL (big-endian u16 at offset 548)
        assert_eq!(
            u16::from_be_bytes([eif[size_of::<EifHeader>()], eif[size_of::<EifHeader>() + 1]]),
            EIF_SECTION_KERNEL
        );
        // Verify CRC32 is valid (recompute excluding CRC field)
        let stored_crc = u32::from_be_bytes(
            eif[EIF_CRC32_OFFSET..EIF_CRC32_OFFSET + 4]
                .try_into()
                .unwrap(),
        );
        let mut hasher = Crc32Hasher::new();
        hasher.update(&eif[..EIF_CRC32_OFFSET]);
        hasher.update(&eif[EIF_CRC32_OFFSET + 4..]);
        assert_eq!(hasher.finalize(), stored_crc);
    }

    #[test]
    fn test_is_eif() {
        let dir = TempDir::new().unwrap();

        // A file starting with EIF magic should be detected
        let eif_path = dir.as_path().join("test.eif");
        let mut data = EIF_MAGIC.to_vec();
        data.extend_from_slice(&[0u8; 100]);
        fs::write(&eif_path, &data).unwrap();
        assert!(is_eif(&File::open(&eif_path).unwrap()));

        // A raw kernel (not EIF) should not be detected
        let kernel_path = dir.as_path().join("vmlinux");
        fs::write(&kernel_path, b"\x7fELF_fake_kernel").unwrap();
        assert!(!is_eif(&File::open(&kernel_path).unwrap()));

        // Empty file should return false
        let empty_path = dir.as_path().join("empty");
        fs::write(&empty_path, b"").unwrap();
        assert!(!is_eif(&File::open(&empty_path).unwrap()));
    }

    #[test]
    fn test_eif_empty_kernel_error() {
        let dir = TempDir::new().unwrap();
        let kernel_path = dir.as_path().join("kernel");
        let initrd_path = dir.as_path().join("initrd");

        fs::write(&kernel_path, b"").unwrap();
        fs::write(&initrd_path, b"initrd").unwrap();

        let kernel_file = File::open(&kernel_path).unwrap();
        let initrd_file = File::open(&initrd_path).unwrap();

        let result = build_eif(
            &kernel_file,
            Some(&initrd_file),
            "",
            256 * 1024 * 1024,
            2,
            0,
        );
        assert!(matches!(result, Err(EifError::EmptyKernel)));
    }

    #[test]
    fn test_eif_no_initrd() {
        let dir = TempDir::new().unwrap();
        let kernel_path = dir.as_path().join("kernel");
        fs::write(&kernel_path, b"FAKE_KERNEL").unwrap();
        let kernel_file = File::open(&kernel_path).unwrap();

        let eif = build_eif(&kernel_file, None, "console=ttyS0", 256 * 1024 * 1024, 2, 0).unwrap();
        assert_eq!(&eif[0..4], &EIF_MAGIC);
        // Without initrd: kernel + cmdline + metadata = 3 sections.
        assert_eq!(u16::from_be_bytes([eif[26], eif[27]]), 3);
    }

    #[test]
    fn test_eif_pcie_flags() {
        let dir = TempDir::new().unwrap();
        let kernel_path = dir.as_path().join("kernel");
        fs::write(&kernel_path, b"FAKE_KERNEL").unwrap();
        let kernel_file = File::open(&kernel_path).unwrap();

        let pcie_flags = EIF_HDR_FLAG_PCIE | EIF_HDR_FLAG_PCIE_VIRTIO;
        let eif = build_eif(&kernel_file, None, "", 256 * 1024 * 1024, 2, pcie_flags).unwrap();

        // Flags field is at offset 6..8 (big-endian u16, after magic(4) + version(2)).
        let header_flags = u16::from_be_bytes([eif[6], eif[7]]);
        assert_eq!(header_flags & EIF_HDR_FLAG_PCIE, EIF_HDR_FLAG_PCIE);
        assert_eq!(
            header_flags & EIF_HDR_FLAG_PCIE_VIRTIO,
            EIF_HDR_FLAG_PCIE_VIRTIO
        );
        assert_eq!(header_flags & EIF_HDR_FLAG_PCIE_HOTPLUG, 0);
        // Arch bits should still be present.
        assert_eq!(header_flags & EIF_ARCH_FLAG, EIF_ARCH_FLAG);
    }
}
