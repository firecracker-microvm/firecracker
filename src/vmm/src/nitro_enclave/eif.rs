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
use std::io::{Read, Seek, SeekFrom};
use std::mem::size_of;
use std::os::unix::fs::FileExt;

use crc32fast::Hasher as Crc32Hasher;
use zerocopy::byteorder::big_endian;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::utils::u64_to_usize;

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
    /// Lay out the sections and return the header with the total image length.
    fn new(
        kernel_len: u64,
        initrd_len: Option<u64>,
        cmdline_len: u64,
        default_mem: u64,
        default_cpus: u64,
        pcie_flags: u16,
    ) -> (Self, usize) {
        let mut header = Self {
            magic: EIF_MAGIC,
            version: big_endian::U16::new(EIF_HDR_VERSION),
            flags: big_endian::U16::new(EIF_ARCH_FLAG | pcie_flags),
            default_mem: big_endian::U64::new(default_mem),
            default_cpus: big_endian::U64::new(default_cpus),
            reserved: big_endian::U16::ZERO,
            num_sections: big_endian::U16::ZERO,
            section_offsets: [big_endian::U64::ZERO; MAX_NUM_SECTIONS],
            section_sizes: [big_endian::U64::ZERO; MAX_NUM_SECTIONS],
            unused: big_endian::U32::ZERO,
            eif_crc32: big_endian::U32::ZERO,
        };

        // Each section follows the previous one: a section header, then its data.
        let mut offset = size_of::<Self>() as u64;
        // The hypervisor expects kernel, cmdline, optional ramdisk, then metadata.
        let section_sizes = [
            Some(kernel_len),
            Some(cmdline_len),
            initrd_len,
            Some(EIF_METADATA.len() as u64),
        ];
        let mut num_sections: u16 = 0;
        for size in section_sizes.into_iter().flatten() {
            let index = usize::from(num_sections);
            header.section_offsets[index] = big_endian::U64::new(offset);
            header.section_sizes[index] = big_endian::U64::new(size);
            offset += size_of::<EifSectionHeader>() as u64 + size;
            num_sections += 1;
        }
        header.num_sections = big_endian::U16::new(num_sections);
        (header, u64_to_usize(offset))
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
    /// Failed to {op} kernel image: {source}
    ReadKernel {
        /// The operation that failed, "seek" or "read".
        op: &'static str,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// Failed to {op} initrd image: {source}
    ReadInitrd {
        /// The operation that failed, "seek" or "read".
        op: &'static str,
        /// Underlying I/O error.
        source: std::io::Error,
    },
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
    // InstanceStart is retryable, so these descriptors may already have been
    // read to EOF by an earlier attempt.
    kernel_file
        .seek(SeekFrom::Start(0))
        .map_err(|source| EifError::ReadKernel { op: "seek", source })?;
    kernel_file
        .read_to_end(&mut kernel_data)
        .map_err(|source| EifError::ReadKernel { op: "read", source })?;
    if kernel_data.is_empty() {
        return Err(EifError::EmptyKernel);
    }
    let initrd_data = match initrd_file {
        Some(mut file) => {
            let mut data = Vec::new();
            file.seek(SeekFrom::Start(0))
                .map_err(|source| EifError::ReadInitrd { op: "seek", source })?;
            file.read_to_end(&mut data)
                .map_err(|source| EifError::ReadInitrd { op: "read", source })?;
            Some(data)
        }
        None => None,
    };
    let (header, total_size) = EifHeader::new(
        kernel_data.len() as u64,
        initrd_data.as_ref().map(|data| data.len() as u64),
        cmdline.len() as u64,
        default_mem,
        default_cpus,
        pcie_flags,
    );

    let mut eif = Vec::with_capacity(total_size);
    eif.extend_from_slice(header.as_bytes());

    // --- Sections (order: KERNEL, CMDLINE, [RAMDISK], METADATA) ---
    write_section(&mut eif, EIF_SECTION_KERNEL, &kernel_data);
    write_section(&mut eif, EIF_SECTION_CMDLINE, cmdline.as_bytes());
    if let Some(ref initrd) = initrd_data {
        write_section(&mut eif, EIF_SECTION_RAMDISK, initrd);
    }
    write_section(&mut eif, EIF_SECTION_METADATA, EIF_METADATA.as_bytes());
    debug_assert_eq!(eif.len(), total_size);

    // Compute EIF CRC32 over the entire image, excluding the 4-byte CRC field itself.
    let mut hasher = Crc32Hasher::new();
    hasher.update(&eif[..EIF_CRC32_OFFSET]);
    hasher.update(&eif[EIF_CRC32_OFFSET + 4..]);
    let crc = hasher.finalize();
    eif[EIF_CRC32_OFFSET..EIF_CRC32_OFFSET + 4].copy_from_slice(&crc.to_be_bytes());

    Ok(eif)
}

/// Minimal metadata JSON required by the NE hypervisor.
// TODO(enclave): understand if we need to fill this information
const EIF_METADATA: &str = r#"{"ImageName":"firecracker-enclave","ImageVersion":"","BuildMetadata":{"BuildTime":"","BuildTool":"firecracker","BuildToolVersion":"","OperatingSystem":"Linux","KernelVersion":""},"DockerInfo":{},"CustomMetadata":null}"#;

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

    /// Split an image into its header and sections, checking that each
    /// section starts where the header's offset table says, that the
    /// sections fill the image, and that the CRC matches.
    fn decode_eif(eif: &[u8]) -> (EifHeader, Vec<(u16, &[u8])>) {
        let (header, _) = EifHeader::read_from_prefix(eif).unwrap();
        let mut sections = Vec::new();
        let mut offset = size_of::<EifHeader>();
        for index in 0..usize::from(header.num_sections.get()) {
            assert_eq!(header.section_offsets[index].get(), offset as u64);
            let (section, rest) = EifSectionHeader::read_from_prefix(&eif[offset..]).unwrap();
            assert_eq!(header.section_sizes[index].get(), section.size.get());
            let size = usize::try_from(section.size.get()).unwrap();
            sections.push((section.section_type.get(), &rest[..size]));
            offset += size_of::<EifSectionHeader>() + size;
        }
        assert_eq!(offset, eif.len());

        let mut hasher = Crc32Hasher::new();
        hasher.update(&eif[..EIF_CRC32_OFFSET]);
        hasher.update(&eif[EIF_CRC32_OFFSET + 4..]);
        assert_eq!(hasher.finalize(), header.eif_crc32.get());
        (header, sections)
    }

    #[test]
    fn test_eif_builder_reuses_descriptors() {
        let dir = TempDir::new().unwrap();
        let kernel_path = dir.as_path().join("kernel");
        let initrd_path = dir.as_path().join("initrd");
        fs::write(&kernel_path, b"FAKE_KERNEL_DATA_1234").unwrap();
        fs::write(&initrd_path, b"FAKE_INITRD_DATA_5678").unwrap();
        let kernel_file = File::open(&kernel_path).unwrap();
        let initrd_file = File::open(&initrd_path).unwrap();

        // A failed InstanceStart is retryable, so build_eif can be called more
        // than once on the same descriptors.
        let first = build_eif(
            &kernel_file,
            Some(&initrd_file),
            "",
            256 * 1024 * 1024,
            2,
            0,
        )
        .unwrap();
        let second = build_eif(
            &kernel_file,
            Some(&initrd_file),
            "",
            256 * 1024 * 1024,
            2,
            0,
        )
        .unwrap();

        assert_eq!(first, second);
    }

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

        let (header, sections) = decode_eif(&eif);
        assert_eq!(header.magic, EIF_MAGIC);
        assert_eq!(header.version.get(), EIF_HDR_VERSION);
        assert_eq!(header.default_mem.get(), mem);
        assert_eq!(header.default_cpus.get(), cpus);
        assert_eq!(header.reserved.get(), 0);
        // Kernel, cmdline, ramdisk, then metadata, as the NE hypervisor expects.
        let types: Vec<u16> = sections
            .iter()
            .map(|&(section_type, _)| section_type)
            .collect();
        assert_eq!(
            types,
            [
                EIF_SECTION_KERNEL,
                EIF_SECTION_CMDLINE,
                EIF_SECTION_RAMDISK,
                EIF_SECTION_METADATA
            ]
        );
        assert_eq!(sections[0].1, b"FAKE_KERNEL_DATA_1234");
        assert_eq!(sections[1].1, b"console=ttyS0");
        assert_eq!(sections[2].1, b"FAKE_INITRD_DATA_5678");
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
    fn test_eif_empty_initrd() {
        let dir = TempDir::new().unwrap();
        let kernel_path = dir.as_path().join("kernel");
        let initrd_path = dir.as_path().join("initrd");
        fs::write(&kernel_path, b"FAKE_KERNEL").unwrap();
        fs::write(&initrd_path, b"").unwrap();
        let kernel_file = File::open(&kernel_path).unwrap();
        let initrd_file = File::open(&initrd_path).unwrap();

        let eif = build_eif(
            &kernel_file,
            Some(&initrd_file),
            "",
            256 * 1024 * 1024,
            2,
            0,
        )
        .unwrap();
        // A present but empty initrd keeps its ramdisk section.
        let (_, sections) = decode_eif(&eif);
        assert_eq!(sections.len(), 4);
        assert_eq!(sections[2], (EIF_SECTION_RAMDISK, &b""[..]));
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
